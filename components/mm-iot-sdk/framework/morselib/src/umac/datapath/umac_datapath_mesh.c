/*
 * Copyright 2026 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

/*
 * 802.11s mesh datapath ops table. Association-less and self-beaconing like IBSS, so the plumbing
 * mirrors the IBSS ops: the "common" stad (the MBSS) backs broadcast/mgmt TX, each ESTAB peer has
 * its own stad (per-pair MTK + RX state). The mesh-specific bits are the common-stad lookups, the
 * multi-queue TX dequeue, the 4-address data-header builder, and the mgmt-frame RX handler which
 * routes ACTION frames to the Mesh Peering / Block-Ack code and AUTH frames to SAE. Bound onto the
 * VIF_STA host-slot at umac_interface_add(UMAC_INTERFACE_MESH, ...).
 */

#include "mmpkt.h"
#include "mmwlan.h"
#include "mmwlan_internal.h"
#include "umac/datapath/umac_datapath_private.h"
#include "umac/data/umac_data.h"
#include "umac/supplicant_shim/umac_supp_shim.h"
#include "dot11/dot11.h"
#include "dot11/dot11_utils.h"
#include "dot11/dot11_frames.h"
#include "umac/interface/umac_interface.h"
#include "umac/ba/umac_ba.h"
#include "umac/stats/umac_stats.h"
#include "umac/mesh/umac_mesh.h"
#include "common/mac_address.h"

/* Unicast RX/TX to an established peer -> that peer's stad (its per-pair MTK + replay/reorder
 * state); broadcast/multicast/zero -> the common (MBSS) stad (group MGTK). An unknown / not-yet-
 * ESTAB unicast falls back to the common stad. */
static struct umac_sta_data *umac_datapath_lookup_stad_by_peer_addr_mesh(struct umac_data *umacd,
                                                                         const uint8_t *addr)
{
    MM_UNUSED(umacd);
    if (addr == NULL || mm_mac_addr_is_zero(addr) || mm_mac_addr_is_multicast(addr))
    {
        return umac_mesh_get_common_stad();
    }
    struct umac_sta_data *peer = umac_mesh_get_peer_stad(addr);
    return (peer != NULL) ? peer : umac_mesh_get_common_stad();
}

static struct umac_sta_data *umac_datapath_lookup_stad_by_tx_dest_addr_mesh(struct umac_data *umacd,
                                                                            const uint8_t *addr)
{
    MM_UNUSED(umacd);
    if (addr == NULL || mm_mac_addr_is_zero(addr) || mm_mac_addr_is_multicast(addr))
    {
        return umac_mesh_get_common_stad();
    }
    struct umac_sta_data *peer = umac_mesh_get_peer_stad(addr);
    return (peer != NULL) ? peer : umac_mesh_get_common_stad();
}

/* Mesh per-AID stad lookup (tx-status). AID 0 = the common (group/mgmt) stad; peer AID N maps to
 * mesh slot N-1 (mirrors umac_ap_lookup_sta_by_aid). Closes the P6c real-RC TX-status gap. */
static struct umac_sta_data *umac_datapath_lookup_stad_by_aid_mesh(struct umac_data *umacd,
                                                                   uint16_t aid)
{
    MM_UNUSED(umacd);
    if (aid == 0)
    {
        return umac_mesh_get_common_stad();
    }
    return umac_mesh_peer_stad_at((size_t)(aid - 1));
}

static enum mmwlan_sta_state umac_datapath_get_state_mesh(struct umac_sta_data *stad)
{
    MM_UNUSED(stad);
    return MMWLAN_STA_CONNECTED;
}

/* Pick the next mesh stad with queued TX work: the common (MBSS) stad first, then each ESTAB
 * peer's stad. Pure (no side effects) so the dequeue can call it twice. */
static struct umac_sta_data *mesh_get_next_tx_stad(void)
{
    struct umac_sta_data *stad = umac_mesh_get_common_stad();
    if (stad != NULL && !umac_sta_data_is_paused(stad) && umac_sta_data_get_queued_len(stad))
    {
        return stad;
    }
    for (size_t ii = 0; ii < UMAC_MESH_MAX_PEERS; ii++)
    {
        stad = umac_mesh_peer_stad_at(ii);
        if (stad != NULL && !umac_sta_data_is_paused(stad) && umac_sta_data_get_queued_len(stad))
        {
            return stad;
        }
    }
    return NULL;
}

static void umac_datapath_tx_queue_frame_mesh(struct umac_data *umacd,
                                              struct umac_sta_data *stad,
                                              struct mmpkt *txbuf)
{
    MMOSAL_TASK_ENTER_CRITICAL();
    umac_sta_data_queue_pkt(stad, txbuf);
    umac_stats_update_datapath_txq_high_water_mark(umacd, umac_sta_data_get_queued_len(stad));
    MMOSAL_TASK_EXIT_CRITICAL();
}

static bool umac_datapath_tx_dequeue_frame_mesh(struct umac_data *umacd,
                                                struct umac_sta_data **stad_ptr,
                                                struct mmpkt **txbuf_ptr)
{
    MM_UNUSED(umacd);
    MMOSAL_ASSERT(stad_ptr && txbuf_ptr);
    *stad_ptr = NULL;
    *txbuf_ptr = NULL;

    /* Scan + pop + recompute has_more under one critical section so a concurrent enqueue can't
     * make the multi-queue view inconsistent (the common stad plus each peer's queue). */
    MMOSAL_TASK_ENTER_CRITICAL();
    struct umac_sta_data *stad = mesh_get_next_tx_stad();
    if (stad != NULL)
    {
        *txbuf_ptr = umac_sta_data_pop_pkt(stad);
        if (*txbuf_ptr != NULL)
        {
            *stad_ptr = stad;
        }
    }
    bool has_more = (mesh_get_next_tx_stad() != NULL);
    MMOSAL_TASK_EXIT_CRITICAL();
    return has_more;
}

/* Build the 802.11 header for a mesh data frame, mirroring net/mac80211 (ieee80211_build_hdr,
 * MESH_POINT). QoS Data + Mesh Control (inserted in the TX path) with the QoS "Mesh Control
 * Present" bit set.
 *  - Group-addressed (bcast/mcast): 3-address, fromDS=1. A1=DA, A2=TA(us), A3=mesh-SA(us).
 *  - Unicast to a peer: 4-address, toDS=fromDS=1. A1=next-hop, A2=us, A3=mesh-DA, A4=mesh-SA(us). */
void umac_datapath_construct_80211_data_header_mesh(struct umac_sta_data *stad,
                                                    const struct umac_8023_hdr *hdr_8023,
                                                    struct dot11_data_hdr *data_hdr)
{
    uint16_t frame_control = DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE |
                             DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE;
    uint8_t our_mac[DOT11_MAC_ADDR_LEN];
    umac_interface_get_mac_addr(stad, our_mac);

    if (mm_mac_addr_is_multicast(hdr_8023->dest_addr))
    {
        frame_control |= DOT11_MASK_FC_FROM_DS;
        mac_addr_copy(data_hdr->base.addr1, hdr_8023->dest_addr);
        mac_addr_copy(data_hdr->base.addr2, our_mac);
        mac_addr_copy(data_hdr->base.addr3, our_mac);
    }
    else
    {
        frame_control |= DOT11_MASK_FC_TO_DS | DOT11_MASK_FC_FROM_DS;
        /* RA = the HWMP next hop toward the destination. If no path is resolved yet, fall back to
         * direct (correct for a directly-peered dest) and kick off path discovery. */
        uint8_t next_hop[DOT11_MAC_ADDR_LEN];
        if (!umac_mesh_lookup_next_hop(hdr_8023->dest_addr, next_hop))
        {
            mac_addr_copy(next_hop, hdr_8023->dest_addr);
            umac_mesh_start_discovery(hdr_8023->dest_addr);
        }
        mac_addr_copy(data_hdr->base.addr1, next_hop);            /* RA = next hop */
        mac_addr_copy(data_hdr->base.addr2, our_mac);             /* TA = us */
        mac_addr_copy(data_hdr->base.addr3, hdr_8023->dest_addr); /* mesh DA (final dest) */
        /* mesh SA = the 802.3 source. For originated frames this is our (synced) MAC; for a
         * FORWARDED frame (re-injected with the original src) it preserves the true origin. */
        mac_addr_copy(data_hdr->addr4, hdr_8023->src_addr);
    }
    data_hdr->base.frame_control = htole16(frame_control);
}

static void umac_datapath_process_rx_mgmt_frame_mesh(struct umac_data *umacd,
                                                     struct umac_sta_data *stad,
                                                     struct mmpktview *rxbufview)
{
    MM_UNUSED(stad);
    const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint16_t subtype = dot11_frame_control_get_subtype(header->frame_control);

    if (subtype == DOT11_FC_SUBTYPE_ACTION)
    {
        /* Block Ack action frames (ADDBA req/resp, DELBA) drive the per-peer BA session for
         * A-MPDU: route them to the BA state machine keyed on the TRANSMITTING peer's stad,
         * mirroring net/mac80211 ieee80211_rx_h_action's `case WLAN_CATEGORY_BACK` for a
         * MESH_POINT vif. The BA agreement is per-link, so resolve the peer stad from the frame's
         * SA (A2). Everything else (MPM/AMPE peering, HWMP path selection) -> mesh action handler. */
        const struct dot11_action *action =
            (const struct dot11_action *)mmpkt_get_data_start(rxbufview);
        if (action->field.category == DOT11_ACTION_CATEGORY_BLOCK_ACK)
        {
            struct umac_sta_data *peer_stad = umac_mesh_get_peer_stad(dot11_get_sa(header));
            if (peer_stad != NULL)
            {
                umac_ba_process_rx_frame(peer_stad,
                                         mmpkt_get_data_start(rxbufview),
                                         mmpkt_get_data_length(rxbufview));
            }
            return;
        }
        umac_mesh_handle_action(umacd, rxbufview);
    }
    else if (subtype == DOT11_FC_SUBTYPE_AUTH)
    {
        umac_mesh_handle_auth(umacd, rxbufview); /* SAE peering */
    }
}

static bool nullop_update_stad_state_mesh(struct umac_sta_data *stad,
                                          const struct mmdrv_rx_metadata *metadata,
                                          uint16_t frame_control_le)
{
    MM_UNUSED(frame_control_le);
    return stad != NULL && metadata != NULL;
}

static void umac_datapath_mesh_handle_frame_unknown_sta(struct umac_data *umacd, const uint8_t *ta)
{
    MM_UNUSED(umacd);
    MM_UNUSED(ta);
}

/* Mesh peering uses ACTION frames (MPM/AMPE) + AUTH frames (SAE) pre-association; allow them (and
 * beacons) through. */
static const uint16_t frames_allowed_pre_association_mesh[] = {
    DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, ACTION),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, AUTH),
    UINT16_MAX,
};

static const struct umac_datapath_ops datapath_ops_mesh = {
    .process_rx_mgmt_frame = umac_datapath_process_rx_mgmt_frame_mesh,
    .lookup_stad_by_peer_addr = umac_datapath_lookup_stad_by_peer_addr_mesh,
    .lookup_stad_by_tx_dest_addr = umac_datapath_lookup_stad_by_tx_dest_addr_mesh,
    .lookup_stad_by_aid = umac_datapath_lookup_stad_by_aid_mesh,
    .update_stad_state_rx = nullop_update_stad_state_mesh,
    .is_stad_tx_paused = umac_sta_data_is_paused,
    .enqueue_tx_frame = umac_datapath_tx_queue_frame_mesh,
    .dequeue_tx_frame = umac_datapath_tx_dequeue_frame_mesh,
    .construct_80211_data_header = umac_datapath_construct_80211_data_header_mesh,
    .get_sta_state = umac_datapath_get_state_mesh,
    .supp_l2_sock_receive = umac_supp_l2_sock_receive,
    .handle_frame_unknown_sta = umac_datapath_mesh_handle_frame_unknown_sta,
    .frames_allowed_pre_association = frames_allowed_pre_association_mesh,
    .type = "MESH",
};

const struct umac_datapath_ops *const umac_datapath_ops_mesh = &datapath_ops_mesh;
