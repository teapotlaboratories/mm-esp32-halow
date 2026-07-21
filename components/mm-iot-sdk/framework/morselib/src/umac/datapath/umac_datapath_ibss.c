/*
 * Copyright 2026 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

/*
 * IBSS (ad-hoc) datapath ops table. Mirrors the per-vif ops model upstream introduced for STA/AP
 * (umac_datapath_sta.c / umac_datapath_ap.c). IBSS is association-less and self-beaconing, so the
 * plumbing looks like STA's but resolves stads to our own "common" (BSS) stad plus per-peer stads.
 * Bound onto the VIF_STA host-slot at umac_interface_add(UMAC_INTERFACE_ADHOC, ...).
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
#include "umac/scan/umac_scan.h"
#include "umac/stats/umac_stats.h"
#include "umac/ibss/umac_ibss.h"
#include "common/mac_address.h"

/* IBSS rx lookup: each unicast sender gets its own per-peer stad so the receive-side sequence
 * number / dedup state is isolated per sender. Broadcast/multicast/NULL -> the common stad. */
static struct umac_sta_data *umac_datapath_lookup_stad_by_peer_addr_ibss(struct umac_data *umacd,
                                                                         const uint8_t *addr)
{
    MM_UNUSED(umacd);
    if (addr == NULL || mm_mac_addr_is_zero(addr) || mm_mac_addr_is_multicast(addr))
    {
        return umac_ibss_get_common_stad();
    }
    return umac_ibss_get_or_create_peer_stad(addr);
}

/* IBSS tx-dest lookup: always the common stad (one SNS2/3 sequence space per IEEE 802.11; the
 * receiver dedupes per-sender, not per-(sender, my-MAC)). */
static struct umac_sta_data *umac_datapath_lookup_stad_by_tx_dest_addr_ibss(struct umac_data *umacd,
                                                                            const uint8_t *addr)
{
    MM_UNUSED(umacd);
    MM_UNUSED(addr);
    return umac_ibss_get_common_stad();
}

/* IBSS aid lookup (tx-status): the common stad carries AID 0. */
static struct umac_sta_data *umac_datapath_lookup_stad_by_aid_ibss(struct umac_data *umacd,
                                                                   uint16_t aid)
{
    MM_UNUSED(umacd);
    if (aid == 0)
    {
        return umac_ibss_get_common_stad();
    }
    return NULL;
}

/* In IBSS there is no association handshake; the controlled port is always open, so report
 * CONNECTED to allow data tx/rx through the common stad. */
static enum mmwlan_sta_state umac_datapath_get_state_ibss(struct umac_sta_data *stad)
{
    MM_UNUSED(stad);
    return MMWLAN_STA_CONNECTED;
}

static void umac_datapath_process_rx_mgmt_frame_ibss(struct umac_data *umacd,
                                                     struct umac_sta_data *stad,
                                                     struct mmpktview *rxbufview)
{
    const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint16_t subtype = dot11_frame_control_get_subtype(header->frame_control);

    switch (subtype)
    {
        case DOT11_FC_SUBTYPE_PROBE_REQ:
            umac_ibss_handle_probe_req(umacd, rxbufview);
            break;

        case DOT11_FC_SUBTYPE_PROBE_RSP:
        case DOT11_FC_SUBTYPE_BEACON:
            umac_scan_process_probe_resp(umacd, rxbufview);
            break;

        default:
            MM_UNUSED(stad);
            break;
    }
}

/* IBSS data frames are sent peer-to-peer: ToDS=0, FromDS=0, addr1=DA, addr2=SA (this node),
 * addr3=BSSID. (Contrast STA mode, which sets ToDS and addr1=BSSID.) */
static void umac_datapath_construct_80211_data_header_ibss(struct umac_sta_data *stad,
                                                           const struct umac_8023_hdr *hdr_8023,
                                                           struct dot11_data_hdr *data_hdr)
{
    uint16_t frame_control = DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE |
                             DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE;

    mac_addr_copy(data_hdr->base.addr1, hdr_8023->dest_addr);
    umac_interface_get_mac_addr(stad, data_hdr->base.addr2);
    umac_sta_data_get_bssid(stad, data_hdr->base.addr3);
    data_hdr->base.frame_control = htole16(frame_control);
}

static bool nullop_update_stad_state_ibss(struct umac_sta_data *stad,
                                          const struct mmdrv_rx_metadata *metadata,
                                          uint16_t frame_control_le)
{
    MM_UNUSED(frame_control_le);
    return stad != NULL && metadata != NULL;
}

static void umac_datapath_tx_queue_frame_ibss(struct umac_data *umacd,
                                              struct umac_sta_data *stad,
                                              struct mmpkt *txbuf)
{
    MMOSAL_TASK_ENTER_CRITICAL();
    umac_sta_data_queue_pkt(stad, txbuf);
    umac_stats_update_datapath_txq_high_water_mark(umacd, umac_sta_data_get_queued_len(stad));
    MMOSAL_TASK_EXIT_CRITICAL();
}

/* IBSS dequeue: STA-mode dequeue uses umac_connection_get_stad(), which is NULL for IBSS (no
 * association FSM). Use the common stad directly, otherwise enqueued frames sit forever. */
static bool umac_datapath_tx_dequeue_frame_ibss(struct umac_data *umacd,
                                                struct umac_sta_data **stad_ptr,
                                                struct mmpkt **txbuf_ptr)
{
    MM_UNUSED(umacd);
    MMOSAL_ASSERT(stad_ptr && txbuf_ptr);
    *stad_ptr = NULL;
    *txbuf_ptr = NULL;

    struct umac_sta_data *stad = umac_ibss_get_common_stad();
    if (stad == NULL || umac_sta_data_is_paused(stad))
    {
        return false;
    }

    MMOSAL_TASK_ENTER_CRITICAL();
    *txbuf_ptr = umac_sta_data_pop_pkt(stad);
    bool has_more = umac_sta_data_get_queued_len(stad);
    MMOSAL_TASK_EXIT_CRITICAL();
    if (*txbuf_ptr != NULL)
    {
        *stad_ptr = stad;
    }
    return has_more;
}

static void umac_datapath_ibss_handle_frame_unknown_sta(struct umac_data *umacd, const uint8_t *ta)
{
    MM_UNUSED(umacd);
    MM_UNUSED(ta);
}

/* IBSS frames allowed from a not-yet-known sender. Like STA mode (not AP mode), S1G beacons must
 * be allowed: otherwise the RX filter falls through to dot11_get_ta(), which for an S1G beacon
 * reads the time_stamp field (addr2 offset) and mints a fresh phantom peer every beacon. Allowing
 * S1G_BEACON routes beacons to umac_datapath_process_s1g_beacon, which does proper
 * source_addr-based peer discovery and drops SA=BSSID. */
static const uint16_t frames_allowed_pre_association_ibss[] = {
    DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, PROBE_RSP),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, ACTION),
    UINT16_MAX,
};

static const struct umac_datapath_ops datapath_ops_ibss = {
    .process_rx_mgmt_frame = umac_datapath_process_rx_mgmt_frame_ibss,
    .lookup_stad_by_peer_addr = umac_datapath_lookup_stad_by_peer_addr_ibss,
    .lookup_stad_by_tx_dest_addr = umac_datapath_lookup_stad_by_tx_dest_addr_ibss,
    .lookup_stad_by_aid = umac_datapath_lookup_stad_by_aid_ibss,
    .update_stad_state_rx = nullop_update_stad_state_ibss,
    .is_stad_tx_paused = umac_sta_data_is_paused,
    .enqueue_tx_frame = umac_datapath_tx_queue_frame_ibss,
    .dequeue_tx_frame = umac_datapath_tx_dequeue_frame_ibss,
    .construct_80211_data_header = umac_datapath_construct_80211_data_header_ibss,
    .get_sta_state = umac_datapath_get_state_ibss,
    .supp_l2_sock_receive = umac_supp_l2_sock_receive,
    .handle_frame_unknown_sta = umac_datapath_ibss_handle_frame_unknown_sta,
    .frames_allowed_pre_association = frames_allowed_pre_association_ibss,
    .type = "IBSS",
};

const struct umac_datapath_ops *const umac_datapath_ops_ibss = &datapath_ops_ibss;
