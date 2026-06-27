/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * 802.11s mesh — host-side bring-up + self-beaconing (P1).
 *
 * Mirrors umac/ibss (association-less, self-beaconing vif). The bring-up
 * sequence follows morse_driver's mesh BSS config flow:
 *   ADD_INTERFACE(MESH) -> SET_CHANNEL -> BSS_CONFIG -> BSSID_SET
 *   -> BSS_BEACON_CONFIG -> arm host beacon engine -> MESH_CONFIG(START).
 * MESH_CONFIG(START) with MBCA enabled makes the firmware run an MBSS TBTT-selection
 * scan and then fire periodic beacon interrupts, which the host serves. The beacon
 * carries a zero-length SSID plus the Mesh ID and Mesh Configuration IEs, like a
 * mac80211 mesh beacon. Peering / HWMP / path table come in P2+.
 */

#include <string.h>

#include "common/common.h"
#include "common/consbuf.h"
#include "common/mac_address.h"
#include "common/morse_commands.h"
#include <stdio.h> /* TEMP(debug): printf for MESH-SEC returns (morselib MMLOG isn't on the ESP console) */
#include "mmdrv.h"
#include "mmhal_wlan.h"
#include "mmlog.h"
#include "mmosal.h"
#include "dot11/dot11.h"
#include "dot11/dot11_utils.h"
#include "umac/connection/umac_connection.h"
#include "umac/core/umac_core.h"
#include "umac/data/umac_data.h"
#include "umac/datapath/umac_datapath.h"
#include "umac/frames/frames_common.h"
#include "umac/ies/s1g_capabilities.h"
#include "umac/ies/ssid.h"
#include "umac/interface/umac_interface.h"
#include "umac/interface/umac_interface_data.h"
#include "umac/mesh/umac_mesh.h"
#include "umac/rc/umac_rc.h"
#include "umac/regdb/umac_regdb.h"

/* 802.11s element IDs (per IEEE 802.11). */
#define DOT11_IE_MESH_CONFIGURATION (113)
#define DOT11_IE_MESH_ID            (114)

/* Mesh beacons advertise no ESS/IBSS in the capability field. */
#define MESH_CAPABILITY_INFO (0)

struct umac_mesh_context
{
    bool active;
    bool link_up;        /* netif signalled up (after first peer ESTAB) */
    bool group_tx_key_installed; /* P1: own MGTK (group TX) installed at first ESTAB (deferred from start) */
    uint8_t mesh_mac[6]; /* our MAC: SA and BSSID in beacons */
    uint8_t mesh_id[MORSE_CMD_MESH_ID_LEN_MAX];
    uint8_t mesh_id_len;
    uint16_t beacon_interval_tu;
    uint8_t s1g_op_chan_width;
    uint8_t s1g_operating_class;
    uint8_t s1g_primary_chan;
    uint8_t s1g_centre_chan;
    uint16_t vif_id;
    /* "Common" stad represents the MBSS for broadcast/multicast + mgmt TX (mirrors the
     * IBSS common stad). Per-peer stads are added with MPM peering. */
    struct umac_sta_data *common_stad;
};

/* Single interface is supported, so a file-static context is sufficient. */
static struct umac_mesh_context mesh_ctx;

bool umac_mesh_is_active(void)
{
    return mesh_ctx.active;
}

struct umac_sta_data *umac_mesh_get_common_stad(void)
{
    return mesh_ctx.common_stad;
}

uint32_t umac_mesh_next_seqnum(void)
{
    /* Monotonic mesh sequence number for the Mesh Control header (net/mac80211 uses a per-vif
     * atomic counter, ieee80211_new_mesh_header). */
    static uint32_t mesh_seqnum;
    return mesh_seqnum++;
}

/* Mesh Configuration element (7 octets) — open HWMP/airtime mesh accepting
 * peers. Matches mac80211's mesh_config defaults so a Linux mesh node treats us
 * as a compatible peer: a mesh node silently ignores beacons whose path
 * protocol / metric / congestion / sync / auth don't match its own. Linux
 * defaults the synchronization method to neighbour-offset (0x01). */
static void mesh_build_config_ie(struct consbuf *buf)
{
    const uint8_t cfg[2 + 7] = {
        DOT11_IE_MESH_CONFIGURATION,
        7,
        0x01, /* Active Path Selection Protocol: HWMP */
        0x01, /* Active Path Selection Metric:   Airtime */
        0x00, /* Congestion Control Mode:        none */
        0x01, /* Synchronization Method:         neighbour offset (mac80211 default) */
        0x00, /* Authentication Protocol:        open */
        0x00, /* Mesh Formation Info:            0 peerings */
        0x01, /* Mesh Capability:                Accepting Additional Peerings */
    };
    consbuf_append(buf, cfg, sizeof(cfg));
}

/* S1G short-beacon frame control: version 0, type EXT(3), subtype S1G_BEACON(1) => low byte
 * 0x1c; high byte 0x08 matches the morse Linux reference (no Next-TBTT/Compressed-SSID/ANO
 * optional fields present, so the IEs follow the 15-byte header directly). */
#define MESH_S1G_BEACON_FC (0x081cu)

static void umac_mesh_build_beacon(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    (void)params;

    /* Build a HaLow S1G short beacon (ext type3/sub1), matching morse Linux mesh — NOT a
     * legacy PV0 beacon. For a MESH-type vif the firmware transmits the host beacon as-is (it
     * only auto-generates S1G beacons for AP-type vifs), so the host must emit S1G itself, like
     * the Linux morse_driver's morse_dot11ah_beacon_to_s1g. The 15-byte single-address header
     * (FC, duration, source_addr, time_stamp, change_sequence) then the IEs. */
    struct dot11_s1g_beacon_hdr *hdr =
        (struct dot11_s1g_beacon_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        memset(hdr, 0, sizeof(*hdr));
        hdr->frame_control = htole16(MESH_S1G_BEACON_FC);
        hdr->duration = 0;
        mac_addr_copy(hdr->source_addr, mesh_ctx.mesh_mac);
        hdr->time_stamp = 0;     /* partial TSF — firmware fills if it manages beacon timing */
        hdr->change_sequence = 0;
    }

    /* S1G Beacon Compatibility (213): carries the beacon interval (the S1G beacon has no
     * legacy Beacon Interval fixed field). */
    struct dot11_ie_s1g_beacon_compatibility *compat =
        (struct dot11_ie_s1g_beacon_compatibility *)consbuf_reserve(buf, sizeof(*compat));
    if (compat)
    {
        memset(compat, 0, sizeof(*compat));
        compat->header.element_id = DOT11_IE_S1G_BEACON_COMPATIBILITY;
        compat->header.length = sizeof(*compat) - sizeof(compat->header);
        compat->compat_info = 0;
        compat->beacon_int = htole16(mesh_ctx.beacon_interval_tu);
        compat->tsf_completion = 0;
    }

    ie_s1g_capabilities_build(umacd, buf);

    struct dot11_ie_s1g_operation *op =
        (struct dot11_ie_s1g_operation *)consbuf_reserve(buf, sizeof(*op));
    if (op)
    {
        memset(op, 0, sizeof(*op));
        op->header.element_id = DOT11_IE_S1G_OPERATION;
        op->header.length = sizeof(*op) - sizeof(op->header);
        op->channel_width = mesh_ctx.s1g_op_chan_width;
        op->operating_class = mesh_ctx.s1g_operating_class;
        op->primary_channel_number = mesh_ctx.s1g_primary_chan;
        op->channel_center_freq = mesh_ctx.s1g_centre_chan;
    }

    /* Mesh ID IE (114) then Mesh Configuration IE (113). */
    const uint8_t mesh_id_hdr[2] = { DOT11_IE_MESH_ID, mesh_ctx.mesh_id_len };
    consbuf_append(buf, mesh_id_hdr, sizeof(mesh_id_hdr));
    consbuf_append(buf, mesh_ctx.mesh_id, mesh_ctx.mesh_id_len);
    mesh_build_config_ie(buf);
}

struct mmpkt *umac_mesh_get_beacon(struct umac_data *umacd)
{
    struct mmpkt *beacon = build_mgmt_frame(umacd, umac_mesh_build_beacon, NULL);
    if (beacon == NULL)
    {
        MMLOG_WRN("Failed to generate mesh beacon\n");
        return NULL;
    }

    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(beacon);
    tx_metadata->flags = MMDRV_TX_FLAG_IMMEDIATE_REPORT;
    tx_metadata->tid = MMWLAN_MAX_QOS_TID;
    tx_metadata->vif_id = mesh_ctx.vif_id;
    umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);

    return beacon;
}

/* --- Mesh Peering Management (MPM) ------------------------------------------
 *
 * Derived from net/mac80211/mesh_plink.c. The peer-link finite state machine and
 * the Self-Protected Action frame layout mirror mac80211 so a Linux mesh node (the
 * reference) completes a peer link with us. Frame layout matches a captured
 * chronium<->chronite exchange (docs/worklog/2026-06-26-mesh-mpm-peering-frames.md):
 *
 *   Category = 15 (Self-Protected); Action 1=Open, 2=Confirm, 3=Close.
 *   Open:    Capability(2)          + IEs
 *   Confirm: Capability(2) + AID(2) + IEs
 *   Close:                            IEs
 *   IEs: [S1G Capabilities] Mesh ID(114) [Mesh Configuration(113)] Mesh Peering Mgmt(117)
 *   Mesh Peering Mgmt (117): protocol(2)=0, local-link-id(2)[, peer-link-id(2)][, reason(2)]
 *   (link ids little-endian).
 *
 * Link-id convention (matches mac80211): in a frame WE send, the element's
 * local-link-id is OUR id (peer->llid) and the peer-link-id echoes the peer's id
 * (peer->plid). In a frame we RECEIVE, the element's local-link-id is the peer's id
 * (-> peer->plid) and the peer-link-id (if present) echoes our id.
 *
 * P2 scope: responder side. The Linux node initiates (it opens on hearing our
 * "accepting peerings" beacon); we answer Open with Open+Confirm and reach ESTAB.
 * Initiating on a heard beacon, per-peer stads, retransmit/holding timers, and the
 * data path are later increments.
 */

#define DOT11_CATEGORY_SELF_PROTECTED (15)
#define WLAN_SP_MESH_PEERING_OPEN     (1)
#define WLAN_SP_MESH_PEERING_CONFIRM  (2)
#define WLAN_SP_MESH_PEERING_CLOSE    (3)
#define DOT11_IE_PEER_MGMT            (117)

/* HWMP path selection (net/mac80211/mesh_hwmp.c). Mesh Action category, action code, and the
 * PREQ/PREP element IDs + lengths. We implement the minimal target behaviour: reply to a PREQ
 * that targets us with a PREP, so a Linux peer can resolve a mesh path to us and deliver
 * unicast. */
#define DOT11_CATEGORY_MESH               (13)
#define WLAN_MESH_ACTION_HWMP_PATH_SEL    (1)
#define DOT11_IE_PREQ                     (130)
#define DOT11_IE_PREP                     (131)
#define DOT11_IE_PERR                     (132)
#define HWMP_PREQ_IE_LEN                  (37)
#define HWMP_PREP_IE_LEN                  (31)
#define HWMP_PERR_IE_LEN                  (15) /* ttl + num_dest(1) + one target (flags+addr+sn+rcode) */
#define HWMP_ELEMENT_TTL                  (31)
#define HWMP_MPATH_PREQ                   (0)
#define HWMP_MPATH_PREP                   (1)

/* Mesh path table (mesh_pathtbl.c) + HWMP on-demand routing. We keep a small path table and a
 * simplified metric (a fixed per-hop cost; mac80211 uses airtime) — sufficient for a line
 * topology with no competing paths. */
#define MESH_MAX_PATHS        (8)
#define MESH_PATH_LINK_METRIC (100)
#define MESH_PATH_LIFETIME_MS (30000) /* refresh well before traffic stalls */
#define MESH_PREQ_MIN_GAP_MS  (250)   /* rate-limit path discovery per destination */
/* The PREQ Lifetime field is in TUs, not ms (mesh_hwmp.c `MSEC_TO_TU(x) = x*1000/1024`). */
#define MESH_MSEC_TO_TU(ms)   ((uint32_t)((ms) * 1000u / 1024u))
/* PREQ per-target flags (ieee80211.h): Target-Only — only the target replies (not an
 * intermediate node with a possibly-stale path). mac80211 sets it on a path refresh. */
#define MESH_PREQ_TO_FLAG     (1u << 0)

/* Sequence-number comparison with wraparound (net/mac80211 SN_GT). */
#define MESH_SN_GT(a, b) ((int32_t)((b) - (a)) < 0)

/* 802.11 mesh peering reason codes. */
#define MESH_REASON_PEERING_CANCELLED (52)
#define MESH_REASON_MAX_RETRIES       (56)
#define MESH_REASON_CONFIRM_TIMEOUT   (57)
#define MESH_REASON_PATH_NOFORWARD    (62) /* WLAN_REASON_MESH_PATH_NOFORWARD — PERR reason code */

/* A link to a next hop broke: invalidate every path through it and announce the now-unreachable
 * destinations with a PERR (mesh_path_error_tx / mesh_plink_broken). Declared early so the MPM
 * tick and the Close handler can tear paths down when a peer is lost. */
static void umac_mesh_invalidate_paths_via(const uint8_t *next_hop);

/* Peer-link retransmission (mac80211 mesh_plink_timer). A single periodic tick services all
 * peers: resend Open in OPN_SNT/OPN_RCVD/CNF_RCVD until ESTAB or max retries, then Close ->
 * HOLDING -> free (the next heard beacon re-opens). The HaLow PHY is slow, so the interval is
 * coarser than mac80211's default. */
#define MESH_PLINK_RETRY_INTERVAL_MS (300)
#define MESH_PLINK_RETRY_JITTER_MS   (200) /* break lockstep so two peers' Opens don't collide */
#define MESH_PLINK_MAX_RETRIES       (16)  /* ~5 s of silence (counter resets on any RX) before
                                            * giving up — avoids tearing down an active handshake */
#define MESH_PLINK_HOLDING_TICKS     (2)
/* Established-peer inactivity (mac80211 mesh_sta_cleanup / ieee80211_sta_expire with
 * mshcfg.plink_timeout). With ~100 ms beacons, no frame from a peer for this long means the
 * link is broken: close it, flush paths through it (-> PERR), and free the slot. */
#define MESH_PLINK_INACTIVITY_MS     (6000)

/* Peer-link states (mirror NL80211_PLINK_*). */
enum mesh_plink_state
{
    MESH_PLINK_LISTEN = 0,
    MESH_PLINK_OPN_SNT,
    MESH_PLINK_OPN_RCVD,
    MESH_PLINK_CNF_RCVD,
    MESH_PLINK_ESTAB,
    MESH_PLINK_HOLDING,
};

#define MESH_MAX_PEERS (4)

/* Phase-1 mesh-security EXPERIMENT: install a static MTK/MGTK to prove the MM6108 firmware
 * accepts SET_STA_STATE + INSTALL_KEY on a MESH vif. Derived from the Linux MESH path (NOT the AP
 * association flow): own group key at start = hostap __mesh_rsn_auth_init (mesh_rsn.c:216-231);
 * per-peer keys at ESTAB = mesh_mpm_plink_estab (mesh_mpm.c:916-960); the firmware command mapping
 * is morse_driver mac.c set_key/sta_state. See docs/mesh-ap/rimba-mesh-security-codemap.md. Keys
 * are FIXED/shared, not AMPE/SAE-derived — P2 (AMPE) + P3 (SAE) replace them. 0 = restore open mesh. */
#ifndef MMWLAN_MESH_SEC_PHASE1
#define MMWLAN_MESH_SEC_PHASE1 (1)
#endif

struct mesh_peer
{
    bool used;
    uint8_t mac[MMWLAN_MAC_ADDR_LEN];
    uint16_t llid; /* our local link id for this peer */
    uint16_t plid; /* the peer's link id */
    uint16_t aid;  /* firmware station AID for this peer (index+1; AP gets this from hostapd) */
    enum mesh_plink_state state;
    uint8_t retries; /* Open retransmits (or holding ticks while HOLDING) */
    uint32_t last_rx_ms; /* last frame heard from this peer (mac80211 sta last_rx) */
};

static struct mesh_peer mesh_peers[MESH_MAX_PEERS];

/* Optional peer allowlist — used to force a test topology (e.g. line/multi-hop) on a bench
 * where all nodes are in range. Empty (count 0) = peer with anyone, the normal behaviour. */
#define MESH_ALLOWLIST_MAX (4)
static uint8_t mesh_allowlist[MESH_ALLOWLIST_MAX][MMWLAN_MAC_ADDR_LEN];
static uint8_t mesh_allowlist_count;

void mmwlan_mesh_set_peer_allowlist(const uint8_t *macs, uint8_t count)
{
    mesh_allowlist_count = (count > MESH_ALLOWLIST_MAX) ? MESH_ALLOWLIST_MAX : count;
    for (uint8_t i = 0; i < mesh_allowlist_count; i++)
    {
        mac_addr_copy(mesh_allowlist[i], &macs[i * MMWLAN_MAC_ADDR_LEN]);
    }
}

static bool mesh_peer_allowed(const uint8_t *mac)
{
    if (mesh_allowlist_count == 0)
    {
        return true;
    }
    for (uint8_t i = 0; i < mesh_allowlist_count; i++)
    {
        if (memcmp(mesh_allowlist[i], mac, MMWLAN_MAC_ADDR_LEN) == 0)
        {
            return true;
        }
    }
    return false;
}

bool umac_mesh_peer_allowed(const uint8_t *mac)
{
    return mesh_peer_allowed(mac);
}

static struct mesh_peer *mesh_peer_find(const uint8_t *mac)
{
    for (size_t i = 0; i < MESH_MAX_PEERS; i++)
    {
        if (mesh_peers[i].used && memcmp(mesh_peers[i].mac, mac, MMWLAN_MAC_ADDR_LEN) == 0)
        {
            return &mesh_peers[i];
        }
    }
    return NULL;
}

static struct mesh_peer *mesh_peer_alloc(const uint8_t *mac)
{
    for (size_t i = 0; i < MESH_MAX_PEERS; i++)
    {
        if (!mesh_peers[i].used)
        {
            struct mesh_peer *p = &mesh_peers[i];
            memset(p, 0, sizeof(*p));
            p->used = true;
            mac_addr_copy(p->mac, mac);
            p->state = MESH_PLINK_LISTEN;
            /* AID = pool index + 1 (non-zero; AID 0 is the group key). Linux mesh assigns the
             * peer AID in wpa_supplicant (hostapd_get_aid, mesh_mpm.c:798); morselib has no
             * supplicant, so we self-assign from the fixed peer pool (platform divergence). */
            p->aid = (uint16_t)(i + 1);
            p->last_rx_ms = mmosal_get_time_ms();
            /* A non-zero local link id, generated per peer (mac80211 mesh_plink_open). */
            do
            {
                p->llid = (uint16_t)mmhal_random_u32(1, 0xffff);
            } while (p->llid == 0);
            return p;
        }
    }
    return NULL;
}

struct mesh_peering_params
{
    const uint8_t *da;
    uint8_t action;
    uint16_t llid;
    uint16_t plid;   /* echoed peer id; included for Confirm (and Close if non-zero) */
    uint16_t reason; /* Close only */
};

static void umac_mesh_build_peering(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    const struct mesh_peering_params *p = (const struct mesh_peering_params *)params;

    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        dot11_build_pv0_mgmt_header(hdr, DOT11_FC_SUBTYPE_ACTION, 0, p->da, mesh_ctx.mesh_mac,
                                    mesh_ctx.mesh_mac);
    }

    const bool is_close = (p->action == WLAN_SP_MESH_PEERING_CLOSE);
    const bool is_confirm = (p->action == WLAN_SP_MESH_PEERING_CONFIRM);

    const uint8_t cat_act[2] = { DOT11_CATEGORY_SELF_PROTECTED, p->action };
    consbuf_append(buf, cat_act, sizeof(cat_act));

    /* Fixed fields: Open/Confirm carry Capability; Confirm also carries AID. */
    if (!is_close)
    {
        uint16_t cap = htole16(MESH_CAPABILITY_INFO);
        consbuf_append(buf, (const uint8_t *)&cap, sizeof(cap));
    }
    if (is_confirm)
    {
        uint16_t aid = htole16(1); /* single peer link; AID 1 (echoed in the peer's log) */
        consbuf_append(buf, (const uint8_t *)&aid, sizeof(aid));
    }

    /* Information elements. Close carries only Mesh ID + Mesh Peering Mgmt. */
    if (!is_close)
    {
        ie_s1g_capabilities_build(umacd, buf);
    }
    const uint8_t mesh_id_hdr[2] = { DOT11_IE_MESH_ID, mesh_ctx.mesh_id_len };
    consbuf_append(buf, mesh_id_hdr, sizeof(mesh_id_hdr));
    consbuf_append(buf, mesh_ctx.mesh_id, mesh_ctx.mesh_id_len);
    if (!is_close)
    {
        mesh_build_config_ie(buf);
    }

    /* Mesh Peering Management element (117). */
    const bool include_plid = is_confirm || (is_close && p->plid != 0);
    const uint8_t ie_len = (uint8_t)(2 /* protocol */ + 2 /* local link id */ +
                                     (include_plid ? 2 : 0) + (is_close ? 2 : 0));
    const uint8_t mpm_hdr[2] = { DOT11_IE_PEER_MGMT, ie_len };
    consbuf_append(buf, mpm_hdr, sizeof(mpm_hdr));
    uint16_t protocol = htole16(0); /* 0 = base MPM (no vendor / no AMPE) */
    consbuf_append(buf, (const uint8_t *)&protocol, sizeof(protocol));
    uint16_t v = htole16(p->llid);
    consbuf_append(buf, (const uint8_t *)&v, sizeof(v));
    if (include_plid)
    {
        v = htole16(p->plid);
        consbuf_append(buf, (const uint8_t *)&v, sizeof(v));
    }
    if (is_close)
    {
        v = htole16(p->reason);
        consbuf_append(buf, (const uint8_t *)&v, sizeof(v));
    }
}

static enum mmwlan_status umac_mesh_tx_peering(uint8_t action, const struct mesh_peer *peer,
                                               uint16_t reason)
{
    if (!mesh_ctx.active || mesh_ctx.common_stad == NULL)
    {
        return MMWLAN_UNAVAILABLE;
    }

    struct umac_data *umacd = umac_data_get_umacd();
    struct mesh_peering_params params = {
        .da = peer->mac,
        .action = action,
        .llid = peer->llid,
        .plid = peer->plid,
        .reason = reason,
    };
    struct mmpkt *frame = build_mgmt_frame(umacd, umac_mesh_build_peering, &params);
    if (frame == NULL)
    {
        MMLOG_WRN("mesh peering build failed\n");
        return MMWLAN_NO_MEM;
    }

    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(frame);
    tx_metadata->vif_id = mesh_ctx.vif_id;
    return umac_datapath_tx_mgmt_frame(mesh_ctx.common_stad, frame);
}

/* Periodic peer-link retransmission, mirroring mac80211's mesh_plink_timer. One tick
 * services every peer: while a handshake is in progress (OPN_SNT/OPN_RCVD/CNF_RCVD) it
 * retransmits the Open until ESTAB or max retries, then sends a reason-coded Close and
 * holds briefly before freeing the slot (the next heard beacon re-opens). Resending the
 * Open is what recovers a lost frame — e.g. a peer stuck in CNF_RCVD reaches ESTAB when
 * the other side retransmits its Open. Runs in the umac event-loop context (same as the
 * RX handler), so TX from here is safe. Self-reschedules while the mesh is active. */
static void umac_mesh_plink_tick(void *arg1, void *arg2)
{
    (void)arg2;
    struct umac_data *umacd = (struct umac_data *)arg1;
    if (!mesh_ctx.active)
    {
        return; /* mesh stopped: let the timer lapse */
    }

    uint32_t now = mmosal_get_time_ms();
    for (size_t i = 0; i < MESH_MAX_PEERS; i++)
    {
        struct mesh_peer *peer = &mesh_peers[i];
        if (!peer->used)
        {
            continue;
        }
        switch (peer->state)
        {
        case MESH_PLINK_OPN_SNT:
        case MESH_PLINK_OPN_RCVD:
        case MESH_PLINK_CNF_RCVD:
            if (peer->retries < MESH_PLINK_MAX_RETRIES)
            {
                peer->retries++;
                (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_OPEN, peer, 0);
            }
            else
            {
                uint16_t reason = (peer->state == MESH_PLINK_CNF_RCVD)
                                      ? MESH_REASON_CONFIRM_TIMEOUT
                                      : MESH_REASON_MAX_RETRIES;
                (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CLOSE, peer, reason);
                peer->state = MESH_PLINK_HOLDING;
                peer->retries = 0;
                MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " HOLDING (peering timed out)\n",
                          MM_MAC_ADDR_VAL(peer->mac));
            }
            break;

        case MESH_PLINK_HOLDING:
            if (++peer->retries >= MESH_PLINK_HOLDING_TICKS)
            {
                umac_mesh_invalidate_paths_via(peer->mac); /* paths through this peer are dead */
                peer->used = false; /* free; the next heard beacon re-opens */
            }
            break;

        case MESH_PLINK_ESTAB:
            /* Link-failure detection: no frame from this peer for too long means the link is
             * gone (ieee80211_sta_expire -> mesh_plink_deactivate). Close it, flush the paths
             * that ran through it (which announces each with a PERR), and free the slot. */
            if ((uint32_t)(now - peer->last_rx_ms) > MESH_PLINK_INACTIVITY_MS)
            {
                (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CLOSE, peer,
                                           MESH_REASON_PEERING_CANCELLED);
                MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " inactive %ums; link down\n",
                          MM_MAC_ADDR_VAL(peer->mac), (unsigned)(now - peer->last_rx_ms));
                umac_mesh_invalidate_paths_via(peer->mac);
                peer->used = false; /* free; the next heard beacon re-opens */
            }
            break;

        default: /* LISTEN: nothing to retransmit */
            break;
        }
    }

    uint32_t jitter = mmhal_random_u32(0, MESH_PLINK_RETRY_JITTER_MS);
    (void)umac_core_register_timeout(umacd, MESH_PLINK_RETRY_INTERVAL_MS + jitter,
                                     umac_mesh_plink_tick, umacd, NULL);
}

void umac_mesh_handle_peer_beacon(const uint8_t *peer_mac, const uint8_t *ies, uint32_t ies_len)
{
    if (!mesh_ctx.active || peer_mac == NULL || ies == NULL)
    {
        return;
    }
    /* Only peer within our own MBSS: require a Mesh ID (114) that matches ours. A peer mesh
     * node's S1G beacon carries the Mesh ID like any mesh beacon. */
    uint32_t off = 0;
    while (off + 2 <= ies_len)
    {
        uint8_t id = ies[off];
        uint8_t len = ies[off + 1];
        if (off + 2 + len > ies_len)
        {
            break;
        }
        if (id == DOT11_IE_MESH_ID)
        {
            if (len == mesh_ctx.mesh_id_len && memcmp(&ies[off + 2], mesh_ctx.mesh_id, len) == 0)
            {
                /* A beacon from an existing peer is a liveness heartbeat (mac80211 last_rx);
                 * for an unknown candidate it opens a new peering. */
                struct mesh_peer *peer = mesh_peer_find(peer_mac);
                if (peer != NULL)
                {
                    peer->last_rx_ms = mmosal_get_time_ms();
                }
                else
                {
                    mmwlan_mesh_peer_open(peer_mac);
                }
            }
            return;
        }
        off += 2 + len;
    }
}

/* Signal the netif up once the first peer link is established, so lwIP can use the mesh.
 * DE-RISK NOTE: this exercises the data TX path (currently the IBSS 3-address header, no Mesh
 * Control header) to observe what the firmware does with mesh data frames before building the
 * full 4-address + Mesh Control path. */
static void umac_mesh_link_up_once(void)
{
    if (mesh_ctx.link_up)
    {
        return;
    }
    mesh_ctx.link_up = true;
    umac_connection_signal_link_state(umac_data_get_umacd(), MMWLAN_VIF_AP, MMWLAN_LINK_UP);
    MMLOG_INF("MESH link up (first peer established)\n");
}

#if MMWLAN_MESH_SEC_PHASE1
/* Phase-1 static test keys: a fixed 128-bit MTK + MGTK, identical on every node so a
 * static-key ESP mesh still interoperates. NOT secure (no per-pair derivation) — this only
 * exercises the firmware key-install path. */
static const uint8_t mesh_p1_mtk[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const uint8_t mesh_p1_mgtk[16] = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};

/* Own TX group key — mirrors hostap __mesh_rsn_auth_init (mesh_rsn.c:216-231): at mesh START
 * each node installs its OWN MGTK once, keyed to the group so it can encrypt its broadcast/group
 * TX. Linux: wpa_drv_set_key(addr=broadcast, key_idx=1, set_tx=1, KEY_FLAG_GROUP_TX_DEFAULT);
 * morse_driver maps a group key (no sta) to aid=0 (mac.c:5153) -> INSTALL_KEY{GTK, aid=0, idx=1}.
 * (The own IGTK is BIP, which morse handles in software (mac.c:5187), so it is NOT sent to FW.)
 * This is the step the AP path lacks — an AP installs one BSS GTK, not a per-node mesh group key. */
static void umac_mesh_install_own_group_key(void)
{
    struct mmdrv_key_conf mgtk = { .is_pairwise = false, .tx_pn = 0, .length = 16, .key_idx = 1 };
    memcpy(mgtk.key, mesh_p1_mgtk, sizeof(mesh_p1_mgtk));
    int ret = mmdrv_install_key(mesh_ctx.vif_id, 0 /* aid 0 = own group TX key */, &mgtk);
    printf("MESH-SEC own MGTK (group TX) aid=0 ret=%d\n", ret);
}

/* Per-peer key install at ESTAB — mirrors hostap mesh_mpm_plink_estab (mesh_mpm.c:916-960).
 * Linux drives the peer sta up to AUTHORIZED via SET_STATION plink-state; morse_driver forwards
 * one SET_STA_STATE per transition but FILTERS NOTEXIST/NONE (mac.c:4813), so AUTH is the first
 * firmware command and the station is created there. Keys install once the peer is AUTHORIZED:
 *   - MTK  pairwise, key_idx 0, aid=peer  (mesh_mpm.c:928 KEY_FLAG_PAIRWISE_RX_TX -> PTK)
 *   - MGTK group RX, key_idx 1, aid=peer  (mesh_mpm.c:938 KEY_FLAG_GROUP_RX     -> GTK)
 * The peer IGTK (mesh_mpm.c:945) is BIP -> software on morse (mac.c:5187), not sent to FW.
 * Logs every return so we can confirm the firmware accepts these on a MESH vif (the -116 question). */
static void umac_mesh_peer_secure_estab(struct mesh_peer *peer)
{
    uint16_t vif = mesh_ctx.vif_id;
    static const enum morse_sta_state seq[] = {
        MORSE_STA_AUTHENTICATED, MORSE_STA_ASSOCIATED, MORSE_STA_AUTHORIZED
    };
    int ret;

    /* Install our own MGTK (group TX, aid=0) on the FIRST ESTAB — deferred from mesh start
     * (where it breaks open peering). Once per mesh session; subsequent peers reuse it. With
     * the own group key + the peer's group RX key (below), broadcast/group frames encrypt. */
    if (!mesh_ctx.group_tx_key_installed)
    {
        umac_mesh_install_own_group_key();
        mesh_ctx.group_tx_key_installed = true;
    }

    for (size_t i = 0; i < sizeof(seq) / sizeof(seq[0]); i++)
    {
        ret = mmdrv_update_sta_state(vif, peer->aid, peer->mac, seq[i]);
        printf("MESH-SEC sta_state aid=%u state=%u ret=%d\n", peer->aid, seq[i], ret);
    }

    struct mmdrv_key_conf mtk = { .is_pairwise = true, .tx_pn = 0, .length = 16, .key_idx = 0 };
    memcpy(mtk.key, mesh_p1_mtk, sizeof(mesh_p1_mtk));
    ret = mmdrv_install_key(vif, peer->aid, &mtk);
    printf("MESH-SEC install MTK (pairwise) aid=%u ret=%d\n", peer->aid, ret);

    struct mmdrv_key_conf mgtk = { .is_pairwise = false, .tx_pn = 0, .length = 16, .key_idx = 1 };
    memcpy(mgtk.key, mesh_p1_mgtk, sizeof(mesh_p1_mgtk));
    ret = mmdrv_install_key(vif, peer->aid, &mgtk);
    printf("MESH-SEC install peer MGTK (group RX) aid=%u ret=%d\n", peer->aid, ret);
}
#endif /* MMWLAN_MESH_SEC_PHASE1 */

void mmwlan_mesh_peer_open(const uint8_t *peer_mac)
{
    if (!mesh_ctx.active || peer_mac == NULL)
    {
        return;
    }
    if (memcmp(peer_mac, mesh_ctx.mesh_mac, MMWLAN_MAC_ADDR_LEN) == 0)
    {
        return; /* never peer with ourselves */
    }
    if (!mesh_peer_allowed(peer_mac))
    {
        return; /* forced-topology allowlist */
    }
    if (mesh_peer_find(peer_mac) != NULL)
    {
        return; /* already tracking this peer (idempotent — beacons arrive continuously) */
    }
    struct mesh_peer *peer = mesh_peer_alloc(peer_mac);
    if (peer == NULL)
    {
        return;
    }
    /* mesh_plink_open(): send a Mesh Peering Open, -> OPN_SNT. */
    enum mmwlan_status st = umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_OPEN, peer, 0);
    peer->state = MESH_PLINK_OPN_SNT;
    MMLOG_INF("MESH open -> " MM_MAC_ADDR_FMT " OPN_SNT st=%d llid=0x%04x\n",
              MM_MAC_ADDR_VAL(peer_mac), (int)st, peer->llid);
}

void mmwlan_mesh_send_test_action(void)
{
    /* Retired: peering is now driven by the MPM state machine — initiated on a heard
     * peer beacon (mmwlan_mesh_peer_open) and answered on a received Open
     * (umac_mesh_handle_action). Kept as a no-op for ABI compatibility. */
}

/* Locate the Mesh Peering Management element (117) in an action body and read its
 * link ids. Returns false if absent/malformed. *peer_plid = the sender's link id;
 * *our_llid_echo = the peer-link-id field (0 if not present). */
static bool mesh_parse_peering_ie(const uint8_t *body, uint32_t body_len, uint8_t action,
                                  uint16_t *peer_plid, uint16_t *our_llid_echo)
{
    /* Skip the fixed fields: Open=Capability(2); Confirm=Capability(2)+AID(2); Close=0. */
    uint32_t off;
    if (action == WLAN_SP_MESH_PEERING_OPEN)
    {
        off = 2 + 2;
    }
    else if (action == WLAN_SP_MESH_PEERING_CONFIRM)
    {
        off = 2 + 2 + 2;
    }
    else
    {
        off = 2; /* close: category + action only */
    }

    while (off + 2 <= body_len)
    {
        uint8_t id = body[off];
        uint8_t len = body[off + 1];
        if (off + 2 + len > body_len)
        {
            break;
        }
        if (id == DOT11_IE_PEER_MGMT && len >= 4)
        {
            const uint8_t *p = &body[off + 2]; /* protocol(2), local-link-id(2)[, peer-link-id(2)] */
            *peer_plid = (uint16_t)(p[2] | (p[3] << 8));
            *our_llid_echo = (len >= 6) ? (uint16_t)(p[4] | (p[5] << 8)) : 0;
            return true;
        }
        off += 2 + len;
    }
    return false;
}

/* --- HWMP path selection (minimal target behaviour) ------------------------
 *
 * Derived from net/mac80211/mesh_hwmp.c. mac80211 forwards ALL mesh unicast via the path
 * table, even to a directly-peered neighbour: it sends a PREQ targeting the destination and
 * waits for a PREP before the path goes ACTIVE. We implement only the target side — on a PREQ
 * that targets us, reply with a PREP — so a Linux peer can resolve a path to us and deliver
 * unicast (ARP/ICMP replies). Our own unicast TX is direct single-hop (next hop = the peer),
 * so we don't originate PREQs yet. PREQ/PREP element layout per mesh_hwmp.c
 * (mesh_path_sel_frame_tx). */

static uint32_t mesh_hwmp_sn;      /* our sequence number (ifmsh->sn equivalent) */
static uint32_t mesh_hwmp_preq_id; /* PREQ id generator */

struct mesh_path_entry
{
    bool used;
    bool active;
    uint8_t dest[MMWLAN_MAC_ADDR_LEN];
    uint8_t next_hop[MMWLAN_MAC_ADDR_LEN];
    uint32_t sn;     /* sequence number we know for dest */
    uint32_t metric; /* accumulated path metric to dest */
    uint8_t hop_count;
    uint32_t expiry_ms;
    uint32_t last_preq_ms;
};

static struct mesh_path_entry mesh_paths[MESH_MAX_PATHS];

static uint32_t mesh_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static struct mesh_path_entry *mesh_path_find(const uint8_t *dest)
{
    for (size_t i = 0; i < MESH_MAX_PATHS; i++)
    {
        if (mesh_paths[i].used && memcmp(mesh_paths[i].dest, dest, MMWLAN_MAC_ADDR_LEN) == 0)
        {
            return &mesh_paths[i];
        }
    }
    return NULL;
}

static struct mesh_path_entry *mesh_path_get_or_add(const uint8_t *dest)
{
    struct mesh_path_entry *p = mesh_path_find(dest);
    if (p != NULL)
    {
        return p;
    }
    struct mesh_path_entry *victim = NULL;
    for (size_t i = 0; i < MESH_MAX_PATHS; i++)
    {
        if (!mesh_paths[i].used)
        {
            victim = &mesh_paths[i];
            break;
        }
        if (victim == NULL || mesh_paths[i].expiry_ms < victim->expiry_ms)
        {
            victim = &mesh_paths[i];
        }
    }
    if (victim != NULL)
    {
        memset(victim, 0, sizeof(*victim));
        victim->used = true;
        mac_addr_copy(victim->dest, dest);
    }
    return victim;
}

/* Install/refresh a path to `dest` reachable via `next_hop` — "fresh info" rule from
 * hwmp_route_info_get: take it if the path is inactive, the SN is newer, or the SN is equal
 * and the metric is better. */
static void mesh_path_update(const uint8_t *dest, const uint8_t *next_hop, uint32_t sn,
                             uint32_t metric, uint8_t hop_count)
{
    if (memcmp(dest, mesh_ctx.mesh_mac, MMWLAN_MAC_ADDR_LEN) == 0)
    {
        return; /* never a path to ourselves */
    }
    struct mesh_path_entry *p = mesh_path_get_or_add(dest);
    if (p == NULL)
    {
        return;
    }
    bool fresh = !p->active || MESH_SN_GT(sn, p->sn) || (sn == p->sn && metric < p->metric);
    if (fresh)
    {
        mac_addr_copy(p->next_hop, next_hop);
        p->sn = sn;
        p->metric = metric;
        p->hop_count = hop_count;
        p->active = true;
        p->expiry_ms = mmosal_get_time_ms() + MESH_PATH_LIFETIME_MS;
    }
}

bool umac_mesh_lookup_next_hop(const uint8_t *dest, uint8_t *next_hop_out)
{
    struct mesh_path_entry *p = mesh_path_find(dest);
    if (p != NULL && p->active && (int32_t)(p->expiry_ms - mmosal_get_time_ms()) > 0)
    {
        mac_addr_copy(next_hop_out, p->next_hop);
        return true;
    }
    if (p != NULL)
    {
        p->active = false; /* expired */
    }
    return false;
}

/* --- HWMP PREQ/PREP action frames (mesh_path_sel_frame_tx) ------------------ */

struct hwmp_frame_params
{
    uint8_t action; /* HWMP_MPATH_PREQ / HWMP_MPATH_PREP */
    const uint8_t *da;
    uint8_t flags;
    uint8_t hop_count;
    uint8_t ttl;
    uint32_t preq_id; /* PREQ only */
    uint8_t orig_addr[MMWLAN_MAC_ADDR_LEN];
    uint32_t orig_sn;
    uint32_t lifetime;
    uint32_t metric;
    uint8_t target_flags; /* PREQ only */
    uint8_t target_addr[MMWLAN_MAC_ADDR_LEN];
    uint32_t target_sn;
};

static void umac_mesh_append_le32(struct consbuf *buf, uint32_t v)
{
    uint32_t le = htole32(v);
    consbuf_append(buf, (const uint8_t *)&le, sizeof(le));
}

static void umac_mesh_build_hwmp(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    (void)umacd;
    const struct hwmp_frame_params *p = (const struct hwmp_frame_params *)params;
    const bool is_preq = (p->action == HWMP_MPATH_PREQ);

    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        dot11_build_pv0_mgmt_header(hdr, DOT11_FC_SUBTYPE_ACTION, 0, p->da, mesh_ctx.mesh_mac,
                                    mesh_ctx.mesh_mac);
    }
    const uint8_t cat_act[2] = { DOT11_CATEGORY_MESH, WLAN_MESH_ACTION_HWMP_PATH_SEL };
    consbuf_append(buf, cat_act, sizeof(cat_act));

    const uint8_t pre[5] = { is_preq ? DOT11_IE_PREQ : DOT11_IE_PREP,
                             is_preq ? HWMP_PREQ_IE_LEN : HWMP_PREP_IE_LEN, p->flags, p->hop_count,
                             p->ttl };
    consbuf_append(buf, pre, sizeof(pre));

    if (is_preq)
    {
        umac_mesh_append_le32(buf, p->preq_id);
        consbuf_append(buf, p->orig_addr, MMWLAN_MAC_ADDR_LEN);
        umac_mesh_append_le32(buf, p->orig_sn);
    }
    else
    {
        consbuf_append(buf, p->target_addr, MMWLAN_MAC_ADDR_LEN);
        umac_mesh_append_le32(buf, p->target_sn);
    }
    umac_mesh_append_le32(buf, p->lifetime);
    umac_mesh_append_le32(buf, p->metric);
    if (is_preq)
    {
        const uint8_t dc[2] = { 1, p->target_flags }; /* destination count = 1 */
        consbuf_append(buf, dc, sizeof(dc));
        consbuf_append(buf, p->target_addr, MMWLAN_MAC_ADDR_LEN);
        umac_mesh_append_le32(buf, p->target_sn);
    }
    else
    {
        consbuf_append(buf, p->orig_addr, MMWLAN_MAC_ADDR_LEN);
        umac_mesh_append_le32(buf, p->orig_sn);
    }
}

static void umac_mesh_tx_hwmp(struct hwmp_frame_params *p)
{
    if (!mesh_ctx.active || mesh_ctx.common_stad == NULL)
    {
        return;
    }
    struct umac_data *umacd = umac_data_get_umacd();
    struct mmpkt *frame = build_mgmt_frame(umacd, umac_mesh_build_hwmp, p);
    if (frame == NULL)
    {
        return;
    }
    mmdrv_get_tx_metadata(frame)->vif_id = mesh_ctx.vif_id;
    (void)umac_datapath_tx_mgmt_frame(mesh_ctx.common_stad, frame);
}

/* Originate a PREQ to discover a path to `dest` (mesh_queue_preq). Rate-limited per dest. */
void umac_mesh_start_discovery(const uint8_t *dest)
{
    if (!mesh_ctx.active)
    {
        return;
    }
    struct mesh_path_entry *p = mesh_path_get_or_add(dest);
    uint32_t now = mmosal_get_time_ms();
    if (p != NULL && p->last_preq_ms != 0 && (now - p->last_preq_ms) < MESH_PREQ_MIN_GAP_MS)
    {
        return; /* don't flood PREQs */
    }
    if (p != NULL)
    {
        p->last_preq_ms = now;
    }
    struct hwmp_frame_params q = { .action = HWMP_MPATH_PREQ,
                                   .da = mac_addr_broadcast,
                                   .flags = 0,
                                   .hop_count = 0,
                                   .ttl = HWMP_ELEMENT_TTL,
                                   .preq_id = ++mesh_hwmp_preq_id,
                                   .orig_sn = ++mesh_hwmp_sn,
                                   .lifetime = MESH_MSEC_TO_TU(MESH_PATH_LIFETIME_MS),
                                   .metric = 0,
                                   /* Target-Only on a refresh (we already know this dest's SN),
                                    * so only the target answers — not an intermediate with a
                                    * stale path (mesh_queue_preq / PREQ_Q_F_REFRESH). */
                                   .target_flags = (p != NULL && p->sn != 0) ? MESH_PREQ_TO_FLAG : 0,
                                   .target_sn = (p != NULL) ? p->sn : 0 };
    mac_addr_copy(q.orig_addr, mesh_ctx.mesh_mac);
    mac_addr_copy(q.target_addr, dest);
    umac_mesh_tx_hwmp(&q);
    MMLOG_INF("MESH PREQ for " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(dest));
}

/* --- HWMP PERR (path error) — mesh_path_error_tx / hwmp_perr_frame_process ---
 * One destination per PERR (like mesh_path_error_tx). Element: ttl, num_dest(=1), then the
 * target {flags=0, addr(6), sn(4), reason(2)}. */
struct hwmp_perr_params
{
    const uint8_t *da; /* RA — broadcast (announce) or a specific peer */
    uint8_t ttl;
    uint8_t target_addr[MMWLAN_MAC_ADDR_LEN];
    uint32_t target_sn;
    uint16_t reason;
};

static void umac_mesh_build_perr(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    (void)umacd;
    const struct hwmp_perr_params *p = (const struct hwmp_perr_params *)params;

    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        dot11_build_pv0_mgmt_header(hdr, DOT11_FC_SUBTYPE_ACTION, 0, p->da, mesh_ctx.mesh_mac,
                                    mesh_ctx.mesh_mac);
    }
    const uint8_t cat_act[2] = { DOT11_CATEGORY_MESH, WLAN_MESH_ACTION_HWMP_PATH_SEL };
    consbuf_append(buf, cat_act, sizeof(cat_act));

    const uint8_t pre[4] = { DOT11_IE_PERR, HWMP_PERR_IE_LEN, p->ttl, 1 /* num destinations */ };
    consbuf_append(buf, pre, sizeof(pre));
    const uint8_t target_flags = 0; /* AE bit only, unused (no proxy) */
    consbuf_append(buf, &target_flags, sizeof(target_flags));
    consbuf_append(buf, p->target_addr, MMWLAN_MAC_ADDR_LEN);
    umac_mesh_append_le32(buf, p->target_sn);
    uint16_t rc = htole16(p->reason);
    consbuf_append(buf, (const uint8_t *)&rc, sizeof(rc));
}

static void umac_mesh_tx_perr(struct hwmp_perr_params *p)
{
    if (!mesh_ctx.active || mesh_ctx.common_stad == NULL)
    {
        return;
    }
    struct umac_data *umacd = umac_data_get_umacd();
    struct mmpkt *frame = build_mgmt_frame(umacd, umac_mesh_build_perr, p);
    if (frame == NULL)
    {
        return;
    }
    mmdrv_get_tx_metadata(frame)->vif_id = mesh_ctx.vif_id;
    (void)umac_datapath_tx_mgmt_frame(mesh_ctx.common_stad, frame);
}

static void umac_mesh_invalidate_paths_via(const uint8_t *next_hop)
{
    for (size_t i = 0; i < MESH_MAX_PATHS; i++)
    {
        struct mesh_path_entry *p = &mesh_paths[i];
        if (!p->used || !p->active ||
            memcmp(p->next_hop, next_hop, MMWLAN_MAC_ADDR_LEN) != 0)
        {
            continue;
        }
        /* Bump the destination SN so a stale cached PREP can't reinstate the dead path
         * (mesh_plink_broken does ++mpath->sn before mesh_path_error_tx), then announce it. */
        p->active = false;
        p->sn++;
        struct hwmp_perr_params perr = { .da = mac_addr_broadcast,
                                         .ttl = HWMP_ELEMENT_TTL,
                                         .target_sn = p->sn,
                                         .reason = MESH_REASON_PATH_NOFORWARD };
        mac_addr_copy(perr.target_addr, p->dest);
        umac_mesh_tx_perr(&perr);
        MMLOG_INF("MESH PERR tx: dest " MM_MAC_ADDR_FMT " unreachable (next-hop "
                  MM_MAC_ADDR_FMT " lost)\n",
                  MM_MAC_ADDR_VAL(p->dest), MM_MAC_ADDR_VAL(next_hop));
    }
}

static void umac_mesh_handle_hwmp(const uint8_t *body, uint32_t body_len, const uint8_t *frame_sa)
{
    /* Only learn paths from an allowed neighbour (the immediate transmitter). With a forced
     * topology this stops us learning a direct path to a node we should only reach via a relay
     * (all bench nodes are in RF range, so HWMP would otherwise resolve a 1-hop path). */
    if (!mesh_peer_allowed(frame_sa))
    {
        return;
    }
    uint32_t off = 2; /* after category(13) + action(1) */
    while (off + 2 <= body_len)
    {
        uint8_t id = body[off];
        uint8_t len = body[off + 1];
        if (off + 2 + len > body_len)
        {
            break;
        }
        const uint8_t *e = &body[off + 2];

        if (id == DOT11_IE_PREQ && len >= HWMP_PREQ_IE_LEN)
        {
            /* flags[0] hop_count[1] ttl[2] preq_id[3..6] orig[7..12] orig_sn[13..16]
             * lifetime[17..20] metric[21..24] dest_count[25] target_flags[26] target[27..32]
             * target_sn[33..36]. */
            uint8_t flags = e[0], hop_count = e[1], ttl = e[2];
            uint32_t preq_id = mesh_rd32(&e[3]);
            const uint8_t *orig_addr = &e[7];
            uint32_t orig_sn = mesh_rd32(&e[13]);
            uint32_t lifetime = mesh_rd32(&e[17]);
            uint32_t metric = mesh_rd32(&e[21]);
            uint8_t target_flags = e[26];
            const uint8_t *target_addr = &e[27];
            uint32_t target_sn = mesh_rd32(&e[33]);
            uint32_t new_metric = metric + MESH_PATH_LINK_METRIC;

            /* Reverse path: the originator is reachable via the immediate sender. */
            mesh_path_update(orig_addr, frame_sa, orig_sn, new_metric, (uint8_t)(hop_count + 1));

            if (memcmp(target_addr, mesh_ctx.mesh_mac, MMWLAN_MAC_ADDR_LEN) == 0)
            {
                /* We are the target — reply with a PREP back toward the originator. */
                struct hwmp_frame_params prep = { .action = HWMP_MPATH_PREP,
                                                  .da = frame_sa,
                                                  .flags = 0,
                                                  .hop_count = 0,
                                                  .ttl = HWMP_ELEMENT_TTL,
                                                  .orig_sn = orig_sn,
                                                  .lifetime = lifetime,
                                                  .metric = 0,
                                                  .target_sn = ++mesh_hwmp_sn };
                mac_addr_copy(prep.orig_addr, orig_addr);
                mac_addr_copy(prep.target_addr, mesh_ctx.mesh_mac);
                umac_mesh_tx_hwmp(&prep);
                MMLOG_INF("MESH PREP -> " MM_MAC_ADDR_FMT " (orig " MM_MAC_ADDR_FMT ")\n",
                          MM_MAC_ADDR_VAL(frame_sa), MM_MAC_ADDR_VAL(orig_addr));
            }
            else if (ttl > 1)
            {
                /* Forward (flood) the PREQ for someone else. */
                struct hwmp_frame_params fwd = { .action = HWMP_MPATH_PREQ,
                                                 .da = mac_addr_broadcast,
                                                 .flags = flags,
                                                 .hop_count = (uint8_t)(hop_count + 1),
                                                 .ttl = (uint8_t)(ttl - 1),
                                                 .preq_id = preq_id,
                                                 .orig_sn = orig_sn,
                                                 .lifetime = lifetime,
                                                 .metric = new_metric,
                                                 .target_flags = target_flags,
                                                 .target_sn = target_sn };
                mac_addr_copy(fwd.orig_addr, orig_addr);
                mac_addr_copy(fwd.target_addr, target_addr);
                umac_mesh_tx_hwmp(&fwd);
            }
            return;
        }

        if (id == DOT11_IE_PREP && len >= HWMP_PREP_IE_LEN)
        {
            /* flags[0] hop_count[1] ttl[2] target[3..8] target_sn[9..12] lifetime[13..16]
             * metric[17..20] orig[21..26] orig_sn[27..30]. */
            uint8_t flags = e[0], hop_count = e[1], ttl = e[2];
            const uint8_t *target_addr = &e[3];
            uint32_t target_sn = mesh_rd32(&e[9]);
            uint32_t lifetime = mesh_rd32(&e[13]);
            uint32_t metric = mesh_rd32(&e[17]);
            const uint8_t *orig_addr = &e[21];
            uint32_t orig_sn = mesh_rd32(&e[27]);
            uint32_t new_metric = metric + MESH_PATH_LINK_METRIC;

            /* Forward path: the target is reachable via the immediate sender. */
            mesh_path_update(target_addr, frame_sa, target_sn, new_metric, (uint8_t)(hop_count + 1));

            if (memcmp(orig_addr, mesh_ctx.mesh_mac, MMWLAN_MAC_ADDR_LEN) == 0)
            {
                MMLOG_INF("MESH path to " MM_MAC_ADDR_FMT " via " MM_MAC_ADDR_FMT " (metric %u)\n",
                          MM_MAC_ADDR_VAL(target_addr), MM_MAC_ADDR_VAL(frame_sa),
                          (unsigned)new_metric);
            }
            else if (ttl > 1)
            {
                /* Forward the PREP toward the originator via our path to it. */
                uint8_t nh[MMWLAN_MAC_ADDR_LEN];
                if (umac_mesh_lookup_next_hop(orig_addr, nh))
                {
                    struct hwmp_frame_params fwd = { .action = HWMP_MPATH_PREP,
                                                     .da = nh,
                                                     .flags = flags,
                                                     .hop_count = (uint8_t)(hop_count + 1),
                                                     .ttl = (uint8_t)(ttl - 1),
                                                     .orig_sn = orig_sn,
                                                     .lifetime = lifetime,
                                                     .metric = new_metric,
                                                     .target_sn = target_sn };
                    mac_addr_copy(fwd.orig_addr, orig_addr);
                    mac_addr_copy(fwd.target_addr, target_addr);
                    umac_mesh_tx_hwmp(&fwd);
                }
            }
            return;
        }

        if (id == DOT11_IE_PERR && len >= HWMP_PERR_IE_LEN)
        {
            /* ttl[0] num_dest[1] then each target {flags(1) addr(6) sn(4) rcode(2)} = 13B. */
            uint8_t ttl = e[0];
            uint8_t num_dest = e[1];
            uint32_t doff = 2;
            for (uint8_t d = 0; d < num_dest && doff + 13 <= len; d++, doff += 13)
            {
                const uint8_t *dest = &e[doff + 1];
                uint32_t dest_sn = mesh_rd32(&e[doff + 7]);
                /* Tear down our path to `dest` only if it actually goes via the PERR sender and
                 * the announced SN isn't older than ours (hwmp_perr_frame_process). */
                struct mesh_path_entry *p = mesh_path_find(dest);
                if (p == NULL || !p->active ||
                    memcmp(p->next_hop, frame_sa, MMWLAN_MAC_ADDR_LEN) != 0 ||
                    MESH_SN_GT(p->sn, dest_sn))
                {
                    continue;
                }
                p->active = false;
                p->sn = dest_sn;
                MMLOG_INF("MESH PERR rx: path to " MM_MAC_ADDR_FMT " via " MM_MAC_ADDR_FMT
                          " torn down\n",
                          MM_MAC_ADDR_VAL(dest), MM_MAC_ADDR_VAL(frame_sa));
                if (ttl > 1)
                {
                    /* Propagate to our upstream neighbours (broadcast flood, ttl-1). */
                    struct hwmp_perr_params fwd = {
                        .da = mac_addr_broadcast,
                        .ttl = (uint8_t)(ttl - 1),
                        .target_sn = dest_sn,
                        .reason = (uint16_t)(e[doff + 11] | ((uint16_t)e[doff + 12] << 8))
                    };
                    mac_addr_copy(fwd.target_addr, dest);
                    umac_mesh_tx_perr(&fwd);
                }
            }
            return;
        }
        off += 2 + len;
    }
}

/* --- Mesh data forwarding (ESP as an intermediate hop) ---------------------- */

struct mesh_forward_params
{
    uint8_t next_hop[MMWLAN_MAC_ADDR_LEN];
    const uint8_t *mesh_da;
    const uint8_t *mesh_sa;
    uint32_t seqnum;
    const uint8_t *payload; /* LLC/SNAP + IP, copied verbatim */
    uint32_t payload_len;
};

static void umac_mesh_build_forward(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    (void)umacd;
    const struct mesh_forward_params *p = (const struct mesh_forward_params *)params;

    struct dot11_data_hdr *hdr = (struct dot11_data_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        memset(hdr, 0, sizeof(*hdr));
        uint16_t fc = ((uint16_t)DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE) |
                      ((uint16_t)DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE) |
                      (uint16_t)DOT11_MASK_FC_TO_DS | (uint16_t)DOT11_MASK_FC_FROM_DS;
        hdr->base.frame_control = htole16(fc);
        mac_addr_copy(hdr->base.addr1, p->next_hop);     /* RA = next hop */
        mac_addr_copy(hdr->base.addr2, mesh_ctx.mesh_mac); /* TA = us */
        mac_addr_copy(hdr->base.addr3, p->mesh_da);       /* mesh DA (unchanged) */
        mac_addr_copy(hdr->addr4, p->mesh_sa);            /* mesh SA (preserved) */
    }
    uint16_t qos = htole16(0x0100u); /* QoS Control: Mesh Control Present */
    consbuf_append(buf, (const uint8_t *)&qos, sizeof(qos));
    const uint8_t mc[6] = { 0, HWMP_ELEMENT_TTL, (uint8_t)p->seqnum, (uint8_t)(p->seqnum >> 8),
                            (uint8_t)(p->seqnum >> 16), (uint8_t)(p->seqnum >> 24) };
    consbuf_append(buf, mc, sizeof(mc)); /* Mesh Control: flags, ttl, seqnum */
    consbuf_append(buf, p->payload, p->payload_len);
}

bool umac_mesh_forward_data(const uint8_t *mesh_da, const uint8_t *mesh_sa, const uint8_t *payload,
                            uint32_t payload_len)
{
    if (!mesh_ctx.active || mesh_ctx.common_stad == NULL)
    {
        return false;
    }
    uint8_t next_hop[MMWLAN_MAC_ADDR_LEN];
    if (!umac_mesh_lookup_next_hop(mesh_da, next_hop))
    {
        umac_mesh_start_discovery(mesh_da); /* no path yet — drop, resolve for next time */
        return false;
    }
    struct mesh_forward_params p = { .mesh_da = mesh_da,
                                     .mesh_sa = mesh_sa,
                                     .seqnum = umac_mesh_next_seqnum(),
                                     .payload = payload,
                                     .payload_len = payload_len };
    mac_addr_copy(p.next_hop, next_hop);

    struct umac_data *umacd = umac_data_get_umacd();
    struct mmpkt *frame = build_mgmt_frame(umacd, umac_mesh_build_forward, &p);
    if (frame == NULL)
    {
        return false;
    }
    mmdrv_get_tx_metadata(frame)->vif_id = mesh_ctx.vif_id;
    (void)umac_datapath_tx_mgmt_frame(mesh_ctx.common_stad, frame);
    return true;
}

/* --- Group-addressed mesh forwarding + duplicate cache (RMC) ----------------
 *
 * net/mac80211 re-broadcasts group-addressed mesh frames (so bcast/mcast — e.g. ARP — reach
 * the whole mesh) and uses a mesh RMC to drop duplicates / suppress loops, keyed on the
 * originator's (mesh SA, mesh seqnum). We mirror that: on a fresh group frame, re-broadcast it
 * (3-address fromDS, A1=bcast, A2=us, A3=mesh-SA unchanged, ttl-1, seqnum preserved) AND deliver
 * locally; duplicates / our own echoes are dropped. */

#define MESH_RMC_SIZE      (16)
#define MESH_RMC_WINDOW_MS (2000)

struct mesh_rmc_entry
{
    bool used;
    uint8_t sa[MMWLAN_MAC_ADDR_LEN];
    uint32_t seqnum;
    uint32_t time_ms;
};
static struct mesh_rmc_entry mesh_rmc[MESH_RMC_SIZE];
static uint8_t mesh_rmc_next;

static bool mesh_rmc_seen(const uint8_t *sa, uint32_t seqnum)
{
    uint32_t now = mmosal_get_time_ms();
    for (size_t i = 0; i < MESH_RMC_SIZE; i++)
    {
        if (mesh_rmc[i].used && mesh_rmc[i].seqnum == seqnum &&
            memcmp(mesh_rmc[i].sa, sa, MMWLAN_MAC_ADDR_LEN) == 0 &&
            (now - mesh_rmc[i].time_ms) < MESH_RMC_WINDOW_MS)
        {
            return true; /* duplicate */
        }
    }
    struct mesh_rmc_entry *e = &mesh_rmc[mesh_rmc_next++ % MESH_RMC_SIZE];
    e->used = true;
    mac_addr_copy(e->sa, sa);
    e->seqnum = seqnum;
    e->time_ms = now;
    return false;
}

struct mesh_rebcast_params
{
    const uint8_t *mesh_sa;
    uint8_t ttl;
    uint32_t seqnum;
    const uint8_t *payload;
    uint32_t payload_len;
};

static void umac_mesh_build_rebcast(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    (void)umacd;
    const struct mesh_rebcast_params *p = (const struct mesh_rebcast_params *)params;

    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        memset(hdr, 0, sizeof(*hdr));
        uint16_t fc = ((uint16_t)DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE) |
                      ((uint16_t)DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE) |
                      (uint16_t)DOT11_MASK_FC_FROM_DS; /* group: 3-address, fromDS */
        hdr->frame_control = htole16(fc);
        mac_addr_copy(hdr->addr1, mac_addr_broadcast);   /* DA = broadcast */
        mac_addr_copy(hdr->addr2, mesh_ctx.mesh_mac);    /* TA = us */
        mac_addr_copy(hdr->addr3, p->mesh_sa);           /* mesh SA (unchanged) */
    }
    /* Mesh Control Present + Ack Policy "No Ack" (0x0020) — group-addressed frames are never
     * acked (matches mac80211's QoS ack policy for multicast RA). */
    uint16_t qos = htole16(0x0100u | 0x0020u);
    consbuf_append(buf, (const uint8_t *)&qos, sizeof(qos));
    const uint8_t mc[6] = { 0, (uint8_t)(p->ttl - 1), (uint8_t)p->seqnum, (uint8_t)(p->seqnum >> 8),
                            (uint8_t)(p->seqnum >> 16), (uint8_t)(p->seqnum >> 24) };
    consbuf_append(buf, mc, sizeof(mc));
    consbuf_append(buf, p->payload, p->payload_len);
}

bool umac_mesh_handle_group_data(const uint8_t *mesh_sa, uint8_t ttl, uint32_t seqnum,
                                 const uint8_t *payload, uint32_t payload_len)
{
    if (!mesh_ctx.active)
    {
        return false;
    }
    if (memcmp(mesh_sa, mesh_ctx.mesh_mac, MMWLAN_MAC_ADDR_LEN) == 0)
    {
        return true; /* our own broadcast echoed back via a relay — drop */
    }
    if (mesh_rmc_seen(mesh_sa, seqnum))
    {
        return true; /* duplicate — drop (don't re-broadcast, don't deliver again) */
    }
    if (ttl > 1 && mesh_ctx.common_stad != NULL)
    {
        struct mesh_rebcast_params p = {
            .mesh_sa = mesh_sa, .ttl = ttl, .seqnum = seqnum, .payload = payload,
            .payload_len = payload_len
        };
        struct umac_data *umacd = umac_data_get_umacd();
        struct mmpkt *frame = build_mgmt_frame(umacd, umac_mesh_build_rebcast, &p);
        if (frame != NULL)
        {
            mmdrv_get_tx_metadata(frame)->vif_id = mesh_ctx.vif_id;
            (void)umac_datapath_tx_mgmt_frame(mesh_ctx.common_stad, frame);
        }
    }
    return false; /* fresh — deliver locally too */
}

void umac_mesh_handle_action(struct umac_data *umacd, struct mmpktview *rxbufview)
{
    (void)umacd;
    const struct dot11_hdr *hdr = (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint32_t total = mmpkt_get_data_length(rxbufview);
    if (total < sizeof(*hdr) + 2)
    {
        return;
    }
    const uint8_t *body = (const uint8_t *)hdr + sizeof(*hdr);
    uint32_t body_len = total - sizeof(*hdr);

    /* HWMP path selection (Mesh Action category 13): reply to a PREQ targeting us. */
    if (body[0] == DOT11_CATEGORY_MESH)
    {
        if (body[1] == WLAN_MESH_ACTION_HWMP_PATH_SEL)
        {
            umac_mesh_handle_hwmp(body, body_len, dot11_get_sa(hdr));
        }
        return;
    }

    if (body[0] != DOT11_CATEGORY_SELF_PROTECTED)
    {
        return;
    }
    const uint8_t action = body[1];
    const uint8_t *sa = dot11_get_sa(hdr);
    MMLOG_INF("MESH action RX from " MM_MAC_ADDR_FMT " action=%u len=%u\n",
              MM_MAC_ADDR_VAL(sa), (unsigned)action, (unsigned)body_len);

    uint16_t peer_plid = 0;
    uint16_t our_llid_echo = 0;
    const bool have_ie = mesh_parse_peering_ie(body, body_len, action, &peer_plid, &our_llid_echo);
    if (!have_ie && action != WLAN_SP_MESH_PEERING_CLOSE)
    {
        MMLOG_WRN("MESH peering from " MM_MAC_ADDR_FMT " action=%u: no Peering Mgmt IE\n",
                  MM_MAC_ADDR_VAL(sa), (unsigned)action);
        return;
    }

    struct mesh_peer *peer = mesh_peer_find(sa);
    if (peer == NULL)
    {
        if (action == WLAN_SP_MESH_PEERING_CLOSE || !mesh_peer_allowed(sa))
        {
            return; /* nothing to tear down, or peer not on the forced-topology allowlist */
        }
        peer = mesh_peer_alloc(sa);
        if (peer == NULL)
        {
            MMLOG_WRN("MESH peer table full; ignoring " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(sa));
            return;
        }
    }

    /* CLOSE: tear the link down (mesh_plink_fsm CLS_ACPT). */
    if (action == WLAN_SP_MESH_PEERING_CLOSE)
    {
        MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " closed (state %u)\n", MM_MAC_ADDR_VAL(sa),
                  (unsigned)peer->state);
        umac_mesh_invalidate_paths_via(peer->mac); /* paths through this peer are dead */
        peer->used = false;
        return;
    }

    /* Stale-session guard: a peer-link-id echo that isn't our current llid means our link
     * ids are out of sync (e.g. the peer rebooted across an established link). Close and
     * free; the next heard beacon re-opens with fresh ids. mac80211 rejects on the same
     * "peer_lid mismatch". */
    if (our_llid_echo != 0 && our_llid_echo != peer->llid)
    {
        MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " llid mismatch echo=0x%04x ours=0x%04x; closing\n",
                  MM_MAC_ADDR_VAL(sa), (unsigned)our_llid_echo, (unsigned)peer->llid);
        (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CLOSE, peer, MESH_REASON_PEERING_CANCELLED);
        peer->used = false;
        return;
    }

    /* Learn the peer's link id; a received peering frame is forward progress, so reset the
     * retransmit counter and mark the peer live (mac80211 last_rx). */
    peer->plid = peer_plid;
    peer->retries = 0;
    peer->last_rx_ms = mmosal_get_time_ms();

    switch (peer->state)
    {
    case MESH_PLINK_LISTEN:
        if (action == WLAN_SP_MESH_PEERING_OPEN)
        {
            /* OPN_ACPT: reply with our Open then a Confirm, then wait for the peer's
             * Confirm. mac80211 sends both frames here. -> OPN_RCVD. */
            (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_OPEN, peer, 0);
            (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CONFIRM, peer, 0);
            peer->state = MESH_PLINK_OPN_RCVD;
            MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " OPN_RCVD (llid=0x%04x plid=0x%04x)\n",
                      MM_MAC_ADDR_VAL(sa), peer->llid, peer->plid);
        }
        break;

    case MESH_PLINK_OPN_SNT:
        if (action == WLAN_SP_MESH_PEERING_OPEN)
        {
            (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CONFIRM, peer, 0);
            peer->state = MESH_PLINK_OPN_RCVD;
        }
        else if (action == WLAN_SP_MESH_PEERING_CONFIRM)
        {
            peer->state = MESH_PLINK_CNF_RCVD;
        }
        break;

    case MESH_PLINK_OPN_RCVD:
        if (action == WLAN_SP_MESH_PEERING_CONFIRM)
        {
            peer->state = MESH_PLINK_ESTAB;
            MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " ESTABLISHED\n", MM_MAC_ADDR_VAL(sa));
            umac_mesh_link_up_once();
#if MMWLAN_MESH_SEC_PHASE1
            umac_mesh_peer_secure_estab(peer);
#endif
        }
        else if (action == WLAN_SP_MESH_PEERING_OPEN)
        {
            (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CONFIRM, peer, 0); /* retransmit */
        }
        break;

    case MESH_PLINK_CNF_RCVD:
        if (action == WLAN_SP_MESH_PEERING_OPEN)
        {
            (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CONFIRM, peer, 0);
            peer->state = MESH_PLINK_ESTAB;
            MMLOG_INF("MESH peer " MM_MAC_ADDR_FMT " ESTABLISHED\n", MM_MAC_ADDR_VAL(sa));
            umac_mesh_link_up_once();
#if MMWLAN_MESH_SEC_PHASE1
            umac_mesh_peer_secure_estab(peer);
#endif
        }
        break;

    case MESH_PLINK_ESTAB:
        if (action == WLAN_SP_MESH_PEERING_OPEN)
        {
            (void)umac_mesh_tx_peering(WLAN_SP_MESH_PEERING_CONFIRM, peer, 0);
        }
        break;

    default:
        break;
    }
}

/* MESH is mutually exclusive with the other vif types: remove anything active. */
static void umac_mesh_tear_down_active_interfaces(struct umac_data *umacd)
{
    struct umac_interface_data *iface = umac_data_get_interface(umacd);
    const enum umac_interface_type maybe_active[] = {
        UMAC_INTERFACE_STA,
        UMAC_INTERFACE_SCAN,
        UMAC_INTERFACE_AP,
        UMAC_INTERFACE_ADHOC,
        UMAC_INTERFACE_NONE,
    };
    for (size_t i = 0; i < sizeof(maybe_active) / sizeof(maybe_active[0]); i++)
    {
        if (iface->active_interface_types & maybe_active[i])
        {
            umac_interface_remove(umacd, maybe_active[i]);
        }
    }
}

enum mmwlan_status mmwlan_mesh_start(const struct mmwlan_mesh_args *args)
{
    if (args == NULL || args->mesh_id_len == 0 || args->mesh_id_len > MORSE_CMD_MESH_ID_LEN_MAX)
    {
        return MMWLAN_INVALID_ARGUMENT;
    }

    struct umac_data *umacd = umac_data_get_umacd();

    /* Boot-time STA (or anything else) must go away — MESH is exclusive. */
    umac_mesh_tear_down_active_interfaces(umacd);

    const uint8_t *iface_mac = args->if_addr;
    if (mm_mac_addr_is_zero(iface_mac))
    {
        iface_mac = NULL; /* inherit the chip's factory MAC */
    }

    uint16_t vif_id = UMAC_INTERFACE_VIF_ID_INVALID;
    enum mmwlan_status status = umac_interface_add(umacd, UMAC_INTERFACE_MESH, iface_mac, &vif_id);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_ERR("MESH interface add failed: %d\n", (int)status);
        return status;
    }

    const struct mmwlan_s1g_channel *chan = umac_regdb_get_channel(umacd, args->s1g_chan_num);
    if (chan == NULL)
    {
        MMLOG_ERR("MESH: unknown S1G channel %u\n", args->s1g_chan_num);
        status = MMWLAN_CHANNEL_INVALID;
        goto fail;
    }

    status = umac_interface_set_channel_from_regdb(umacd, chan, false);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_ERR("MESH: set_channel failed: %d\n", (int)status);
        goto fail;
    }

    int ret = mmdrv_cfg_bss(vif_id, args->beacon_interval_tu, 1, 0);
    if (ret != 0)
    {
        MMLOG_ERR("MESH: cfg_bss failed fw_status=%d\n", ret);
        status = MMWLAN_ERROR;
        goto fail;
    }

    /* Set the BSSID = this node's own MAC (mac80211 sets bss_conf.bssid = vif->addr
     * for mesh; morse_driver sends BSSID_SET on BSS_CHANGED_BSSID). Unlike IBSS,
     * MESH_CONFIG doesn't carry the BSSID, so it must be set separately first. */
    uint8_t mesh_mac[MMWLAN_MAC_ADDR_LEN] = { 0 };
    (void)umac_interface_get_vif_mac_addr(umacd, vif_id, mesh_mac);
    ret = mmdrv_set_bssid(vif_id, mesh_mac);
    if (ret != 0)
    {
        MMLOG_ERR("MESH: set_bssid failed fw_status=%d\n", ret);
        status = MMWLAN_ERROR;
        goto fail;
    }

    /* Set up the beacon context + host beacon engine BEFORE telling the firmware
     * to start beaconing. mmdrv_host_get_beacon() routes here via
     * umac_mesh_is_active(), so the host must be ready to serve beacons the moment
     * MESH_CONFIG(START) enables firmware beaconing — otherwise the firmware
     * beacons into an unready host and the command channel backs up (page
     * exhaustion). 1 MHz primary+operating (channel_width=0x01); the S1G
     * centre/primary channel number both equal s1g_chan_num for a 1 MHz channel. */
    memset(&mesh_ctx, 0, sizeof(mesh_ctx));
    memset(mesh_peers, 0, sizeof(mesh_peers)); /* fresh peer table for this MBSS */
    memset(mesh_paths, 0, sizeof(mesh_paths)); /* fresh HWMP path table */
    memset(mesh_rmc, 0, sizeof(mesh_rmc));     /* fresh duplicate cache */
    mesh_ctx.vif_id = vif_id;
    /* The mesh vif's MAC = the address it was created with: the app's if_addr, or the
     * chip's factory MAC if none was given. Do NOT use umac_interface_get_vif_mac_addr()
     * here — it only resolves the STA/AP roles and returns zero for a mesh vif, which made
     * every beacon/action frame advertise a 00:00 source address (so peers could never be
     * identified — this was the real cause of the "firmware strips the source addr" red
     * herring). This is the node's SA and BSSID in its mesh beacons. */
    if (iface_mac != NULL)
    {
        mac_addr_copy(mesh_ctx.mesh_mac, iface_mac);
    }
    else
    {
        (void)umac_interface_get_device_mac_addr(umacd, mesh_ctx.mesh_mac);
    }
    memcpy(mesh_ctx.mesh_id, args->mesh_id, args->mesh_id_len);
    mesh_ctx.mesh_id_len = args->mesh_id_len;
    mesh_ctx.beacon_interval_tu = args->beacon_interval_tu;
    mesh_ctx.s1g_op_chan_width = 0x01;
    mesh_ctx.s1g_operating_class = (uint8_t)chan->global_operating_class;
    mesh_ctx.s1g_primary_chan = args->s1g_chan_num;
    mesh_ctx.s1g_centre_chan = args->s1g_chan_num;
    mesh_ctx.active = true;

    /* Host-side MBSS state for mgmt/data TX (mirrors umac_ibss_start): a "common" stad
     * representing the mesh BSS, plus the mesh datapath ops. Without this the datapath
     * ops are NULL and any mgmt TX (e.g. Mesh Peering action frames) crashes. The mesh
     * BSSID is this node's own MAC. */
    mesh_ctx.common_stad = umac_sta_data_alloc_static(umacd);
    if (mesh_ctx.common_stad != NULL)
    {
        umac_sta_data_set_bssid(mesh_ctx.common_stad, mesh_ctx.mesh_mac);
        umac_sta_data_set_peer_addr(mesh_ctx.common_stad, mesh_ctx.mesh_mac);
    }
    umac_datapath_configure_mesh_mode(umacd);

    /* Start the peer-link retransmission tick (mesh_plink_timer equivalent). Self-reschedules
     * while the mesh is active; serves Open/Confirm retransmits so handshakes reach ESTAB. */
    (void)umac_core_register_timeout(umacd, MESH_PLINK_RETRY_INTERVAL_MS, umac_mesh_plink_tick,
                                     umacd, NULL);

    /* BSS_BEACON_CONFIG(enable) — morse_driver sends this on BSS_CHANGED_BEACON_ENABLED,
     * alongside the mesh config. Periodic beaconing itself is started by MESH_CONFIG(START)
     * below; this just enables the BSS beacon path first, matching the driver order. */
    ret = mmdrv_config_beacon_timer(vif_id, true);
    if (ret != 0)
    {
        MMLOG_ERR("MESH: config_beacon_timer failed fw_status=%d\n", ret);
        mesh_ctx.active = false;
        status = MMWLAN_ERROR;
        goto fail;
    }

    /* Host beacon engine on (unmask the beacon IRQ) so the host serves each beacon
     * the firmware's timer requests. */
    ret = mmdrv_start_beaconing(vif_id);
    if (ret != 0)
    {
        MMLOG_ERR("MESH: start_beaconing failed: %d\n", ret);
        mesh_ctx.active = false;
        status = MMWLAN_ERROR;
        goto fail;
    }

    /* MESH_CONFIG(START, enable_beaconing=1): the firmware runs an MBSS TBTT-selection
     * scan (~2 s) then starts generating beacon interrupts, which the armed host beacon
     * engine above serves. mbca_config must be non-zero (handled in mmdrv_cfg_mesh) —
     * zero == beaconless mode, which contradicts enable_beaconing and wedges the chip. */
    ret = mmdrv_cfg_mesh(vif_id, true, true);
    if (ret != 0)
    {
        MMLOG_ERR("MESH: cfg_mesh(enable beaconing) failed fw_status=%d\n", ret);
        mesh_ctx.active = false;
        status = MMWLAN_ERROR;
        goto fail;
    }

    MMLOG_INF("MESH up on chan %u, Mesh ID \"%.*s\" BSSID " MM_MAC_ADDR_FMT "\n",
              args->s1g_chan_num, (int)args->mesh_id_len, (const char *)args->mesh_id,
              MM_MAC_ADDR_VAL(mesh_ctx.mesh_mac));

#if MMWLAN_MESH_SEC_PHASE1
    /* NOTE: hostap installs the own MGTK here at mesh start (__mesh_rsn_auth_init, mesh_rsn.c:266),
     * but Linux peering is AMPE-PROTECTED from the start. With morselib's OPEN MPM, installing a
     * group key before peering flips the firmware to expect protected frames and the unprotected
     * peering Open/Confirm get dropped -> no ESTAB (proven: PHASE1=1 fails to peer, PHASE1=0 peers,
     * same clear channel). So we DEFER the own-MGTK to the first ESTAB (umac_mesh_peer_secure_estab),
     * a forced divergence from Linux that only resolves once AMPE-protected peering lands (P2). */
#endif

    /* P1 is beacon-only: do NOT signal link-up. Bringing the netif up makes lwIP
     * immediately TX (IPv6 RS / mDNS) through the mesh vif, but the mesh DATA path
     * (4-address forwarding) isn't configured yet — that crashes in
     * umac_datapath_tx_frame. The data path + link-up arrive in P4. */

    return MMWLAN_SUCCESS;

fail:
    mesh_ctx.active = false;
    umac_interface_remove(umacd, UMAC_INTERFACE_MESH);
    return status;
}

enum mmwlan_status mmwlan_mesh_stop(void)
{
    if (!mesh_ctx.active)
    {
        return MMWLAN_UNAVAILABLE;
    }

    struct umac_data *umacd = umac_data_get_umacd();
    (void)umac_core_cancel_timeout(umacd, umac_mesh_plink_tick, umacd, NULL);
    (void)mmdrv_cfg_mesh(mesh_ctx.vif_id, false, false); /* MESH_CONFIG(STOP) */
    mesh_ctx.active = false;
    umac_interface_remove(umacd, UMAC_INTERFACE_MESH);
    return MMWLAN_SUCCESS;
}
