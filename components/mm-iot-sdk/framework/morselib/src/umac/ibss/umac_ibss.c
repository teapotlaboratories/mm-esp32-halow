/*
 * Copyright 2026 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include <string.h>

#include "common/common.h"
#include "common/morse_commands.h"
#include "mmlog.h"

#include "umac_ibss.h"
#include "mmdrv.h"
#include "dot11/dot11.h"
#include "dot11/dot11_utils.h"
#include "common/mac_address.h"
#include "common/consbuf.h"
#include "umac/data/umac_data.h"
#include "umac/datapath/umac_datapath.h"
#include "umac/frames/frames_common.h"
#include "umac/ies/ssid.h"
#include "umac/ies/s1g_capabilities.h"
#include "umac/rc/umac_rc.h"
#include "umac/regdb/umac_regdb.h"
#include "umac/interface/umac_interface.h"
#include "umac/interface/umac_interface_data.h"
#include "umac/connection/umac_connection.h"

/** Capability Information bit for IBSS (bit 1). */
#define IBSS_CAPABILITY_INFO (0x0002u)

/** Max simultaneously-tracked unicast peers. LRU eviction when full. */
#define UMAC_IBSS_MAX_PEERS (8)

/** Marker for "no RSSI sample yet" (returned by mmwlan_ibss_get_peer_rssi
 *  when the peer exists but no frame has been seen — vanishingly rare in
 *  practice since the peer is created at first-frame time — and when the
 *  mac doesn't match any active peer). */
#define UMAC_IBSS_RSSI_NONE (INT16_MIN)

struct umac_ibss_peer
{
    bool in_use;
    uint8_t mac[6];
    struct umac_sta_data *stad;
    uint32_t last_rx_ms;     /* mmosal time; used as LRU key on eviction. */
    int16_t last_rssi_dbm;   /* RSSI of most recent frame from this peer
                              * (signed dBm, e.g. -65). UMAC_IBSS_RSSI_NONE
                              * before the first sample. */
};

struct umac_ibss_context
{
    bool active;
    uint8_t bssid[6];
    uint8_t src_mac[6];
    uint8_t ssid[MMWLAN_SSID_MAXLEN];
    uint8_t ssid_len;
    uint16_t beacon_interval_tu;
    uint8_t s1g_op_chan_width;
    uint8_t s1g_operating_class;
    uint8_t s1g_primary_chan;
    uint8_t s1g_centre_chan;
    uint16_t vif_id;
    struct umac_sta_data *common_stad;
    struct umac_ibss_peer peers[UMAC_IBSS_MAX_PEERS];
};

/* Single interface is supported, so a file-static context is sufficient. */
static struct umac_ibss_context ibss_ctx;

/* Protects ibss_ctx.peers[]. The table is touched both from the rx context
 * (peer add via umac_ibss_get_or_create_peer_stad) and from user-supplied
 * tasks (age-out, foreach, stop). Created lazily on first use. */
static struct mmosal_mutex *ibss_peers_lock;

static void ibss_peers_lock_init_(void)
{
    if (ibss_peers_lock == NULL)
    {
        ibss_peers_lock = mmosal_mutex_create("ibss_peers");
    }
}
#define IBSS_PEERS_LOCK()   MMOSAL_MUTEX_GET_INF(ibss_peers_lock)
#define IBSS_PEERS_UNLOCK() ((void)mmosal_mutex_release(ibss_peers_lock))

static mmwlan_ibss_peer_cb_t ibss_peer_cb;
static void *ibss_peer_cb_arg;

static mmwlan_ibss_peer_rx_cb_t ibss_peer_rx_cb;
static void *ibss_peer_rx_cb_arg;

/* Forward decl: defined further down where the peer-table machinery lives. */
static struct umac_ibss_peer *umac_ibss_find_peer_locked_(const uint8_t *mac);

static void umac_ibss_invoke_peer_cb_(const uint8_t *mac, enum mmwlan_ibss_peer_event event)
{
    if (ibss_peer_cb != NULL)
    {
        ibss_peer_cb(mac, event, ibss_peer_cb_arg);
    }
}

void mmwlan_ibss_register_peer_cb(mmwlan_ibss_peer_cb_t cb, void *arg)
{
    ibss_peer_cb = cb;
    ibss_peer_cb_arg = arg;
}

void mmwlan_ibss_register_peer_rx_cb(mmwlan_ibss_peer_rx_cb_t cb, void *arg)
{
    ibss_peer_rx_cb = cb;
    ibss_peer_rx_cb_arg = arg;
}

void umac_ibss_record_peer_rx(const uint8_t *mac, int16_t rssi_dbm)
{
    if (mac == NULL || ibss_peers_lock == NULL)
    {
        return;
    }
    /* Multicast TAs shouldn't appear in 802.11, but defend against them. */
    if (mm_mac_addr_is_multicast(mac) || mm_mac_addr_is_zero(mac))
    {
        return;
    }

    IBSS_PEERS_LOCK();
    struct umac_ibss_peer *p = umac_ibss_find_peer_locked_(mac);
    if (p != NULL)
    {
        p->last_rssi_dbm = rssi_dbm;
    }
    IBSS_PEERS_UNLOCK();

    /* Push callback fires outside the lock so handlers can re-enter the
     * IBSS API. Fire even if the peer entry doesn't exist yet — at that
     * moment the rx path is about to allocate one, and a caller that
     * needs the by-mac state can look it up after the cb returns. */
    if (ibss_peer_rx_cb != NULL)
    {
        ibss_peer_rx_cb(mac, rssi_dbm, ibss_peer_rx_cb_arg);
    }
}

int16_t mmwlan_ibss_get_peer_rssi(const uint8_t *mac)
{
    if (mac == NULL || ibss_peers_lock == NULL)
    {
        return UMAC_IBSS_RSSI_NONE;
    }
    IBSS_PEERS_LOCK();
    struct umac_ibss_peer *p = umac_ibss_find_peer_locked_(mac);
    int16_t rssi = (p != NULL) ? p->last_rssi_dbm : (int16_t)UMAC_IBSS_RSSI_NONE;
    IBSS_PEERS_UNLOCK();
    return rssi;
}

void mmwlan_ibss_foreach_peer(mmwlan_ibss_peer_cb_t cb, void *arg)
{
    if (cb == NULL || ibss_peers_lock == NULL)
    {
        return;
    }
    uint8_t snapshot[UMAC_IBSS_MAX_PEERS][6];
    size_t n = 0;
    IBSS_PEERS_LOCK();
    for (size_t i = 0; i < UMAC_IBSS_MAX_PEERS; i++)
    {
        if (ibss_ctx.peers[i].in_use)
        {
            memcpy(snapshot[n++], ibss_ctx.peers[i].mac, 6);
        }
    }
    IBSS_PEERS_UNLOCK();
    for (size_t i = 0; i < n; i++)
    {
        cb(snapshot[i], MMWLAN_IBSS_PEER_ADDED, arg);
    }
}

void mmwlan_ibss_age_peers(uint32_t threshold_ms)
{
    if (ibss_peers_lock == NULL)
    {
        return;
    }
    uint8_t removed[UMAC_IBSS_MAX_PEERS][6];
    size_t n_removed = 0;
    uint32_t now = mmosal_get_time_ms();

    IBSS_PEERS_LOCK();
    for (size_t i = 0; i < UMAC_IBSS_MAX_PEERS; i++)
    {
        struct umac_ibss_peer *p = &ibss_ctx.peers[i];
        if (!p->in_use)
        {
            continue;
        }
        if ((now - p->last_rx_ms) >= threshold_ms)
        {
            memcpy(removed[n_removed++], p->mac, 6);
            mmosal_free(p->stad);
            memset(p, 0, sizeof(*p));
        }
    }
    IBSS_PEERS_UNLOCK();

    for (size_t i = 0; i < n_removed; i++)
    {
        MMLOG_INF("IBSS aging out peer " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(removed[i]));
        umac_ibss_invoke_peer_cb_(removed[i], MMWLAN_IBSS_PEER_REMOVED);
    }
}

/* Look up a peer entry by MAC; returns NULL if not present. Does not allocate.
 * Caller must hold the peer-table mutex. */
static struct umac_ibss_peer *umac_ibss_find_peer_locked_(const uint8_t *mac)
{
    for (size_t i = 0; i < UMAC_IBSS_MAX_PEERS; i++)
    {
        struct umac_ibss_peer *p = &ibss_ctx.peers[i];
        if (p->in_use && mm_mac_addr_is_equal(p->mac, mac))
        {
            return p;
        }
    }
    return NULL;
}

/* Return existing or newly-allocated peer stad for the given MAC. Bumps the
 * peer's last_rx_ms on hit. NULL only if alloc fails. */
struct umac_sta_data *umac_ibss_get_or_create_peer_stad(const uint8_t *mac)
{
    if (mm_mac_addr_is_zero(mac) || mm_mac_addr_is_multicast(mac))
    {
        return ibss_ctx.common_stad;
    }

    IBSS_PEERS_LOCK();

    struct umac_ibss_peer *p = umac_ibss_find_peer_locked_(mac);
    if (p != NULL)
    {
        p->last_rx_ms = mmosal_get_time_ms();
        struct umac_sta_data *stad = p->stad;
        IBSS_PEERS_UNLOCK();
        return stad;
    }

    /* Find a free slot, or evict the least-recently-used. */
    struct umac_ibss_peer *victim = &ibss_ctx.peers[0];
    for (size_t i = 0; i < UMAC_IBSS_MAX_PEERS; i++)
    {
        struct umac_ibss_peer *q = &ibss_ctx.peers[i];
        if (!q->in_use)
        {
            victim = q;
            break;
        }
        if (q->last_rx_ms < victim->last_rx_ms)
        {
            victim = q;
        }
    }

    uint8_t evicted_mac[6];
    bool fire_evicted_cb = false;
    if (victim->in_use)
    {
        MMLOG_INF("IBSS evicting peer " MM_MAC_ADDR_FMT " for " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(victim->mac), MM_MAC_ADDR_VAL(mac));
        memcpy(evicted_mac, victim->mac, sizeof(evicted_mac));
        mmosal_free(victim->stad);
        memset(victim, 0, sizeof(*victim));
        fire_evicted_cb = true;
    }

    victim->stad = umac_sta_data_alloc(umac_data_get_umacd());
    if (victim->stad == NULL)
    {
        MMLOG_ERR("IBSS peer stad alloc failed for " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(mac));
        memset(victim, 0, sizeof(*victim));
        IBSS_PEERS_UNLOCK();
        if (fire_evicted_cb)
        {
            umac_ibss_invoke_peer_cb_(evicted_mac, MMWLAN_IBSS_PEER_REMOVED);
        }
        return ibss_ctx.common_stad; /* graceful fallback */
    }

    victim->in_use = true;
    memcpy(victim->mac, mac, sizeof(victim->mac));
    victim->last_rx_ms = mmosal_get_time_ms();
    victim->last_rssi_dbm = UMAC_IBSS_RSSI_NONE;
    umac_sta_data_set_bssid(victim->stad, ibss_ctx.bssid);
    umac_sta_data_set_peer_addr(victim->stad, mac);
    struct umac_sta_data *stad = victim->stad;
    uint8_t added_mac[6];
    memcpy(added_mac, victim->mac, sizeof(added_mac));

    IBSS_PEERS_UNLOCK();

    /* Callbacks fire outside the lock — they're user code and may call back
     * into our API (e.g. mmwlan_ibss_foreach_peer). */
    if (fire_evicted_cb)
    {
        umac_ibss_invoke_peer_cb_(evicted_mac, MMWLAN_IBSS_PEER_REMOVED);
    }
    MMLOG_INF("IBSS new peer " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(added_mac));
    umac_ibss_invoke_peer_cb_(added_mac, MMWLAN_IBSS_PEER_ADDED);
    return stad;
}

/* Tear down the peer table — called on mmwlan_ibss_stop. Fires the
 * peer_removed callback for each active entry so the app's membership view
 * is consistent. Callbacks fire outside the lock. */
static void umac_ibss_clear_peers_(void)
{
    if (ibss_peers_lock == NULL)
    {
        return;
    }
    uint8_t removed[UMAC_IBSS_MAX_PEERS][6];
    size_t n_removed = 0;

    IBSS_PEERS_LOCK();
    for (size_t i = 0; i < UMAC_IBSS_MAX_PEERS; i++)
    {
        struct umac_ibss_peer *p = &ibss_ctx.peers[i];
        if (!p->in_use)
        {
            continue;
        }
        memcpy(removed[n_removed++], p->mac, 6);
        if (p->stad != NULL && p->stad != ibss_ctx.common_stad)
        {
            mmosal_free(p->stad);
        }
        memset(p, 0, sizeof(*p));
    }
    IBSS_PEERS_UNLOCK();

    for (size_t i = 0; i < n_removed; i++)
    {
        umac_ibss_invoke_peer_cb_(removed[i], MMWLAN_IBSS_PEER_REMOVED);
    }
}

/* Parameters selecting which kind of frame the shared body builder produces. */
struct ibss_frame_params
{
    uint16_t subtype;        /* DOT11_FC_SUBTYPE_BEACON or _PROBE_RSP */
    const uint8_t *dst_addr; /* addr1: broadcast for beacons, requester for probe rsp */
};

void umac_ibss_configure(uint16_t vif_id,
                         const uint8_t *bssid,
                         const uint8_t *src_mac,
                         const uint8_t *ssid,
                         uint8_t ssid_len,
                         uint16_t beacon_interval_tu,
                         uint8_t s1g_op_chan_width,
                         uint8_t s1g_operating_class,
                         uint8_t s1g_primary_chan,
                         uint8_t s1g_centre_chan)
{
    struct umac_sta_data *preserved_stad = ibss_ctx.common_stad;
    memset(&ibss_ctx, 0, sizeof(ibss_ctx));
    ibss_ctx.common_stad = preserved_stad;
    ibss_ctx.vif_id = vif_id;
    memcpy(ibss_ctx.bssid, bssid, sizeof(ibss_ctx.bssid));
    memcpy(ibss_ctx.src_mac, src_mac, sizeof(ibss_ctx.src_mac));
    if (ssid_len > sizeof(ibss_ctx.ssid))
    {
        ssid_len = sizeof(ibss_ctx.ssid);
    }
    memcpy(ibss_ctx.ssid, ssid, ssid_len);
    ibss_ctx.ssid_len = ssid_len;
    ibss_ctx.beacon_interval_tu = beacon_interval_tu;
    ibss_ctx.s1g_op_chan_width = s1g_op_chan_width;
    ibss_ctx.s1g_operating_class = s1g_operating_class;
    ibss_ctx.s1g_primary_chan = s1g_primary_chan;
    ibss_ctx.s1g_centre_chan = s1g_centre_chan;
}

void umac_ibss_start(uint16_t vif_id,
                     const uint8_t *bssid,
                     const uint8_t *src_mac,
                     const uint8_t *ssid,
                     uint8_t ssid_len,
                     uint16_t beacon_interval_tu,
                     uint8_t s1g_op_chan_width,
                     uint8_t s1g_operating_class,
                     uint8_t s1g_primary_chan,
                     uint8_t s1g_centre_chan)
{
    struct umac_data *umacd = umac_data_get_umacd();

    umac_ibss_configure(vif_id, bssid, src_mac, ssid, ssid_len, beacon_interval_tu,
                        s1g_op_chan_width, s1g_operating_class, s1g_primary_chan, s1g_centre_chan);

    /* The "common" stad represents the cell itself: used for broadcast/multicast
     * TX, our beacons/probe responses, and as the lookup fallback. Per-peer
     * stads (allocated on first RX from a new sender) carry the receive-side
     * sequence-number / dedup state that matters once the cell has >2 nodes. */
    ibss_ctx.common_stad = umac_sta_data_alloc_static(umacd);
    if (ibss_ctx.common_stad != NULL)
    {
        umac_sta_data_set_bssid(ibss_ctx.common_stad, bssid);
        umac_sta_data_set_peer_addr(ibss_ctx.common_stad, bssid);
    }

    /* In case of a restart, wipe the peer table. */
    umac_ibss_clear_peers_();

    umac_datapath_configure_ibss_mode(umacd);
    ibss_ctx.active = true;
}

void umac_ibss_set_active(bool active)
{
    ibss_ctx.active = active;
}

bool umac_ibss_is_active(void)
{
    return ibss_ctx.active;
}

struct umac_sta_data *umac_ibss_get_common_stad(void)
{
    return ibss_ctx.common_stad;
}

/* Shared builder for IBSS beacons and probe responses (identical body, differing
 * only in frame subtype and addr1). */
static void umac_ibss_build_frame(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    const struct ibss_frame_params *fp = (const struct ibss_frame_params *)params;

    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr)
    {
        dot11_build_pv0_mgmt_header(hdr,
                                    fp->subtype,
                                    0,
                                    fp->dst_addr,
                                    ibss_ctx.src_mac,
                                    ibss_ctx.bssid);
    }

    const uint8_t zero_timestamp[8] = { 0 };
    consbuf_append(buf, zero_timestamp, sizeof(zero_timestamp));

    uint16_t beacon_interval = htole16(ibss_ctx.beacon_interval_tu);
    consbuf_append(buf, (const uint8_t *)&beacon_interval, sizeof(beacon_interval));

    uint16_t capability_info = htole16(IBSS_CAPABILITY_INFO);
    consbuf_append(buf, (const uint8_t *)&capability_info, sizeof(capability_info));

    /* IEs required by frame_probe_response_parse: SSID, S1G capabilities,
     * S1G operation. (No TIM — that is AP-only.) */
    ie_ssid_build(buf, ibss_ctx.ssid, ibss_ctx.ssid_len);
    ie_s1g_capabilities_build(umacd, buf);

    struct dot11_ie_s1g_operation *op =
        (struct dot11_ie_s1g_operation *)consbuf_reserve(buf, sizeof(*op));
    if (op)
    {
        memset(op, 0, sizeof(*op));
        op->header.element_id = DOT11_IE_S1G_OPERATION;
        op->header.length = sizeof(*op) - sizeof(op->header);
        op->channel_width = ibss_ctx.s1g_op_chan_width;
        op->operating_class = ibss_ctx.s1g_operating_class;
        op->primary_channel_number = ibss_ctx.s1g_primary_chan;
        op->channel_center_freq = ibss_ctx.s1g_centre_chan;
    }
}

struct mmpkt *umac_ibss_get_beacon(struct umac_data *umacd)
{
    struct ibss_frame_params fp = {
        .subtype = DOT11_FC_SUBTYPE_BEACON,
        .dst_addr = mac_addr_broadcast,
    };
    struct mmpkt *beacon = build_mgmt_frame(umacd, umac_ibss_build_frame, &fp);
    if (beacon == NULL)
    {
        MMLOG_WRN("Failed to generate IBSS beacon\n");
        return NULL;
    }

    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(beacon);
    tx_metadata->flags = MMDRV_TX_FLAG_IMMEDIATE_REPORT;
    tx_metadata->tid = MMWLAN_MAX_QOS_TID;
    tx_metadata->vif_id = ibss_ctx.vif_id;
    umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);

    return beacon;
}

void umac_ibss_handle_probe_req(struct umac_data *umacd, struct mmpktview *rxbufview)
{
    const struct dot11_hdr *probe_req_header =
        (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);

    struct ibss_frame_params fp = {
        .subtype = DOT11_FC_SUBTYPE_PROBE_RSP,
        .dst_addr = dot11_get_sa(probe_req_header),
    };

    struct mmpkt *probe_rsp = build_mgmt_frame(umacd, umac_ibss_build_frame, &fp);
    if (probe_rsp == NULL)
    {
        MMLOG_WRN("Failed to construct IBSS probe rsp\n");
        return;
    }

    struct mmdrv_rx_metadata *rx_metadata = mmpkt_get_metadata(mmpkt_from_view(rxbufview)).rx;
    MMOSAL_ASSERT(rx_metadata != NULL);

    struct mmrc_rate mmrc_rate_override = {
        .attempts = 5,
        .rate = MMRC_MCS0,
        .bw = (rx_metadata->bw_mhz == 1) ? MMRC_BW_1MHZ : MMRC_BW_2MHZ,
        .guard = MMRC_GUARD_LONG,
        .ss = MMRC_SPATIAL_STREAM_1,
        .flags = 0,
    };

    enum mmwlan_status status =
        umac_datapath_tx_mgmt_frame_ap(umacd, probe_rsp, &mmrc_rate_override);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_WRN("Failed to send IBSS probe rsp\n");
    }
}

/* Tear down whatever interface is currently up so the ADHOC iface can be added
 * cleanly. mmhalow_init brings up a boot-time STA; we walk every active bit
 * and remove it. Each remove call is a no-op if the bit isn't set. */
static void umac_ibss_tear_down_active_interfaces(struct umac_data *umacd)
{
    struct umac_interface_data *iface = umac_data_get_interface(umacd);
    const enum umac_interface_type maybe_active[] = {
        UMAC_INTERFACE_STA,
        UMAC_INTERFACE_SCAN,
        UMAC_INTERFACE_AP,
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

enum mmwlan_status mmwlan_ibss_start(const struct mmwlan_ibss_args *args)
{
    if (args == NULL || args->ssid_len == 0 || args->ssid_len > sizeof(args->ssid))
    {
        return MMWLAN_INVALID_ARGUMENT;
    }

    struct umac_data *umacd = umac_data_get_umacd();

    /* Lazy-init the peer-table lock on first start; safe to call repeatedly. */
    ibss_peers_lock_init_();

    /* Boot-time STA (or anything else) must go away — UMAC_INTERFACE_ADHOC is
     * mutually exclusive with the other interface types. */
    umac_ibss_tear_down_active_interfaces(umacd);

    /* Caller may leave if_addr all-zero to inherit the chip's factory MAC
     * (keeps mmhalow's netif MAC in sync, avoids ARP table mismatches). */
    const uint8_t *iface_mac = args->if_addr;
    if (mm_mac_addr_is_zero(iface_mac))
    {
        iface_mac = NULL;
    }

    uint16_t vif_id = UMAC_INTERFACE_VIF_ID_INVALID;
    enum mmwlan_status status =
        umac_interface_add(umacd, UMAC_INTERFACE_ADHOC, iface_mac, &vif_id);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_ERR("IBSS interface add failed: %d\n", (int)status);
        return status;
    }

    const struct mmwlan_s1g_channel *chan = umac_regdb_get_channel(umacd, args->s1g_chan_num);
    if (chan == NULL)
    {
        MMLOG_ERR("IBSS: unknown S1G channel %u\n", args->s1g_chan_num);
        status = MMWLAN_CHANNEL_INVALID;
        goto fail;
    }

    status = umac_interface_set_channel_from_regdb(umacd, chan, false);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_ERR("IBSS: set_channel failed: %d\n", (int)status);
        goto fail;
    }

    int ret = mmdrv_cfg_bss(vif_id, args->beacon_interval_tu, 1, 0);
    if (ret != 0)
    {
        MMLOG_ERR("IBSS: cfg_bss failed fw_status=%d\n", ret);
        status = MMWLAN_ERROR;
        goto fail;
    }

    enum morse_cmd_ibss_config_opcode opcode = args->create ?
                                                   MORSE_CMD_IBSS_CONFIG_OPCODE_CREATE :
                                                   MORSE_CMD_IBSS_CONFIG_OPCODE_JOIN;
    ret = mmdrv_cfg_ibss(vif_id, args->bssid, opcode, false);
    if (ret != 0)
    {
        MMLOG_ERR("IBSS: cfg_ibss(%s) failed fw_status=%d\n",
                  args->create ? "CREATE" : "JOIN", ret);
        status = MMWLAN_ERROR;
        goto fail;
    }

    /* Build host-side IBSS state: common stad + IBSS datapath ops + beacon
     * context. mmdrv_host_get_beacon() routes ADHOC vifs here via
     * umac_ibss_is_active(). 1 MHz primary+operating (channel_width=0x01); the
     * S1G centre/primary channel number both equal s1g_chan_num for a 1 MHz
     * channel. */
    umac_ibss_start(vif_id, args->bssid, args->if_addr, args->ssid, args->ssid_len,
                    args->beacon_interval_tu, 0x01, (uint8_t)chan->global_operating_class,
                    args->s1g_chan_num, args->s1g_chan_num);

    ret = mmdrv_start_beaconing(vif_id);
    if (ret != 0)
    {
        MMLOG_ERR("IBSS: start_beaconing failed: %d\n", ret);
        status = MMWLAN_ERROR;
        goto fail;
    }

    MMLOG_INF("IBSS %s on chan %u BSSID " MM_MAC_ADDR_FMT " SSID \"%.*s\"\n",
              args->create ? "CREATE" : "JOIN", args->s1g_chan_num,
              MM_MAC_ADDR_VAL(args->bssid), (int)args->ssid_len, (const char *)args->ssid);

    /* Signal link-up so mmhalow's netif (registered via mmwlan_register_link
     * _state_cb) transitions to "connected" and lwIP can use sockets. We
     * piggyback the AP per-vif slot for the per-vif state cb. */
    umac_connection_signal_link_state(umacd, MMWLAN_VIF_AP, MMWLAN_LINK_UP);

    return MMWLAN_SUCCESS;

fail:
    umac_ibss_set_active(false);
    umac_interface_remove(umacd, UMAC_INTERFACE_ADHOC);
    return status;
}

enum mmwlan_status mmwlan_ibss_stop(void)
{
    struct umac_data *umacd = umac_data_get_umacd();
    struct umac_interface_data *iface = umac_data_get_interface(umacd);

    if (!(iface->active_interface_types & UMAC_INTERFACE_ADHOC))
    {
        return MMWLAN_UNAVAILABLE;
    }

    uint16_t vif_id = iface->vif_id;
    /* Stop our local beacon generation first so we stop touching the vif. */
    umac_ibss_set_active(false);
    umac_connection_signal_link_state(umacd, MMWLAN_VIF_AP, MMWLAN_LINK_DOWN);
    umac_ibss_clear_peers_();

    /* Tell the firmware to leave the IBSS. STOP releases firmware-side state
     * for the cell; the ADD/REMOVE bracket below tears the vif itself down. */
    (void)mmdrv_cfg_ibss(vif_id, (const uint8_t[6]){ 0 },
                         MORSE_CMD_IBSS_CONFIG_OPCODE_STOP, false);

    umac_interface_remove(umacd, UMAC_INTERFACE_ADHOC);
    return MMWLAN_SUCCESS;
}
