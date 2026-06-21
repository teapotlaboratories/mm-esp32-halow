/*
 * Copyright 2026 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#pragma once

#include "mmwlan.h"
#include "mmpkt.h"

struct umac_data;

/* ---------------------------------------------------------------------------
 *  Public IBSS API (mmwlan_ibss_*)
 *
 *  IBSS / adhoc mode brings two or more nodes into the same cell with no AP:
 *  one node CREATEs the cell, others JOIN. All nodes share the BSSID/SSID/
 *  channel and exchange data peer-to-peer.
 *
 *  Lifecycle:
 *    mmwlan_init() / mmwlan_boot() (e.g. via mmhalow_init)
 *      -> mmwlan_ibss_start(args, create=true|false)
 *        ... exchange traffic via the registered rx callback / netif ...
 *      -> mmwlan_ibss_stop()
 *
 *  This is mutually exclusive with STA and AP; the start call removes any
 *  active STA/SCAN/AP interface from a prior boot.
 * --------------------------------------------------------------------------- */

/** Arguments to @ref mmwlan_ibss_start. */
struct mmwlan_ibss_args
{
    /** This node's interface MAC address (locally administered). */
    uint8_t if_addr[MMWLAN_MAC_ADDR_LEN];
    /** Shared BSSID for the cell. All nodes in the cell must use the same value.
     *  This is an *agreed/provisioned* BSSID, not a random one: there is no IBSS
     *  TSF merge here. TSF merge (net/mac80211/ibss.c ieee80211_rx_bss_info, higher
     *  TSF wins) only exists to coalesce *uncoordinated* cells that each rolled a
     *  random BSSID; with a pre-shared BSSID there is always exactly one cell, so it
     *  is intentionally omitted (the consuming product, Rimba, is a provisioned
     *  network — decided 2026-06-20). */
    uint8_t bssid[MMWLAN_MAC_ADDR_LEN];
    /** SSID bytes. */
    uint8_t ssid[MMWLAN_SSID_MAXLEN];
    /** SSID length (1..MMWLAN_SSID_MAXLEN). */
    uint8_t ssid_len;
    /** true to CREATE a new cell; false to JOIN an existing one. Caller decides the
     *  role (no auto create-else-join scan, since the BSSID is pre-agreed). */
    bool create;
    /** S1G channel number (e.g. 27 for US 915.5 MHz 1 MHz). Must exist in the
     *  current regulatory domain's channel list. */
    uint8_t s1g_chan_num;
    /** Beacon interval in TU (typically 100). */
    uint16_t beacon_interval_tu;
};

/**
 * Bring up the IBSS interface. Sends ADD_INTERFACE(ADHOC) -> SET_CHANNEL ->
 * BSS_CONFIG -> IBSS_CONFIG(CREATE|JOIN), configures the host-side IBSS
 * datapath + beacon context, and starts host-driven beaconing.
 *
 * @param args  Bring-up parameters. See @ref mmwlan_ibss_args.
 *
 * @returns MMWLAN_SUCCESS on success, or an error code on failure (in which
 *          case any partially-added interface is removed).
 */
enum mmwlan_status mmwlan_ibss_start(const struct mmwlan_ibss_args *args);

/**
 * Tear down the IBSS interface. Sends IBSS_CONFIG(STOP) and removes the vif.
 *
 * @returns MMWLAN_SUCCESS on success, MMWLAN_UNAVAILABLE if IBSS isn't active.
 */
enum mmwlan_status mmwlan_ibss_stop(void);

/** Reasons a peer-event callback fires. */
enum mmwlan_ibss_peer_event
{
    /** A new peer started transmitting in the cell (host saw first frame). */
    MMWLAN_IBSS_PEER_ADDED,
    /** A peer was removed — either evicted to make room or aged out for idle. */
    MMWLAN_IBSS_PEER_REMOVED,
};

/**
 * Peer-event callback signature.
 *
 * @param mac    The peer's 6-byte MAC address.
 * @param event  See @ref mmwlan_ibss_peer_event.
 * @param arg    User-supplied argument from @ref mmwlan_ibss_register_peer_cb.
 *
 * @note Invoked from morselib's RX context — keep the callback short and don't
 *       block. Hand off to a task for any heavy lifting.
 */
typedef void (*mmwlan_ibss_peer_cb_t)(const uint8_t *mac,
                                      enum mmwlan_ibss_peer_event event,
                                      void *arg);

/**
 * Register a peer-event callback. At most one callback can be registered at a
 * time — re-registering replaces the previous one. Pass @c NULL @p cb to clear.
 */
void mmwlan_ibss_register_peer_cb(mmwlan_ibss_peer_cb_t cb, void *arg);

/**
 * Iterate currently-known peers, calling @p cb once per active entry. The
 * callback is invoked with @c MMWLAN_IBSS_PEER_ADDED for each existing peer.
 * Useful for an app to bootstrap its membership list after registering.
 */
void mmwlan_ibss_foreach_peer(mmwlan_ibss_peer_cb_t cb, void *arg);

/**
 * Age out peers that have not been heard from in @p threshold_ms.
 * Intended to be invoked periodically (e.g. every few seconds from a timer
 * task). Fires @c MMWLAN_IBSS_PEER_REMOVED for each evicted entry.
 */
void mmwlan_ibss_age_peers(uint32_t threshold_ms);

/**
 * Per-frame RX callback signature for per-peer link quality.
 *
 * @param mac       The transmitter's 6-byte MAC address.
 * @param rssi_dbm  RSSI of the received frame in dBm (signed, typically
 *                  in the range -100 to -10).
 * @param arg       User-supplied argument from
 *                  @ref mmwlan_ibss_register_peer_rx_cb.
 *
 * @note Fired from morselib's RX context, once per received data frame
 *       that's attributable to a peer. High-rate path — keep the
 *       handler trivial (e.g. push to a queue and return). Do an EMA
 *       or jitter smoothing on a separate task.
 */
typedef void (*mmwlan_ibss_peer_rx_cb_t)(const uint8_t *mac,
                                         int16_t rssi_dbm,
                                         void *arg);

/**
 * Register a per-frame RX callback that fires for every IBSS data
 * frame received, with the sender's MAC and the frame's RSSI. At most
 * one callback may be registered; re-registering replaces the previous
 * one. Pass @c NULL @p cb to clear.
 */
void mmwlan_ibss_register_peer_rx_cb(mmwlan_ibss_peer_rx_cb_t cb, void *arg);

/**
 * Get the last-sampled RSSI (in dBm) for a known peer. Returns
 * @c INT16_MIN if @p mac doesn't match any active peer or no frame has
 * been received yet. Single-sample (no smoothing); callers should
 * smooth on their own task if needed.
 */
int16_t mmwlan_ibss_get_peer_rssi(const uint8_t *mac);

/* ---------------------------------------------------------------------------
 *  Internal helpers (called from the driver and umac_datapath)
 * --------------------------------------------------------------------------- */

/**
 * Internal: record the RSSI of a received frame for the given peer and
 * fire the registered @ref mmwlan_ibss_peer_rx_cb. Called from the RX
 * datapath; not for application use.
 */
void umac_ibss_record_peer_rx(const uint8_t *mac, int16_t rssi_dbm);

/**
 * Configure the IBSS beacon context. Internal helper called by
 * @ref umac_ibss_start.
 */
void umac_ibss_configure(uint16_t vif_id,
                         const uint8_t *bssid,
                         const uint8_t *src_mac,
                         const uint8_t *ssid,
                         uint8_t ssid_len,
                         uint16_t beacon_interval_tu,
                         uint8_t s1g_op_chan_width,
                         uint8_t s1g_operating_class,
                         uint8_t s1g_primary_chan,
                         uint8_t s1g_centre_chan);

/**
 * Bring up host-side IBSS state: store the beacon context, allocate the common
 * stad, and configure the IBSS datapath. Called from @ref mmwlan_ibss_start
 * after the firmware-side commands have succeeded.
 */
void umac_ibss_start(uint16_t vif_id,
                     const uint8_t *bssid,
                     const uint8_t *src_mac,
                     const uint8_t *ssid,
                     uint8_t ssid_len,
                     uint16_t beacon_interval_tu,
                     uint8_t s1g_op_chan_width,
                     uint8_t s1g_operating_class,
                     uint8_t s1g_primary_chan,
                     uint8_t s1g_centre_chan);

/** Enable/disable IBSS beacon generation. */
void umac_ibss_set_active(bool active);

/** @returns true if IBSS beaconing is active (used by @ref mmdrv_host_get_beacon). */
bool umac_ibss_is_active(void);

/** @returns the IBSS common stad (used by the IBSS datapath peer lookup). */
struct umac_sta_data *umac_ibss_get_common_stad(void);

/**
 * Look up or allocate a per-peer stad keyed on @p mac. Broadcast/multicast
 * addresses map to the common stad. The peer table holds the receive-side
 * sequence number / dedup state per sender, which is what lets the cell scale
 * past two nodes without ghost duplicates from sequence-space aliasing. LRU
 * eviction when the table is full.
 */
struct umac_sta_data *umac_ibss_get_or_create_peer_stad(const uint8_t *mac);

/** Build and transmit an IBSS probe response in reply to a received probe req. */
void umac_ibss_handle_probe_req(struct umac_data *umacd, struct mmpktview *rxbufview);

/** Build an IBSS beacon mmpkt for transmission. Mirrors @ref umac_ap_get_beacon. */
struct mmpkt *umac_ibss_get_beacon(struct umac_data *umacd);
