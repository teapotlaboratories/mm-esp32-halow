/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */



#pragma once

#include "mmwlan.h"
#include "mmwlan_internal.h"
#include "mmpkt.h"
#include "mmdrv.h"

#include "umac/ies/s1g_operation.h"


enum mmwlan_status umac_ap_enable_ap(struct umac_data *umacd, const struct mmwlan_ap_args *args);


enum mmwlan_status umac_ap_disable_ap(struct umac_data *umacd);


bool umac_ap_validate_ap_args(struct umac_data *umacd, const struct mmwlan_ap_args *args);

/**
 * Is RAW enabled for this AP?
 *
 * Port of `morse_raw_is_enabled()` (morse_driver raw.c:1630-1632), which requires BOTH that the vif
 * is an AP and that RAW is in the enabled state. Here the AP data pointer being non-NULL carries the
 * first condition -- it is allocated only for an AP vif -- and the configured flag carries the second.
 *
 * This is the predicate that gates the S1G Capabilities RAW Operation Support bit. Linux treats that
 * bit as live state rather than a static capability, and so must this: advertising RAW on an AP with
 * no schedule is exactly the case the design rules out.
 */
bool umac_ap_raw_is_enabled(struct umac_data *umacd);


struct umac_ap_config
{

    uint8_t bssid[MMWLAN_MAC_ADDR_LEN];

    uint8_t ssid[MMWLAN_SSID_MAXLEN];

    size_t ssid_len;

    uint16_t beacon_interval_tus;

    uint8_t dtim_period;


    uint8_t *head;

    size_t head_len;

    uint8_t *tail;

    size_t tail_len;
};


enum mmwlan_status umac_ap_start(struct umac_data *umacd, const struct umac_ap_config *cfg);


/**
 * Restore an AP vif after the chip was torn down and re-inited by a hardware restart.
 *
 * Counterpart to @c umac_connection_handle_hw_restarted() and @c umac_mesh_handle_hw_restarted()
 * for the VIF_AP host-slot: reinstalls the vif, re-pushes the BSS config, re-arms beaconing, then
 * re-adds every associated station and its keys. Self-guards, so it is a no-op on a node with no AP
 * (or with one enabled but not yet started).
 *
 * The channel is NOT restored here -- it is HW-global and the caller restores it once, before any
 * per-slot arm.
 */
void umac_ap_handle_hw_restarted(struct umac_data *umacd);


const struct mmwlan_ap_args *umac_ap_get_args(struct umac_data *umacd);


const struct mmwlan_s1g_channel *umac_ap_get_specified_s1g_channel(struct umac_data *umacd);


enum mmwlan_status umac_ap_get_channel_info(struct umac_data *umacd,
                                            struct mmwlan_vif_channel_info *cfg);


struct mmpkt *umac_ap_get_beacon(struct umac_data *umacd);


void umac_ap_handle_probe_req(struct umac_data *umacd, struct mmpktview *rxbufview);


enum mmwlan_status umac_ap_get_bssid(struct umac_data *umacd, uint8_t *bssid);


const uint8_t *umac_ap_peek_bssid(struct umac_data *umacd);


struct umac_ap_sta_info
{

    uint8_t mac_addr[MMWLAN_MAC_ADDR_LEN];

    enum morse_sta_state sta_state;
};


enum mmwlan_status umac_ap_add_sta(struct umac_data *umacd,
                                   uint16_t aid,
                                   const struct umac_ap_sta_info *sta_info);


enum mmwlan_status umac_ap_update_sta(struct umac_data *umacd,
                                      const struct umac_ap_sta_info *sta_info);


enum mmwlan_status umac_ap_remove_sta(struct umac_data *umacd, const uint8_t *mac_addr);


enum mmwlan_sta_state umac_ap_get_sta_state(struct umac_sta_data *stad);


struct umac_sta_data *umac_ap_lookup_sta_by_addr(struct umac_data *umacd, const uint8_t *sta_addr);


struct umac_sta_data *umac_ap_lookup_sta_by_aid(struct umac_data *umacd, uint16_t aid);


void umac_ap_queue_pkt(struct umac_data *umacd, struct umac_sta_data *stad, struct mmpkt *mmpkt);


bool umac_ap_is_stad_paused(struct umac_sta_data *stad);


bool umac_ap_set_stad_sleep_state(struct umac_sta_data *stad, bool asleep);


enum mmwlan_status umac_ap_get_sta_status(struct umac_data *umacd,
                                          const uint8_t *sta_addr,
                                          struct mmwlan_ap_sta_status *sta_status);


void umac_ap_update_stad_last_active(struct umac_sta_data *stad, uint32_t activity_ms);


uint32_t umac_ap_get_stad_last_active(struct umac_sta_data *stad);


bool umac_ap_tx_dequeue_frame(struct umac_data *umacd,
                              struct umac_sta_data **stad,
                              struct mmpkt **txbuf);

