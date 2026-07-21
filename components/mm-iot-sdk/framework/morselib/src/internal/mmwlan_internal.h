/*
 * Copyright 2023 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */



#pragma once

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "mmwlan.h"

#ifdef __cplusplus
extern "C"
{
#endif


struct mmpkt;


typedef void (*mmwlan_shutdown_cb_t)(void *arg);


enum mmwlan_status mmwlan_sta_enable_nowait(const struct mmwlan_sta_args *args,
                                            mmwlan_sta_status_cb_t sta_status_cb);


enum mmwlan_status mmwlan_sta_disable_nowait(void);


enum mmwlan_status mmwlan_shutdown_nowait(mmwlan_shutdown_cb_t shutdown_cb, void *cb_arg);


void mmwlan_stop_core_if_no_interface(void);


enum mmwlan_sta_autoconnect_mode
{

    MMWLAN_STA_AUTOCONNECT_ENABLED,

    MMWLAN_STA_AUTOCONNECT_DISABLED,
};


enum mmwlan_status mmwlan_set_sta_autoconnect(enum mmwlan_sta_autoconnect_mode mode);


enum mmwlan_status mmwlan_roam(const uint8_t *bssid);


enum mmwlan_key_type
{
    MMWLAN_KEY_TYPE_PAIRWISE,
    MMWLAN_KEY_TYPE_GROUP,
    MMWLAN_KEY_TYPE_IGTK,
};


#define MMWLAN_MAX_KEYLEN (32)

#define MMWLAN_MAX_KEYS (6)


struct mmwlan_key_info
{

    uint8_t key_id;

    enum mmwlan_key_type key_type;

    uint8_t key_data[MMWLAN_MAX_KEYLEN];

    size_t key_len;
};


enum mmwlan_status mmwlan_ate_get_key_info(struct mmwlan_key_info *key_info,
                                           uint32_t *key_info_count);

#if defined(ENABLE_EXTERNAL_EVENT_LOOP) && ENABLE_EXTERNAL_EVENT_LOOP

enum mmwlan_status mmwlan_dispatch_events(uint32_t *next_event_time);
#endif


enum mmwlan_sleep_state
{

    MMWLAN_SLEEP_STATE_BUSY,

    MMWLAN_SLEEP_STATE_IDLE,
};


typedef void (
    *mmwlan_sleep_cb_t)(enum mmwlan_sleep_state sleep_state, uint32_t next_timeout_ms, void *arg);


enum mmwlan_status mmwlan_register_sleep_cb(mmwlan_sleep_cb_t callback, void *arg);


enum mmwlan_status mmwlan_tx_mgmt_frame(struct mmpkt *txbuf);


enum mmwlan_frame_filter_flag
{
    MMWLAN_FRAME_NO_MATCH = 0,

    MMWLAN_FRAME_ASSOC_REQ = 1 << 0,
    MMWLAN_FRAME_ASSOC_RSP = 1 << 1,
    MMWLAN_FRAME_REASSOC_REQ = 1 << 2,
    MMWLAN_FRAME_REASSOC_RSP = 1 << 3,
    MMWLAN_FRAME_PROBE_REQ = 1 << 4,
    MMWLAN_FRAME_PROBE_RSP = 1 << 5,
    MMWLAN_FRAME_TIMING_ADV = 1 << 6,
    MMWLAN_FRAME_BEACON = 1 << 8,
    MMWLAN_FRAME_ATIM = 1 << 9,
    MMWLAN_FRAME_DISASSOC = 1 << 10,
    MMWLAN_FRAME_AUTH = 1 << 11,
    MMWLAN_FRAME_DEAUTH = 1 << 12,
    MMWLAN_FRAME_ACTION = 1 << 13,
    MMWLAN_FRAME_ACTION_NO_ACK = 1 << 14,
};


struct mmwlan_rx_frame_info
{

    enum mmwlan_frame_filter_flag frame_filter_flag;

    const uint8_t *buf;

    uint32_t buf_len;

    uint16_t freq_100khz;

    int16_t rssi_dbm;

    uint8_t bw_mhz;
};


typedef void (*mmwlan_rx_frame_cb_t)(const struct mmwlan_rx_frame_info *rx_info, void *arg);


enum mmwlan_status mmwlan_register_rx_frame_cb(uint32_t filter,
                                               mmwlan_rx_frame_cb_t callback,
                                               void *arg);

/**
 * Information about a frame delivered to the promiscuous monitor callback.
 */
struct mmwlan_monitor_rx_info
{
    /** Pointer to the raw received 802.11 frame (header onwards). */
    const uint8_t *buf;
    /** Length of @c buf in bytes. */
    uint32_t buf_len;
    /** Frequency at which the frame was received (in 100 kHz). */
    uint16_t freq_100khz;
    /** RSSI of the received frame, in dBm. */
    int16_t rssi_dbm;
    /** Bandwidth in MHz at which the frame was received. */
    uint8_t bw_mhz;
};

/**
 * Promiscuous monitor callback prototype.
 *
 * Invoked for @em every 802.11 frame the firmware delivers to the host, at the datapath
 * RX entry point, @em before any address/BSSID filtering or upper-MAC handling. Unlike
 * @ref mmwlan_rx_frame_cb_t (which fires only for management sub-types matching a filter,
 * and only after the normal datapath has accepted the frame), this surfaces all frames the
 * firmware hands up — including foreign-BSSID beacons that the datapath would otherwise
 * discard. This is what a monitor/sniffer build uses.
 *
 * @warning Advanced use only. Keep work to an absolute minimum, do not modify the buffer,
 * and do not call any mmwlan API from within the callback. The buffer is only valid for the
 * duration of the call.
 */
typedef void (*mmwlan_monitor_rx_cb_t)(const struct mmwlan_monitor_rx_info *info, void *arg);

/**
 * Register (or clear) the promiscuous monitor callback.
 *
 * @param callback Callback to invoke for every received frame, or @c NULL to clear.
 * @param arg      Opaque argument passed through to the callback.
 *
 * @return MMWLAN_SUCCESS.
 */
enum mmwlan_status mmwlan_register_monitor_cb(mmwlan_monitor_rx_cb_t callback, void *arg);

/**
 * Retrieve UMAC statistics in serialized (TLV) form.
 *
 * @param buf   Buffer to serialize into.
 * @param len   Pointer to a size_t that is initialized to the length of the buffer. The value
 *              will be updated by this function to the actual length of data written into
 *              the buffer.
 *
 * @returns @c MMWLAN_SUCCESS on success, @c MMWLAN_NO_MEM if the buffer was too small.
 */
enum mmwlan_status mmwlan_get_serialized_umac_stats(uint8_t *buf, size_t *len);

#ifdef __cplusplus
}
#endif


