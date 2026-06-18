/*
 * Copyright 2023-2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "mmhal_wlan.h"
#include "mmhal_os.h"
#include "mmosal.h"
#include "mmpkt.h"
#include "mmwlan.h"
#include "mmwlan_stats.h"

#include "mmregdb.h"

typedef struct mmhalow_wifi_config_t{
    union {
        struct mmwlan_sta_args sta;
        struct mmwlan_ap_args ap;
    };
} mmhalow_wifi_config_t;

typedef struct mmhalow_netif_driver
{
    esp_netif_driver_base_t base;

    struct mmwlan_sta_args sta_args;
    struct mmwlan_ap_args ap_args;

    bool sta_conf_set;
} mmhalow_netif_driver_t;

struct mmhalow_scan_args
{
    mmwlan_scan_rx_cb_t rx_cb;
    mmwlan_scan_complete_cb_t complete_cb;
    void *cb_arg;
};

/**
 * Initialize the WLAN interface
 * @warning This must be called only once.
 */
esp_err_t mmhalow_init(const wifi_init_config_t *config);

/**
 * Shut down the WLAN interface
 */
esp_err_t mmhalow_deinit();

/**
 * Scans for APs
 */
esp_err_t mmhalow_scan(struct mmhalow_scan_args *args);

/**
 * Connect to an AP
 */
esp_err_t mmhalow_connect(mmwlan_sta_status_cb_t cb);

/**
 * Disconnect from an AP
 */
esp_err_t mmhalow_disconnect();

/**
 * Set the network configuration
 */
esp_err_t mmhalow_set_config(wifi_interface_t interface, mmhalow_wifi_config_t *conf);

/**
 * Get the network configuration
 */
esp_err_t mmhalow_get_config(wifi_interface_t interface, mmhalow_wifi_config_t *conf);

/**
 * Get the STA State
 */
enum mmwlan_status mmhalow_status();

/**
 * Print BCF/Firmware/Morselib version information
 */
void mmhalow_print_version_info(void);

/**
 * Start an AP interface
 */
void mmhalow_wifi_start();
