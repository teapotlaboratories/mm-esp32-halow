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

    /* VIF to stamp on egress frames. morselib's per-VIF datapath (>= 2.11.2) resolves the TX frame's
     * VIF from this tag; a plain AP app still boots an (idle) STA VIF, so an UNSPECIFIED tag is
     * ambiguous and the frame is dropped by mmwlan_tx_pkt ("Unable to infer VIF ID"). Set per active
     * role (the AP path sets MMWLAN_VIF_AP). Defaults to MMWLAN_VIF_UNSPECIFIED (calloc) so the STA
     * and mesh paths keep inferring the VIF exactly as before. */
    enum mmwlan_vif tx_vif;
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

/**
 * Return the esp_netif handle backing the HaLow interface. Useful for callers
 * that need to set static IP, query DHCP, etc. NULL if @ref mmhalow_init has
 * not been called.
 */
esp_netif_t *mmhalow_get_netif(void);

/**
 * Set the VIF that mmhalow's netif stamps on egress frames. Needed when a caller drives mmwlan
 * directly (e.g. a mesh-gate calling @ref mmwlan_mesh_start) rather than via @ref mmhalow_connect /
 * @ref mmhalow_wifi_start: morselib's per-VIF datapath must be told which VIF the netif egresses on,
 * and an UNSPECIFIED tag is ambiguous once more than one VIF is active. For a mesh netif pass
 * @ref MMWLAN_VIF_STA (the mesh occupies the STA host-slot; morselib resolves STA->MESH).
 */
void mmhalow_set_tx_vif(enum mmwlan_vif vif);
