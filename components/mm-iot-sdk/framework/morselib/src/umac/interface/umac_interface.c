/*
 * Copyright 2022 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "common/mac_address.h"
#include "mmlog.h"
#include "common/morse_commands.h"
#include "common/morse_command_utils.h"
#include "dot11/dot11_utils.h"

#include "mmdrv.h"
#include "umac_interface.h"
#include "umac_interface_data.h"
#include "umac/ps/umac_ps.h"
#include "umac/config/umac_config.h"
#include "umac/rc/umac_rc.h"
#include "umac/regdb/umac_regdb.h"
#include "umac/twt/umac_twt.h"
#include "umac/core/umac_core.h"
#include "umac/supplicant_shim/umac_supp_shim.h"
#include "mmhal_wlan.h"


#define MM_TX_STATUS_BUFFER_FLUSH_WATERMARK (10)


#define DEFAULT_MORSE_IBSS_ACK_TIMEOUT_ADJUST_US (1000)

static inline const char *umac_interface_type_to_str(enum umac_interface_type type)
{
    switch (type)
    {
        case UMAC_INTERFACE_NONE:
            return "None";

        case UMAC_INTERFACE_SCAN:
            return "Scan";

        case UMAC_INTERFACE_STA:
            return "STA";

        case UMAC_INTERFACE_AP:
            return "AP";

        case UMAC_INTERFACE_ADHOC:
            return "IBSS";

        default:
            return "??";
    }
}

void umac_interface_init(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    /* 0 is a valid FW-assigned vif_id, so a zero-initialised struct would read
     * as "AP secondary vif 0". Mark "no concurrent AP vif" explicitly. */
    data->ap_vif_id = UMAC_INTERFACE_VIF_ID_INVALID;
}

static void umac_interface_populate_device_mac_addr(struct umac_interface_data *data,
                                                    struct mmdrv_chip_info *chip_info)
{
    MMOSAL_DEV_ASSERT(mm_mac_addr_is_zero(data->mac_addr));

    if (!mm_mac_addr_is_zero(chip_info->mac_addr))
    {
        mac_addr_copy(data->mac_addr, chip_info->mac_addr);
        MMLOG_INF("Using MAC addr from %s\n", "chip");
    }


    mmhal_read_mac_addr(data->mac_addr);
    if (!mm_mac_addr_is_zero(data->mac_addr))
    {
        MMLOG_INF("Using MAC addr from %s\n", "HAL/prev");
        return;
    }

    MMLOG_INF("Using MAC addr from %s\n", "rng");
    data->mac_addr[0] = 0x02;
    data->mac_addr[1] = 0x01;
    uint32_t rnd = mmhal_random_u32(0, UINT32_MAX);
    data->mac_addr[2] = rnd >> 24;
    data->mac_addr[3] = rnd >> 16;
    data->mac_addr[4] = rnd >> 8;
    data->mac_addr[5] = rnd >> 0;
}

void umac_interface_configure_periodic_health_check(struct umac_data *umacd)
{
    uint32_t min_health_check_intvl_ms, max_health_check_intvl_ms;
    umac_config_get_health_check_interval(umacd,
                                          &min_health_check_intvl_ms,
                                          &max_health_check_intvl_ms);
    mmdrv_set_health_check_interval(min_health_check_intvl_ms, max_health_check_intvl_ms);
}


static void umac_interface_configure_control_response_out_1mhz(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    bool enabled = umac_config_is_ctrl_resp_out_1mhz_enabled(umacd) &&
                   MORSE_CAP_SUPPORTED(&data->capabilities, 1MHZ_CONTROL_RESPONSE_PREAMBLE);
    mmdrv_set_control_response_bw(data->vif_id, MMDRV_DIRECTION_OUTGOING, enabled);
}

bool umac_interface_get_control_response_bw_1mhz_out_enabled(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    return umac_config_is_ctrl_resp_out_1mhz_enabled(umacd) &&
           MORSE_CAP_SUPPORTED(&data->capabilities, 1MHZ_CONTROL_RESPONSE_PREAMBLE);
}


#define VIF_STA_INTERFACE_TYPES_MASK (UMAC_INTERFACE_SCAN | UMAC_INTERFACE_STA)

static void umac_interface_init_vif(struct umac_data *umacd,
                                    enum umac_interface_type type,
                                    uint16_t vif_id)
{

    umac_ps_update_mode(umacd);


    mmdrv_set_param(vif_id,
                    MORSE_PARAM_ID_TX_STATUS_FLUSH_WATERMARK,
                    MM_TX_STATUS_BUFFER_FLUSH_WATERMARK);

    umac_interface_configure_periodic_health_check(umacd);
    mmdrv_set_dynamic_ps_timeout(umac_config_get_dynamic_ps_timeout(umacd));

    if (type & UMAC_INTERFACE_SCAN)
    {
        mmdrv_set_ndp_probe(vif_id, umac_config_is_ndp_probe_supported(umacd));
    }
    if (type & UMAC_INTERFACE_STA)
    {
        mmdrv_set_listen_interval_sleep(vif_id, umac_config_get_listen_interval(umacd));
        umac_twt_init_vif(umacd, &vif_id, false);   /* STA = TWT requester */
        umac_interface_configure_control_response_out_1mhz(umacd);
    }
    if (type & UMAC_INTERFACE_AP)
    {
        /* AP = TWT responder. Mirror morse_driver morse_twt_init_vif: enable only when
         * the firmware reports responder capability (responder is default-on for AP). */
        if (MORSE_CAP_SUPPORTED(umac_interface_get_capabilities(umacd), TWT_RESPONDER))
        {
            umac_twt_init_vif(umacd, &vif_id, true);
        }
    }
}

bool umac_interface_type_is_compatible_with_active(struct umac_interface_data *data,
                                                   enum umac_interface_type type)
{

    if ((data->active_interface_types & VIF_STA_INTERFACE_TYPES_MASK) && (type & UMAC_INTERFACE_AP))
    {
        return false;
    }


    if ((data->active_interface_types & UMAC_INTERFACE_AP) && (type & VIF_STA_INTERFACE_TYPES_MASK))
    {
        return false;
    }


    /* ADHOC is exclusive with every other active type, and conversely no other
     * type may be added while ADHOC is active. */
    if ((data->active_interface_types & UMAC_INTERFACE_ADHOC) && type != UMAC_INTERFACE_ADHOC)
    {
        return false;
    }
    if ((type & UMAC_INTERFACE_ADHOC) &&
        (data->active_interface_types & ~(uint16_t)UMAC_INTERFACE_ADHOC))
    {
        return false;
    }

    /*
     * MESH is exclusive with every other active type EXCEPT a concurrent AP.
     * Mesh + AP co-channel on one radio (the "Mesh-gate") mirrors the Linux
     * morse_driver iface_combination {AP, MESH} with num_different_channels = 1.
     * Our host abstraction requires mesh to own the PRIMARY vif (a mesh on a
     * secondary vif never joins — Linux recipe note), so ONLY the mesh-first
     * ordering is supported: adding AP while MESH is active is allowed; adding
     * MESH on top of an active AP is not (the second test below rejects it).
     */
    if ((data->active_interface_types & UMAC_INTERFACE_MESH) &&
        type != UMAC_INTERFACE_MESH && type != UMAC_INTERFACE_AP)
    {
        return false;
    }
    if ((type & UMAC_INTERFACE_MESH) &&
        (data->active_interface_types & ~(uint16_t)UMAC_INTERFACE_MESH))
    {
        return false;
    }

    return true;
}

enum mmwlan_status umac_interface_add(struct umac_data *umacd,
                                      enum umac_interface_type type,
                                      const uint8_t *mac_addr,
                                      uint16_t *vif_id)
{
    int ret = -1;
    enum mmwlan_status status = MMWLAN_ERROR;
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (!umac_interface_type_is_compatible_with_active(data, type))
    {
        MMLOG_WRN("Interface type %s not compatible with active interface(s) [active=%02x]\n",
                  umac_interface_type_to_str(type),
                  data->active_interface_types);
        return MMWLAN_UNAVAILABLE;
    }


    /*
     * A SoftAP added while a MESH is already active becomes a concurrent SECOND
     * vif (the Mesh-gate): the mesh keeps the primary vif_id, the AP gets its
     * own ap_vif_id. All other cases (device boot, STA<->AP swap on the primary
     * vif) keep the legacy single-vif behaviour.
     */
    const bool ap_secondary = (type == UMAC_INTERFACE_AP) &&
                              (data->active_interface_types & UMAC_INTERFACE_MESH);

    if (ap_secondary)
    {
        /*
         * Route the requested BSSID to the AP vif; do NOT clobber the mesh MAC.
         * The AP MAC must differ from the mesh MAC — derive a distinct
         * locally-administered address if the caller did not supply a usable one
         * (mirrors the Linux recipe's `sed 's/^../3a/'` locally-admin AP MAC).
         */
        uint8_t derived[DOT11_MAC_ADDR_LEN];
        const uint8_t *ap_mac = mac_addr;
        if (ap_mac == NULL || mm_mac_addr_is_zero(ap_mac) ||
            mm_mac_addr_is_equal(ap_mac, data->mac_addr))
        {
            /* Same convention as umac_ap_enable's fallback BSSID (bssid[0] ^= 0x02):
             * flip the locally-administered bit so the AP vif MAC matches the BSSID
             * the AP code advertises, while staying distinct from the mesh MAC. */
            mac_addr_copy(derived, data->mac_addr);
            derived[0] ^= 0x02;
            ap_mac = derived;
        }
        mac_addr_copy(data->ap_mac_addr, ap_mac);
    }
    else if (mac_addr != NULL)
    {
        mac_addr_copy(data->mac_addr, mac_addr);
    }


    if (data->active_interface_types == 0)
    {
        MMLOG_DBG("Booting device\n");

        const char *country_code = umac_regdb_get_country_code(umacd);
        if (strncmp(country_code, "??", 2) == 0)
        {
            MMLOG_ERR("Channel list not set\n");
            status = MMWLAN_CHANNEL_LIST_NOT_SET;
            goto error;
        }

        struct mmdrv_chip_info chip_info = { 0 };
        ret = mmdrv_init(&chip_info, country_code);
        if (ret)
        {
            MMLOG_WRN("Driver init failed with %d\n", ret);
            status = MMWLAN_ERROR;
            goto error;
        }

        data->fw_version.major = chip_info.fw_version.major;
        data->fw_version.minor = chip_info.fw_version.minor;
        data->fw_version.patch = chip_info.fw_version.patch;
        data->morse_chip_id = chip_info.morse_chip_id;
        data->morse_chip_id_string = chip_info.morse_chip_id_string;


        if (mm_mac_addr_is_zero(data->mac_addr))
        {
            umac_interface_populate_device_mac_addr(data, &chip_info);
            MMLOG_DBG("Device MAC address: " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(data->mac_addr));
        }

        enum mmdrv_interface_type drv_if_type;
        if (type == UMAC_INTERFACE_AP)
        {
            drv_if_type = MMDRV_INTERFACE_TYPE_AP;
        }
        else if (type == UMAC_INTERFACE_ADHOC)
        {
            drv_if_type = MMDRV_INTERFACE_TYPE_ADHOC;
        }
        else if (type == UMAC_INTERFACE_MESH)
        {
            drv_if_type = MMDRV_INTERFACE_TYPE_MESH;
        }
        else
        {
            drv_if_type = MMDRV_INTERFACE_TYPE_STA;
        }
        ret = mmdrv_add_if(&data->vif_id, data->mac_addr, drv_if_type);
        MMOSAL_ASSERT(ret == 0);

        MMLOG_DBG("Added IF type=%s, mac_addr=" MM_MAC_ADDR_FMT ", vif_id=%u\n",
                  umac_interface_type_to_str(type),
                  MM_MAC_ADDR_VAL(data->mac_addr),
                  data->vif_id);

        ret = mmdrv_get_capabilities(data->vif_id, &data->capabilities);
        MMOSAL_ASSERT(ret == 0);
    }
    else if (ap_secondary)
    {
        /*
         * Concurrent AP alongside the active mesh: add a SECOND firmware vif and
         * keep it in ap_vif_id. The mesh vif (data->vif_id) is left untouched, so
         * unlike the swap branches below there is no rm_if / umac_ps_reset here.
         */
        ret = mmdrv_add_if(&data->ap_vif_id, data->ap_mac_addr, MMDRV_INTERFACE_TYPE_AP);
        MMOSAL_ASSERT(ret == 0);
        MMLOG_INF("Added concurrent AP vif_id=%u mac=" MM_MAC_ADDR_FMT
                  " alongside mesh vif_id=%u\n",
                  data->ap_vif_id,
                  MM_MAC_ADDR_VAL(data->ap_mac_addr),
                  data->vif_id);
    }
    else if (!(data->active_interface_types & VIF_STA_INTERFACE_TYPES_MASK) &&
             (type & VIF_STA_INTERFACE_TYPES_MASK))
    {
        MMOSAL_DEV_ASSERT(!(data->active_interface_types & MMDRV_INTERFACE_TYPE_AP));
        ret = mmdrv_rm_if(data->vif_id);
        MMOSAL_ASSERT(ret == 0);
        data->vif_id = 0;


        umac_ps_reset(umacd);

        ret = mmdrv_add_if(&data->vif_id, data->mac_addr, MMDRV_INTERFACE_TYPE_STA);
        MMOSAL_ASSERT(ret == 0);
    }
    else if (!(data->active_interface_types & UMAC_INTERFACE_AP) && (type == UMAC_INTERFACE_AP))
    {
        MMOSAL_DEV_ASSERT(!(data->active_interface_types & VIF_STA_INTERFACE_TYPES_MASK));
        ret = mmdrv_rm_if(data->vif_id);
        MMOSAL_ASSERT(ret == 0);
        data->vif_id = 0;


        umac_ps_reset(umacd);

        ret = mmdrv_add_if(&data->vif_id, data->mac_addr, MMDRV_INTERFACE_TYPE_AP);
        MMOSAL_ASSERT(ret == 0);
    }

    data->active_interface_types |= type;

    /* Non-secondary types drive the primary vif; a concurrent AP drives ap_vif_id. */
    uint16_t used_vif_id = ap_secondary ? data->ap_vif_id : data->vif_id;

    umac_interface_init_vif(umacd, type, used_vif_id);
    if (vif_id)
    {
        *vif_id = used_vif_id;
    }

    MMLOG_INF("%s interface added successfully (active=%x)\n",
              umac_interface_type_to_str(type),
              data->active_interface_types);

    return MMWLAN_SUCCESS;
error:
    MMLOG_WRN("Failed to add %s interface\n", umac_interface_type_to_str(type));
    return status;
}

static void umac_interface_execute_inactive_cb(struct umac_interface_data *data)
{
    if (data->inactive_callback != NULL)
    {
        data->inactive_callback(data->inactive_cb_arg);
    }


    data->inactive_callback = NULL;
}

void umac_interface_remove(struct umac_data *umacd, enum umac_interface_type type)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if ((data->active_interface_types & type) == 0)
    {
        umac_interface_execute_inactive_cb(data);
        return;
    }

    /*
     * Removing the primary interface (mesh/STA) while a concurrent AP is still
     * up would orphan the AP's secondary vif in the firmware. Tear the AP down
     * first. The supported teardown order is AP-before-mesh, mirroring the
     * mesh-before-AP bring-up; this keeps any order safe.
     */
    if (!(type & UMAC_INTERFACE_AP) &&
        (data->active_interface_types & UMAC_INTERFACE_AP) &&
        data->ap_vif_id != UMAC_INTERFACE_VIF_ID_INVALID)
    {
        MMLOG_WRN("Removing primary %s with a concurrent AP active; tearing down AP first\n",
                  umac_interface_type_to_str(type));
        umac_interface_remove(umacd, UMAC_INTERFACE_AP);
    }

    /*
     * Concurrent AP on the secondary vif: remove just that vif and leave the
     * primary (mesh) interface running — no full driver deinit here.
     */
    if ((type & UMAC_INTERFACE_AP) && data->ap_vif_id != UMAC_INTERFACE_VIF_ID_INVALID)
    {
        umac_twt_deinit_vif(umacd, &data->ap_vif_id);

        int ret = mmdrv_rm_if(data->ap_vif_id);
        if (ret != 0)
        {
            MMLOG_WRN("Failed to remove concurrent AP vif %u (%d)\n", data->ap_vif_id, ret);
        }
        data->ap_vif_id = UMAC_INTERFACE_VIF_ID_INVALID;
        data->active_interface_types &= ~((uint16_t)UMAC_INTERFACE_AP);

        MMLOG_DBG("Removed concurrent AP vif, active=%u\n", data->active_interface_types);
        return;
    }

    if (type & UMAC_INTERFACE_STA)
    {

        umac_twt_deinit_vif(umacd, &data->vif_id);
    }

    data->active_interface_types &= ~((uint16_t)type);

    MMLOG_DBG("Interface remove %s, active=%u\n",
              umac_interface_type_to_str(type),
              data->active_interface_types);

    if (data->active_interface_types == 0)
    {
        MMLOG_DBG("Shutting down\n");

        int ret = mmdrv_rm_if(data->vif_id);
        if (ret != 0)
        {
            if (umac_shutdown_is_in_progress(umacd))
            {

                MMLOG_WRN("Failed to remove %s interface (%d); ignoring.\n",
                          umac_interface_type_to_str(type),
                          ret);
            }
            else
            {
                MMLOG_ERR("Failed to remove interface (%d)\n", ret);
                MMOSAL_ASSERT(ret == 0);
            }
        }

        data->vif_id = 0;

        mmdrv_set_health_check_interval(0, 0);

        mmdrv_deinit();

        umac_interface_execute_inactive_cb(data);


        uint8_t backup_mac_addr[DOT11_MAC_ADDR_LEN];
        memcpy(backup_mac_addr, data->mac_addr, sizeof(backup_mac_addr));
        const char *chip_id_string = data->morse_chip_id_string;
        uint32_t chip_id;
        memcpy(&chip_id, &data->morse_chip_id, sizeof(chip_id));
        struct mmdrv_fw_version fw_version;
        memcpy(&fw_version, &data->fw_version, sizeof(fw_version));
        memset(data, 0, sizeof(*data));
        memcpy(data->mac_addr, backup_mac_addr, sizeof(data->mac_addr));
        memcpy(&data->fw_version, &fw_version, sizeof(fw_version));
        data->morse_chip_id_string = chip_id_string;
        memcpy(&data->morse_chip_id, &chip_id, sizeof(chip_id));
        data->ap_vif_id = UMAC_INTERFACE_VIF_ID_INVALID;

        umac_ps_reset(umacd);
    }
}

bool umac_interface_is_active(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    return (data->active_interface_types != 0);
}

uint16_t umac_interface_get_vif_id(struct umac_data *umacd, uint16_t type_mask)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    /* A concurrent AP lives on its own secondary vif; resolve AP requests there. */
    if ((type_mask & UMAC_INTERFACE_AP) &&
        (data->active_interface_types & UMAC_INTERFACE_AP) &&
        data->ap_vif_id != UMAC_INTERFACE_VIF_ID_INVALID)
    {
        return data->ap_vif_id;
    }

    if (type_mask & data->active_interface_types)
    {
        return data->vif_id;
    }
    else
    {
        return UMAC_INTERFACE_VIF_ID_INVALID;
    }
}

uint16_t umac_interface_get_vif_type_mask(struct umac_data *umacd, uint16_t vif_id)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    /* The secondary vif only ever serves the concurrent AP. */
    if (data->ap_vif_id != UMAC_INTERFACE_VIF_ID_INVALID && vif_id == data->ap_vif_id)
    {
        return UMAC_INTERFACE_AP;
    }

    if (data->vif_id == vif_id)
    {
        uint16_t mask = data->active_interface_types;
        /* When an AP is concurrent it lives on the secondary vif, so the primary
         * vif's type must not report AP (keeps supplicant TX-status routing to
         * the mesh/STA context, not the AP context). */
        if (data->ap_vif_id != UMAC_INTERFACE_VIF_ID_INVALID)
        {
            mask &= ~(uint16_t)UMAC_INTERFACE_AP;
        }
        return mask;
    }
    else
    {
        return 0;
    }
}

enum mmwlan_status umac_interface_reinstall_vif(struct umac_data *umacd,
                                                enum umac_interface_type type,
                                                uint16_t *vif_id)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (!(data->active_interface_types & type))
    {
        MMLOG_WRN("Unable to reinstall VIF type %s: no active\n", umac_interface_type_to_str(type));
        return MMWLAN_UNAVAILABLE;
    }

    enum mmdrv_interface_type drv_if_type;
    if (type == UMAC_INTERFACE_AP)
    {
        drv_if_type = MMDRV_INTERFACE_TYPE_AP;
    }
    else if (type == UMAC_INTERFACE_ADHOC)
    {
        drv_if_type = MMDRV_INTERFACE_TYPE_ADHOC;
    }
    else
    {
        drv_if_type = MMDRV_INTERFACE_TYPE_STA;
    }
    int ret = mmdrv_add_if(&data->vif_id, data->mac_addr, drv_if_type);
    if (ret != 0)
    {
        return MMWLAN_ERROR;
    }

    if (vif_id != NULL)
    {
        *vif_id = data->vif_id;
    }

    umac_interface_init_vif(umacd, type, data->vif_id);

    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_interface_get_fw_version(struct umac_data *umacd,
                                                 struct mmdrv_fw_version *version)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    MMOSAL_DEV_ASSERT(version != NULL);

    memcpy(version, &data->fw_version, sizeof(data->fw_version));
    return MMWLAN_SUCCESS;
}

uint32_t umac_interface_get_chip_id(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (data->morse_chip_id != 0)
    {
        return data->morse_chip_id;
    }
    MMLOG_WRN("Failed: invalid chip id\n");
    return 0;
}

const char *umac_interface_get_chip_id_string(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (data->morse_chip_id_string != NULL)
    {
        return data->morse_chip_id_string;
    }
    MMLOG_WRN("Failed: invalid chip id\n");
    return NULL;
}

enum mmwlan_status umac_interface_get_mac_addr(struct umac_sta_data *stad, uint8_t *mac_addr)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (data->active_interface_types == 0)
    {
        memset(mac_addr, 0, MMWLAN_MAC_ADDR_LEN);
        MMLOG_INF("Failed: no interface\n");
        return MMWLAN_UNAVAILABLE;
    }

    mac_addr_copy(mac_addr, data->mac_addr);
    return MMWLAN_SUCCESS;
}

const uint8_t *umac_interface_peek_mac_addr(struct umac_sta_data *stad)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (data->active_interface_types != 0)
    {
        return data->mac_addr;
    }
    else
    {
        return NULL;
    }
}

bool umac_interface_addr_matches_mac_addr(struct umac_sta_data *stad, const uint8_t *addr)
{
    const uint8_t *stad_addr = umac_interface_peek_mac_addr(stad);
    if (stad_addr == NULL)
    {
        return false;
    }
    return mm_mac_addr_is_equal(addr, stad_addr);
}

enum mmwlan_status umac_interface_set_scan(struct umac_data *umacd, bool enabled)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (data->active_interface_types == 0)
    {
        MMLOG_INF("Failed: no interface\n");
        return MMWLAN_ERROR;
    }

    MMLOG_INF("Setting scan mode: enabled=%s\n", (enabled ? "true" : "false"));

    int ret = mmdrv_cfg_scan(enabled);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to set scan mode: %d\n", ret);
        return MMWLAN_ERROR;
    }

    return MMWLAN_SUCCESS;
}


static int umac_interface_calc_pri_1mhz_idx(struct umac_data *umacd,
                                            const struct ie_s1g_operation *s1g_operation,
                                            const struct mmwlan_s1g_channel *operating_chan)
{
    const struct mmwlan_s1g_channel *primary_chan =
        umac_regdb_get_channel(umacd, s1g_operation->primary_channel_number);

    if (primary_chan == NULL)
    {
        return -1;
    }

    const int32_t freq_delta_hz = primary_chan->centre_freq_hz - operating_chan->centre_freq_hz;
    const int32_t bw_margin_hz =
        (operating_chan->bw_mhz - primary_chan->bw_mhz) * (MHZ_TO_HZ(1) / 2);

    int pri_1mhz_idx = (freq_delta_hz + bw_margin_hz) / MHZ_TO_HZ(1);

    if (primary_chan->bw_mhz > 1)
    {
        pri_1mhz_idx += s1g_operation->primary_1mhz_channel_loc;
    }

    if (pri_1mhz_idx < 0 || pri_1mhz_idx >= operating_chan->bw_mhz)
    {
        return -1;
    }

    return pri_1mhz_idx;
}

const struct mmwlan_s1g_channel *umac_interface_calc_pri_channel(
    struct umac_data *umacd,
    const struct mmwlan_s1g_channel *operating_chan,
    uint8_t pri_1mhz_chan_idx,
    uint8_t pri_bw_mhz)
{
    MMOSAL_DEV_ASSERT(pri_1mhz_chan_idx < operating_chan->bw_mhz);
    MMOSAL_DEV_ASSERT((pri_bw_mhz == 1) || (pri_bw_mhz == 2));


    uint8_t primary_1mhz_offset = 0;
    if (pri_bw_mhz == 2)
    {
        primary_1mhz_offset = pri_1mhz_chan_idx % 2;
    }

    const int32_t bw_margin_hz = (operating_chan->bw_mhz - pri_bw_mhz) * (MHZ_TO_HZ(1) / 2);
    const int32_t freq_delta_hz =
        (pri_1mhz_chan_idx - primary_1mhz_offset) * MHZ_TO_HZ(1) - bw_margin_hz;
    const int32_t primary_centre_freq_hz = operating_chan->centre_freq_hz + freq_delta_hz;

    return umac_regdb_get_channel_from_freq_and_bw(umacd,
                                                   (uint32_t)primary_centre_freq_hz,
                                                   pri_bw_mhz);
}

static enum mmwlan_status umac_interface_set_channel_internal(
    struct umac_data *umacd,
    const struct ie_s1g_operation *s1g_operation,
    const struct mmwlan_s1g_channel *s1g_channel_info,
    bool is_off_channel)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    int ret = 0;

    if (data->active_interface_types == 0)
    {
        MMLOG_INF("Failed: no interface\n");
        return MMWLAN_ERROR;
    }


    if (s1g_operation->primary_channel_width_mhz > 2 ||
        s1g_operation->primary_channel_width_mhz > s1g_operation->operation_channel_width_mhz)
    {
        MMLOG_ERR("Invalid primary bandwidth %u\n", s1g_operation->primary_channel_width_mhz);
        return MMWLAN_CHANNEL_INVALID;
    }

    if (s1g_operation->operation_channel_width_mhz > umac_interface_max_supported_bw(umacd))
    {
        MMLOG_ERR("%u MHz not supported\n", s1g_operation->operation_channel_width_mhz);
        return MMWLAN_CHANNEL_INVALID;
    }

    if (s1g_operation->operation_channel_width_mhz != s1g_channel_info->bw_mhz)
    {
        MMLOG_ERR("Invalid operating bw %u, expect %u (chan#=%u)\n",
                  s1g_operation->operation_channel_width_mhz,
                  s1g_channel_info->bw_mhz,
                  s1g_channel_info->s1g_chan_num);
        return MMWLAN_CHANNEL_INVALID;
    }

    if (s1g_operation->primary_1mhz_channel_loc > 1 ||
        s1g_operation->primary_1mhz_channel_loc == s1g_channel_info->bw_mhz)
    {
        MMLOG_ERR("Invalid primary 1 MHz channel %u\n", s1g_operation->primary_1mhz_channel_loc);
        return MMWLAN_CHANNEL_INVALID;
    }

    int prim_1mhz_chan_idx =
        umac_interface_calc_pri_1mhz_idx(umacd, s1g_operation, s1g_channel_info);
    if (prim_1mhz_chan_idx < 0)
    {
        MMLOG_ERR("Invalid primary channel config in S1G operation\n");
        return MMWLAN_CHANNEL_INVALID;
    }

    MMLOG_INF(
        "Setting channel %u: op freq=%lu Hz, pri ch=%u, pri 1M idx=%d, bw=%u MHz, pri bw=%u MHz\n",
        s1g_operation->operating_channel_index,
        s1g_channel_info->centre_freq_hz,
        s1g_operation->primary_channel_number,
        prim_1mhz_chan_idx,
        s1g_channel_info->bw_mhz,
        s1g_operation->primary_channel_width_mhz);

    if (ie_s1g_operation_is_equal(&data->current_s1g_operation, s1g_operation))
    {
        MMLOG_INF("Channel is the same, skipping set channel\n");
    }
    else
    {
        ret = mmdrv_set_channel(s1g_channel_info->centre_freq_hz,
                                prim_1mhz_chan_idx,
                                s1g_channel_info->bw_mhz,
                                s1g_operation->primary_channel_width_mhz,
                                is_off_channel);
        if (ret != 0)
        {
            MMLOG_WRN("Failed to set channel %u: %d\n",
                      s1g_operation->operating_channel_index,
                      ret);
            if (ret == MORSE_RET_EPERM)
            {
                return MMWLAN_CHANNEL_INVALID;
            }
            else
            {
                return MMWLAN_ERROR;
            }
        }
        data->current_s1g_operation = *s1g_operation;
    }

    int32_t actual_txpower = 0;
    int new_txpower = s1g_channel_info->max_tx_eirp_dbm;
    uint16_t tx_power_override = umac_config_get_max_tx_power(umacd);
    if (tx_power_override > 0 && tx_power_override < new_txpower)
    {
        new_txpower = tx_power_override;
    }

    ret = mmdrv_set_txpower(&actual_txpower, new_txpower);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to set power level %d\n", new_txpower);
        return MMWLAN_ERROR;
    }

    enum mmwlan_duty_cycle_mode duty_cycle_mode = umac_config_get_duty_cycle_mode(umacd);
    ret = mmdrv_set_duty_cycle(s1g_channel_info->duty_cycle_sta,
                               s1g_channel_info->duty_cycle_omit_ctrl_resp,
                               duty_cycle_mode);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to set duty cycle %d\n", s1g_channel_info->duty_cycle_sta);
        return MMWLAN_ERROR;
    }

    ret = mmdrv_cfg_mpsw(s1g_channel_info->airtime_min_us,
                         s1g_channel_info->airtime_max_us,
                         s1g_channel_info->pkt_spacing_us);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to configure mpsw.\n");
        return MMWLAN_ERROR;
    }

    MMLOG_INF("Requested tx power %d, actual %ld; duty cycle %u.%02u %%, "
              "minimum airtime %lu us, maximum airtime %lu us, packet space window %lu us.\n",
              new_txpower,
              actual_txpower,
              s1g_channel_info->duty_cycle_sta / 100,
              s1g_channel_info->duty_cycle_sta % 100,
              s1g_channel_info->airtime_min_us,
              s1g_channel_info->airtime_max_us,
              s1g_channel_info->pkt_spacing_us);

    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_interface_set_channel(struct umac_data *umacd,
                                              const struct ie_s1g_operation *s1g_operation)
{
    const struct mmwlan_s1g_channel *operating_chan =
        umac_regdb_get_channel(umacd, s1g_operation->operating_channel_index);
    if (operating_chan == NULL ||
        !umac_regdb_op_class_match(umacd, s1g_operation->operating_class, operating_chan))
    {
        MMLOG_ERR("No matching channel (reg_dom=%s, op_class=%u, chan#=%u)\n",
                  umac_regdb_get_country_code(umacd),
                  s1g_operation->operating_class,
                  s1g_operation->operating_channel_index);
        return MMWLAN_CHANNEL_INVALID;
    }

    return umac_interface_set_channel_internal(umacd, s1g_operation, operating_chan, false);
}

enum mmwlan_status umac_interface_set_channel_from_regdb(struct umac_data *umacd,
                                                         const struct mmwlan_s1g_channel *channel,
                                                         bool is_off_channel)
{
    struct ie_s1g_operation s1g_operation = {
        .primary_channel_width_mhz = channel->bw_mhz > 1 ? 2 : 1,
        .operation_channel_width_mhz = channel->bw_mhz,
        .primary_1mhz_channel_loc = 0,
        .recommend_no_mcs10 = false,
        .operating_class = channel->global_operating_class,
        .primary_channel_number = channel->s1g_chan_num,
        .operating_channel_index = channel->s1g_chan_num,
    };

    return umac_interface_set_channel_internal(umacd, &s1g_operation, channel, is_off_channel);
}

const struct ie_s1g_operation *umac_interface_get_current_s1g_operation_info(
    struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    return &data->current_s1g_operation;
}

enum mmwlan_status umac_interface_reconfigure_channel(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);


    struct ie_s1g_operation s1g_operation = data->current_s1g_operation;


    memset(&data->current_s1g_operation, 0, sizeof(data->current_s1g_operation));

    if (s1g_operation.operating_channel_index != 0)
    {
        return umac_interface_set_channel(umacd, &s1g_operation);
    }
    else
    {
        return MMWLAN_SUCCESS;
    }
}

const struct morse_caps *umac_interface_get_capabilities(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    return &data->capabilities;
}

uint8_t umac_interface_max_supported_bw(struct umac_data *umacd)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    const struct morse_caps *capabilities = &data->capabilities;

    if (morse_caps_supported(capabilities, MORSE_CAPS_16MHZ))
    {
        return 16;
    }
    if (morse_caps_supported(capabilities, MORSE_CAPS_8MHZ))
    {
        return 8;
    }
    if (morse_caps_supported(capabilities, MORSE_CAPS_4MHZ))
    {
        return 4;
    }
    if (morse_caps_supported(capabilities, MORSE_CAPS_2MHZ))
    {
        return 2;
    }
    return 1;
}

enum mmwlan_status umac_interface_set_ndp_probe_support(struct umac_data *umacd, bool enabled)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (data->active_interface_types == 0)
    {
        MMLOG_INF("Failed: no interface\n");
        return MMWLAN_UNAVAILABLE;
    }

    MMLOG_INF("Setting ndp probe support: enabled=%s\n", (enabled ? "true" : "false"));

    int ret = mmdrv_set_ndp_probe(data->vif_id, enabled);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to set ndp probe support: %d\n", ret);
        return MMWLAN_ERROR;
    }

    return MMWLAN_SUCCESS;
}

void umac_interface_register_inactive_cb(struct umac_data *umacd,
                                         umac_interface_inactive_cb_t callback,
                                         void *arg)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    data->inactive_callback = callback;
    data->inactive_cb_arg = arg;
}

enum mmwlan_status umac_interface_register_vif_state_cb(struct umac_data *umacd,
                                                        enum mmwlan_vif vif,
                                                        mmwlan_vif_state_cb_t callback,
                                                        void *arg)
{
    if (vif == MMWLAN_VIF_UNSPECIFIED)
    {
        umac_interface_register_vif_state_cb(umacd, MMWLAN_VIF_STA, callback, arg);
        umac_interface_register_vif_state_cb(umacd, MMWLAN_VIF_AP, callback, arg);
        return MMWLAN_SUCCESS;
    }

    struct umac_interface_vif_data *data = umac_data_get_interface_vif(umacd, vif);
    if (data == NULL)
    {
        return MMWLAN_INVALID_ARGUMENT;
    }

    data->vif_state_cb = callback;
    data->vif_state_cb_arg = arg;

    return MMWLAN_SUCCESS;
}

bool umac_interface_invoke_vif_state_cb(struct umac_data *umacd,
                                        const struct mmwlan_vif_state *state)
{
    struct umac_interface_vif_data *data = umac_data_get_interface_vif(umacd, state->vif);
    if (data == NULL || data->vif_state_cb == NULL)
    {
        return false;
    }

    data->vif_state_cb(state, data->vif_state_cb_arg);
    return true;
}

enum mmwlan_status umac_interface_get_device_mac_addr(struct umac_data *umacd, uint8_t *mac_addr)
{
    struct umac_interface_data *data = umac_data_get_interface(umacd);
    mac_addr_copy(mac_addr, data->mac_addr);

    if (mm_mac_addr_is_zero(data->mac_addr))
    {
        MMLOG_INF("Failed: no MAC addr\n");
        return MMWLAN_UNAVAILABLE;
    }

    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_interface_get_vif_mac_addr(struct umac_data *umacd,
                                                   enum mmwlan_vif vif,
                                                   uint8_t *mac_addr)
{

    struct umac_interface_data *data = umac_data_get_interface(umacd);
    if (vif == MMWLAN_VIF_STA)
    {
        if (!(data->active_interface_types & UMAC_INTERFACE_AP) &&
            (data->active_interface_types != 0))
        {
            mac_addr_copy(mac_addr, data->mac_addr);
            return MMWLAN_SUCCESS;
        }
    }
    else if (vif == MMWLAN_VIF_AP)
    {
        if (data->active_interface_types & UMAC_INTERFACE_AP)
        {
            mac_addr_copy(mac_addr, data->mac_addr);
            return MMWLAN_SUCCESS;
        }
    }

    return MMWLAN_UNAVAILABLE;
}

enum mmwlan_status umac_interface_borrow_vif_mac_addr(struct umac_data *umacd,
                                                      enum mmwlan_vif vif,
                                                      const uint8_t **mac_addr)
{

    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (vif == MMWLAN_VIF_STA)
    {
        if (!(data->active_interface_types & UMAC_INTERFACE_AP) &&
            (data->active_interface_types != 0))
        {
            *mac_addr = data->mac_addr;
            return MMWLAN_SUCCESS;
        }
    }
    else if (vif == MMWLAN_VIF_AP)
    {
        if (data->active_interface_types & UMAC_INTERFACE_AP)
        {
            *mac_addr = data->mac_addr;
            return MMWLAN_SUCCESS;
        }
    }

    MMLOG_INF("Failed: no interface\n");
    return MMWLAN_ERROR;
}

enum mmwlan_status umac_interface_set_vif_mac_addr(struct umac_data *umacd,
                                                   enum mmwlan_vif vif,
                                                   const uint8_t *mac_addr)
{

    struct umac_interface_data *data = umac_data_get_interface(umacd);

    if (vif == MMWLAN_VIF_STA)
    {
        if (!(data->active_interface_types & UMAC_INTERFACE_AP) &&
            (data->active_interface_types != 0))
        {
            mac_addr_copy(data->mac_addr, mac_addr);
            return MMWLAN_SUCCESS;
        }
    }
    else if (vif == MMWLAN_VIF_AP)
    {
        if (data->active_interface_types & UMAC_INTERFACE_AP)
        {
            mac_addr_copy(data->mac_addr, mac_addr);
            return MMWLAN_SUCCESS;
        }
    }

    MMLOG_INF("Failed: no interface\n");
    return MMWLAN_ERROR;
}

enum mmwlan_status umac_interface_register_rx_pkt_ext_cb(struct umac_data *umacd,
                                                         enum mmwlan_vif vif,
                                                         mmwlan_rx_pkt_ext_cb_t callback,
                                                         void *arg)
{
    if (vif == MMWLAN_VIF_UNSPECIFIED)
    {
        umac_interface_register_rx_pkt_ext_cb(umacd, MMWLAN_VIF_STA, callback, arg);
        umac_interface_register_rx_pkt_ext_cb(umacd, MMWLAN_VIF_AP, callback, arg);
        return MMWLAN_SUCCESS;
    }

    struct umac_interface_vif_data *data = umac_data_get_interface_vif(umacd, vif);
    if (data == NULL)
    {
        return MMWLAN_INVALID_ARGUMENT;
    }

    data->rx_pkt_ext_cb = callback;
    data->rx_pkt_ext_cb_arg = arg;

    return MMWLAN_SUCCESS;
}

mmwlan_rx_pkt_ext_cb_t umac_interface_get_rx_pkt_ext_cb(struct umac_data *umacd,
                                                        enum mmwlan_vif vif,
                                                        void **arg)
{
    MMOSAL_DEV_ASSERT(arg != NULL);

    struct umac_interface_vif_data *data = umac_data_get_interface_vif(umacd, vif);
    if (data == NULL)
    {
        *arg = NULL;
        return NULL;
    }

    *arg = data->rx_pkt_ext_cb_arg;
    return data->rx_pkt_ext_cb;
}
