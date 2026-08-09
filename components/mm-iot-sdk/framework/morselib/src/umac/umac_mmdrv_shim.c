/*
 *  Copyright 2022 Morse Micro
 *  SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "common/common.h"
#include "mmdrv.h"
#include "mmlog.h"
#include "umac/ap/umac_ap.h"
#include "umac/ibss/umac_ibss.h"
#include "umac/mesh/umac_mesh.h"
#include "umac/core/umac_core.h"
#include "umac/datapath/umac_datapath.h"
#include "umac/connection/umac_connection.h"
#include "umac/health_check/umac_health_check.h"
#include "umac/regdb/umac_regdb.h"
#include "umac/stats/umac_stats.h"
#include "umac/supplicant_shim/umac_supp_shim.h"



void mmdrv_host_process_rx_frame(struct mmpkt *rxbuf, uint16_t channel)
{
    MM_UNUSED(channel);

    MMOSAL_DEV_ASSERT(channel == 0);
    struct umac_data *umacd = umac_data_get_umacd();

    if (!umac_core_is_running(umacd))
    {
        MMLOG_WRN("Event loop not running. Dropping frame.\n");
        mmpkt_release(rxbuf);
        return;
    }

    umac_datapath_rx_frame(umacd, rxbuf);
}

void mmdrv_host_process_tx_status(struct mmpkt *mmpkt)
{
    struct umac_data *umacd = umac_data_get_umacd();

    if (!umac_core_is_running(umacd))
    {
        mmpkt_release(mmpkt);
        return;
    }

    umac_datapath_handle_tx_status(umacd, mmpkt);
}

void mmdrv_host_set_tx_paused(uint16_t sources_mask, bool paused)
{
    struct umac_data *umacd = umac_data_get_umacd();
    if (paused)
    {
        umac_datapath_pause(umacd, sources_mask);
    }
    else
    {
        umac_datapath_unpause(umacd, sources_mask);
    }
}

void mmdrv_host_update_tx_paused(uint16_t sources_mask, mmdrv_host_update_tx_paused_cb_t cb)
{
    struct umac_data *umacd = umac_data_get_umacd();
    umac_datapath_update_tx_paused(umacd, sources_mask, cb);
}

static void hw_restart_evt_handler(struct umac_data *umacd, const struct umac_evt *evt)
{
    MM_UNUSED(evt);

    if (umac_interface_get_vif_id(umacd, UMAC_INTERFACE_AP) != MMDRV_VIF_ID_INVALID)
    {
        MMLOG_ERR("Unable to recover from hardware restart with AP interface active\n");
        MMOSAL_ASSERT(false);
    }

    if (umac_interface_is_active(umacd))
    {
        const char *country_code = umac_regdb_get_country_code(umacd);
        if (country_code == NULL)
        {
            MMLOG_ERR("Channel list not set\n");
            return;
        }

        mmdrv_deinit();
        MMOSAL_ASSERT(mmdrv_init(NULL, country_code) == MMWLAN_SUCCESS);

        umac_health_check_start(umacd);
        umac_stats_increment_hw_restart_counter(umacd);

        /* HW-GLOBAL settings first, before any per-interface handler -- mirroring net/mac80211, where
         * ieee80211_reconfig() restores the frag/RTS thresholds (util.c:1836/1839) after drv_start()
         * and before the vif loop. The fragmentation threshold lived inside
         * umac_connection_handle_hw_restarted()'s STA-gated body until 2026-08-06, which meant a mesh
         * node -- which never enters that body -- lost it on every restart. It is not STA state: the
         * value comes from umacd's config and mmdrv_set_frag_threshold() takes no vif.
         * ⚠ The RTS threshold (MORSE_PARAM_ID_RTS_THRESHOLD) is NOT restored here or anywhere, for any
         * interface type; Linux restores it alongside. Tracked separately rather than fixed in passing,
         * because it changes STA behaviour too and needs its own verification. */
        unsigned fragment_threshold = umac_config_get_frag_threshold(umacd);
        if (mmdrv_set_frag_threshold(fragment_threshold) != MMWLAN_SUCCESS)
        {
            MMLOG_WRN("Failed to reconfigure fragmentation threshold.\n");
        }

        umac_scan_handle_hw_restarted(umacd);

        /* Dispatch by interface type, EXPLICITLY -- mirroring net/mac80211, where ieee80211_reconfig
         * runs a per-type switch and no vif takes two arms.
         *
         * ⚠ The exclusivity must be enforced here; it cannot be inferred from the handlers. It is
         * tempting to call both and assume the connection handler no-ops on a mesh node, because it
         * opens on `umac_interface_get_vif_id(umacd, UMAC_INTERFACE_STA)`. It does NOT no-op:
         * UMAC_INTERFACE_STA is inside VIF_STA_INTERFACE_TYPES_MASK (umac_interface.c:118-120), so
         * get_vif_id() returns vif_data_sta->vif_id WITHOUT consulting active_interface_types
         * (umac_interface.c:492-499) -- and mesh shares that very slot. On a mesh node the guard is
         * true and the body runs, which was confirmed on hardware (probe, 2026-08-06: "BODY RUNNING
         * vif_id=0" on a meshing node).
         *
         * Left unguarded, the connection handler would then run umac_interface_reinstall_vif() a
         * SECOND time, immediately after the mesh handler had reinstalled the vif, reprogrammed the
         * BSS, re-pushed every peer and armed beaconing -- re-adding the FW interface underneath all
         * of it, and driving mmdrv_update_sta_state() with the connection stad's aid 0 and all-zero
         * BSSID. It happened to survive on the bench; that is not a property worth depending on. */
        if (umac_mesh_is_active())
        {
            umac_mesh_handle_hw_restarted(umacd);
        }
        else
        {
            umac_connection_handle_hw_restarted(umacd);
        }
    }

    MMLOG_DBG("Notify MMDRV that restart has completed\n");
    mmdrv_hw_restart_completed();
}

/* Public fault-injection entry point. Lives here, beside the handler it drives, so the restart path has
 * exactly one place to read. Deliberately a morselib API rather than an app reaching into
 * morselib/src/internal/mmdrv.h: the internal header is not on an app's link surface, and widening that
 * surface to suit one test fixture would make every internal mmdrv symbol app-callable. */
enum mmwlan_status mmwlan_force_hw_restart(void)
{
    /* No umacd NULL check: umac_data_get_umacd() returns the address of a static and cannot return
     * NULL -- it asserts on an uninitialised subsystem instead (umac_data.c:57). The sibling public
     * accessors (mmwlan_get_umac_stats, mmwlan_clear_umac_stats) call it unguarded for the same
     * reason, so a check here would be dead code that reads as a boot-safety guarantee it cannot
     * make. Callers must boot the WLAN subsystem first; see the header. */
    struct umac_data *umacd = umac_data_get_umacd();

    if (!umac_interface_is_active(umacd))
    {
        return MMWLAN_UNAVAILABLE;
    }

    MMLOG_WRN("Forcing a hardware restart on request (fault injection)\n");
    mmdrv_host_hw_restart_required();
    return MMWLAN_SUCCESS;
}

void mmdrv_host_hw_restart_required(void)
{
    struct umac_data *umacd = umac_data_get_umacd();

    mmdrv_host_set_tx_paused(MMDRV_PAUSE_SOURCE_MASK_HW_RESTART, true);

    struct umac_evt evt = UMAC_EVT_INIT(hw_restart_evt_handler);
    bool ok = umac_core_evt_queue_at_start(umacd, &evt);
    if (!ok)
    {

        MMLOG_ERR("Failed to queue HW_RESTARTED event.\n");
        MMOSAL_ASSERT(false);
    }
}

static void health_check_required_evt_handler(struct umac_data *umacd, const struct umac_evt *evt)
{
    MM_UNUSED(evt);
    umac_health_check_demand_check(umacd);
}

void mmdrv_host_health_check_required(void)
{
    struct umac_data *umacd = umac_data_get_umacd();

    struct umac_evt evt = UMAC_EVT_INIT(health_check_required_evt_handler);
    bool ok = umac_core_evt_queue_at_start(umacd, &evt);
    if (!ok)
    {
        MMLOG_WRN("Failed to queue HEALTH_CHECK_REQUIRED event.\n");
    }
}

static void beacon_loss_evt_handler(struct umac_data *umacd, const struct umac_evt *evt)
{
    MM_UNUSED(evt);

    umac_connection_handle_beacon_loss(umacd);
}

void mmdrv_host_beacon_loss(uint32_t num_bcns)
{
    MM_UNUSED(num_bcns);
    struct umac_data *umacd = umac_data_get_umacd();

    struct umac_evt evt = UMAC_EVT_INIT(beacon_loss_evt_handler);
    bool ok = umac_core_evt_queue(umacd, &evt);
    if (!ok)
    {
        MMLOG_WRN("Failed to queue BEACON_LOSS event.\n");
    }
}

static void connection_loss_evt_handler(struct umac_data *umacd, const struct umac_evt *evt)
{
    MM_UNUSED(evt);

    MMLOG_WRN("UMAC_EVT_CONNECTION_LOSS event received with reason code %lu\n",
              evt->args.connection_loss.reason);
    umac_connection_process_disassoc_req(umacd, NULL);
}

void mmdrv_host_connection_loss(uint32_t reason)
{
    struct umac_data *umacd = umac_data_get_umacd();

    struct umac_evt evt = UMAC_EVT_INIT(connection_loss_evt_handler);
    evt.args.connection_loss.reason = reason;
    bool ok = umac_core_evt_queue(umacd, &evt);
    if (!ok)
    {
        MMLOG_WRN("Failed to queue CONNECTION_LOSS event.\n");
    }
}

void mmdrv_host_cqm_event(enum mmdrv_cqm_event event, int16_t rssi)
{
    struct umac_data *umacd = umac_data_get_umacd();

    switch (event)
    {
        case MMDRV_CQM_EVENT_RSSI_THRESHOLD_HIGH:
        case MMDRV_CQM_EVENT_RSSI_THRESHOLD_LOW:

            umac_supp_notify_signal_change(umacd,
                                           rssi,
                                           (event == MMDRV_CQM_EVENT_RSSI_THRESHOLD_HIGH));
            break;

        default:
            MMLOG_WRN("Unknown CQM event %u\n", event);
            break;
    }
}

static void hw_scan_complete_evt_handler(struct umac_data *umacd, const struct umac_evt *evt)
{
    umac_scan_hw_scan_done(umacd, evt->args.hw_scan_done.state);
}

void mmdrv_host_hw_scan_complete(enum mmwlan_scan_state state)
{
    struct umac_data *umacd = umac_data_get_umacd();

    struct umac_evt evt =
        UMAC_EVT_INIT_ARGS(hw_scan_complete_evt_handler, hw_scan_done, .state = state);
    bool ok = umac_core_evt_queue(umacd, &evt);
    if (!ok)
    {
        MMLOG_ERR("Failed to queue HW_SCAN_DONE event.\n");
    }
}

void mmdrv_host_stats_increment_datapath_driver_rx_alloc_failures(void)
{
    struct umac_data *umacd = umac_data_get_umacd();
    umac_stats_increment_datapath_driver_rx_alloc_failures(umacd);
}


void mmdrv_host_stats_increment_datapath_driver_rx_read_failures(void)
{
    struct umac_data *umacd = umac_data_get_umacd();
    umac_stats_increment_datapath_driver_rx_read_failures(umacd);
}

void mmdrv_host_stats_increment_datapath_driver_tx_skbq_timeout(void)
{
    struct umac_data *umacd = umac_data_get_umacd();
    umac_stats_increment_datapath_driver_tx_skbq_timeout(umacd);
}

void mmdrv_host_stats_increment_datapath_driver_tx_pending_status_timeout(void)
{
    struct umac_data *umacd = umac_data_get_umacd();
    umac_stats_increment_datapath_driver_tx_pending_status_timeout(umacd);
}

struct mmpkt *mmdrv_host_get_beacon(uint16_t vif_id)
{
    struct umac_data *umacd = umac_data_get_umacd();

    /* IBSS is exclusive (single vif); keep the legacy global dispatch. */
    if (umac_ibss_is_active())
    {
        return umac_ibss_get_beacon(umacd);
    }

    /* Mesh + AP can beacon concurrently on separate vifs: dispatch by the vif
     * that requested a beacon rather than by a single global "active" type. */
    uint16_t vif_types = umac_interface_get_vif_type_mask(umacd, vif_id);
    if (vif_types & UMAC_INTERFACE_MESH)
    {
        return umac_mesh_get_beacon(umacd);
    }
#if !(defined(MMWLAN_AP_DISABLED) && MMWLAN_AP_DISABLED)
    if (vif_types & UMAC_INTERFACE_AP)
    {
        return umac_ap_get_beacon(umacd);
    }
#endif

    /* Fallback preserves the legacy single-vif behaviour if the vif->type
     * lookup comes back empty (e.g. a beacon in flight during teardown). */
    if (umac_mesh_is_active())
    {
        return umac_mesh_get_beacon(umacd);
    }
#if !(defined(MMWLAN_AP_DISABLED) && MMWLAN_AP_DISABLED)
    return umac_ap_get_beacon(umacd);
#else
    /* AP support is compiled out (CONFIG_HALOW_AP_MODE=n): there is no AP vif that could have asked
     * for this beacon, so there is nothing to serve.
     *
     * These guards are not cosmetic. umac_ap.c is not compiled in this configuration, so every
     * umac_ap_get_beacon() reference above is undefined -- the build only ever succeeded because
     * --gc-sections dropped this whole function when nothing referenced it. That made the STA-only
     * build silently dependent on an accident of dead-code elimination: adding any new call into this
     * chain broke the link. It did, on 2026-08-06, when the hw-restart handler started calling
     * umac_mesh_handle_hw_restarted() and pulled umac_mesh.o (and this dispatcher) back in. */
    return NULL;
#endif
}
