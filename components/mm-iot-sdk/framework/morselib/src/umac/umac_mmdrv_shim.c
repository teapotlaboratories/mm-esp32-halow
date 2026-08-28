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
        /* Power save, for the same reason and by the same argument. It is NOT enough to let
         * umac_interface_reinstall_vif() -> umac_interface_init_vif() call umac_ps_update_mode():
         * that early-returns on `data->pwr_mode == new_mode` (umac_ps.c), and pwr_mode is HOST state
         * that survived the restart. The chip comes back with PS off while the host still believes it
         * is on, so no mmdrv_set_chip_power_save_enabled() is ever issued -- and every later
         * update_mode() short-circuits too, so nothing can fix it. umac_ps_handle_hw_restarted()
         * exists precisely to break that: it calls umac_ps_reset() (clearing pwr_mode) BEFORE
         * update_mode(). Third instance of the same trap in this path -- see the channel cache and the
         * CCMP PN counters. */
        umac_ps_handle_hw_restarted(umacd);

        unsigned fragment_threshold = umac_config_get_frag_threshold(umacd);
        if (mmdrv_set_frag_threshold(fragment_threshold) != MMWLAN_SUCCESS)
        {
            MMLOG_WRN("Failed to reconfigure fragmentation threshold.\n");
        }

        umac_scan_handle_hw_restarted(umacd);

        /* The channel, also HW-GLOBAL and hoisted here for the same reason. mmdrv_set_channel() is
         * issued with MMDRV_VIF_ID_INVALID (driver.c:864) -- it is a radio-wide command, and so are
         * the txpower / duty-cycle / mpsw commands that ride with it (umac_interface.c:834-866).
         * Linux agrees on the placement: ieee80211_hw_config() runs once, after drv_start() and
         * before the per-vif loop, not inside the type switch.
         *
         * It has to be OUT of the per-slot arms because the mesh gateway runs a mesh vif AND an AP
         * vif. With the call inside each arm the gate would program the channel a second time from
         * the AP arm, after the mesh arm had already armed beaconing. One radio, one channel, one
         * restore.
         *
         * ⚠ It must be reconfigure_channel(), NOT set_channel_from_regdb(): the latter short-circuits
         * on ie_s1g_operation_is_equal() against data->current_s1g_operation (umac_interface.c:815),
         * a HOST cache that mmdrv_init() does not clear -- so it programs nothing and returns
         * SUCCESS. Fourth instance of that trap on this path; see the pwr_mode note above.
         *
         * ⚠ umac_connection_handle_hw_restarted() KEEPS its own copy of this call, and that is not
         * dead code. It has a second caller that never comes through this handler:
         * wnm_sleep_fsm_active_exit() (umac_wnm_sleep.c:281-286) re-inits the chip after a WNM
         * chip-powerdown and drives the connection restore directly. Dropping it there would silently
         * lose the channel on the power-save wake path. The cost here is one redundant SET_CHANNEL
         * with the same value on a STA node, issued before any vif is beaconing. */
        /* A failure here is FATAL, not a log line. Before the hoist this call lived inside the arms
         * and carried real consequences -- the mesh arm ran umac_mesh_abort_restore() and the STA arm
         * UMAC_FATAL_ERROR() -- and moving it must not quietly downgrade that. Without the channel the
         * node cannot transmit or receive, so carrying on to re-arm beaconing would manufacture
         * exactly the silently-deaf state this whole feature exists to eliminate: a node whose host
         * view looks healthy and whose radio says nothing.
         *
         * UMAC_FATAL_ERROR is the right severity for every interface type, which is the point of
         * being here rather than in an arm: it drives the shutdown path, which tears the mesh and the
         * AP down honestly instead of leaving mesh_ctx.active true over a dead chip. It is also
         * exactly what the STA arm did before. */
        enum mmwlan_status chan_status = umac_interface_reconfigure_channel(umacd);
        bool channel_ok = (chan_status == MMWLAN_SUCCESS);
        if (!channel_ok)
        {
            /* Either way the arms are skipped -- beaconing on a chip with no channel is the
             * silently-deaf state this path exists to prevent -- but the two causes are not the same
             * fault and must not read as one.
             *
             * MMWLAN_UNAVAILABLE means there was no channel configured to restore. That is not an
             * error the node caused: it is reachable on an interface that is active but has never been
             * given a channel (the boot vif), and escalating it to a fatal shutdown would turn a benign
             * early restart into a dead node. Anything else means the chip REJECTED a channel it was
             * operating on moments ago, which is fatal. */
            if (chan_status == MMWLAN_UNAVAILABLE)
            {
                MMLOG_WRN("No channel was configured before the hardware restart, so there is nothing "
                          "to restore; skipping the per-slot restore rather than beaconing on a chip "
                          "with no channel\n");
            }
            else
            {
                MMLOG_ERR("Failed to reconfigure the channel after a hardware restart (%d) -- the node "
                          "cannot transmit or receive; aborting the restore rather than beaconing on a "
                          "chip with no channel\n", (int)chan_status);
                UMAC_FATAL_ERROR(umacd);
            }
        }

        /* Restore per HOST-SLOT, not by picking one interface type -- mirroring net/mac80211, where
         * ieee80211_reconfig() LOOPS over every interface (util.c:1902) and each one independently
         * takes its own arm of the type switch.
         *
         * morselib has exactly two host slots: VIF_STA (STA / IBSS / mesh / scan / the boot vif) and
         * VIF_AP (VIF_STA_INTERFACE_TYPES_MASK, umac_interface.c:118-120). The shipped mesh gateway
         * -- rimba-halow-mesh-ap -- runs BOTH at once, which a single `mesh else connection` choice
         * cannot express: whichever arm won, the other interface stayed dead on the chip. Two
         * independent slot restores can, and that is the only structural change needed to make the
         * gateway recoverable.
         *
         * Order is mesh-then-AP, matching the order the gateway is brought up in: mmwlan_mesh_start()
         * first, then mmwlan_ap_enable(), whose enable path inherits the STA slot's channel
         * (umac_ap.c:265-281).
         *
         * Within the VIF_STA slot the choice IS exclusive -- STA, IBSS and mesh share one FW vif --
         * so that arm stays an either/or.
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
        if (channel_ok && umac_mesh_is_active())
        {
            umac_mesh_handle_hw_restarted(umacd);
        }
        else if (channel_ok)
        {
            umac_connection_handle_hw_restarted(umacd);
        }

#if !(defined(MMWLAN_AP_DISABLED) && MMWLAN_AP_DISABLED)
        /* The VIF_AP slot, restored independently of the one above.
         *
         * This replaces an MMOSAL_ASSERT(false) that used to be the FIRST statement in this handler:
         * an active AP vif panicked the node instead of recovering it, which made the gateway the one
         * configuration a hardware restart could not survive. Linux does not refuse an AP either --
         * NL80211_IFTYPE_AP takes the same generic restore as every other type plus drv_start_ap()
         * (util.c:2036-2038). umac_ap_handle_hw_restarted() self-guards, so this is a no-op on a node
         * with no AP.
         *
         * The #if is load-bearing, not cosmetic. umac_ap.c is not compiled when AP support is off, so
         * an unguarded reference here is an undefined symbol at link -- exactly the trap documented on
         * umac_mmdrv_get_beacon() below, which the S2 work tripped once already by pulling this
         * translation unit back in. */
        if (channel_ok)
        {
            umac_ap_handle_hw_restarted(umacd);
        }
#endif
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
