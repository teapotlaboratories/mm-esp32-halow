/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include <stdatomic.h>

#include "beacon.h"
#include "driver/driver.h"
#include "driver/morse_driver/hw.h"

void morse_beacon_irq_handle(struct driver_data *driverd, uint32_t status1_reg)
{
    /* One beacon IRQ bit per enabled vif; latch which vif(s) fired for the work
     * handler and wake it once. */
    uint32_t pending = 0;
    uint8_t enabled = driverd->beacon.enabled_vif_mask;
    while (enabled)
    {
        uint8_t vif = (uint8_t)__builtin_ctz(enabled);
        enabled &= (uint8_t)(enabled - 1);

        if (status1_reg & (1ul << (MORSE_INT_BEACON_BASE_NUM + vif)))
        {
            pending |= (1ul << vif);
        }
    }

    if (pending)
    {
        atomic_fetch_or(&driverd->beacon.pending_vif_mask, pending);
        driver_task_notify_event(driverd, DRV_EVT_BEACON_REQ_PEND);
    }
}

static int morse_beacon_set_irq_enabled(struct driver_data *driverd, uint16_t vif_id, bool enabled)
{
    uint8_t beacon_irq_num = MORSE_INT_BEACON_BASE_NUM + vif_id;

    int ret = morse_hw_irq_enable(driverd, beacon_irq_num, enabled);
    if (ret == 0)
    {
        MMLOG_DBG("Beacon IRQ %s for vif %u (mask=0x%08lx)\n",
                  enabled ? "enabled" : "disabled",
                  vif_id,
                  1ul << beacon_irq_num);
    }
    else
    {
        MMLOG_ERR("Failed to %s beacon IRQ (%d)\n", enabled ? "enable" : "disable", ret);
    }
    return ret;
}

static int morse_beacon_tx_one(struct driver_data *driverd, uint16_t vif_id)
{
    struct mmpkt *beacon = mmdrv_host_get_beacon(vif_id);
    if (beacon == NULL)
    {
        MMLOG_WRN("Failed to get beacon for vif %u\n", vif_id);
        return -MM_EINVAL;
    }

    struct morse_skbq *mq = driverd->cfg->ops->skbq_bcn_tc_q(driverd);
    if (!mq)
    {
        static bool error_message_displayed = false;
        if (!error_message_displayed)
        {
            MMLOG_ERR("Failed to find beacon mq\n");
            error_message_displayed = true;
        }

        return -MM_EINVAL;
    }

    return morse_skbq_mmpkt_tx(mq, beacon, MORSE_SKB_CHAN_BEACON);
}

static int morse_beacon_work_(struct driver_data *driverd)
{
    if (!driver_task_notification_check_and_clear(driverd, DRV_EVT_BEACON_REQ_PEND))
    {
        return 0;
    }

    /* Drain the vifs whose beacon IRQ fired; ignore any that stopped meanwhile. */
    uint32_t pending = atomic_exchange(&driverd->beacon.pending_vif_mask, 0);
    pending &= driverd->beacon.enabled_vif_mask;

    int result = 0;
    while (pending)
    {
        uint8_t vif = (uint8_t)__builtin_ctz(pending);
        pending &= (pending - 1);

        int ret = morse_beacon_tx_one(driverd, vif);
        if (ret != 0)
        {
            result = ret;
        }
    }

    return result;
}

int morse_beacon_start(struct driver_data *driverd, uint16_t vif_id)
{
    MMLOG_INF("Start beaconing on vif %u\n", vif_id);
    driverd->beacon.count = 0;
    driverd->beacon.enabled_vif_mask |= (uint8_t)(1u << vif_id);
    driverd->beacon.beacon_work_fn = morse_beacon_work_;

    /* Kick the first beacon for this vif (no IRQ has fired yet). */
    atomic_fetch_or(&driverd->beacon.pending_vif_mask, (1u << vif_id));
    driver_task_notify_event(driverd, DRV_EVT_BEACON_REQ_PEND);

    int ret = morse_beacon_set_irq_enabled(driverd, vif_id, true);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to start beaconing\n");
    }

    return ret;
}

int morse_beacon_stop(struct driver_data *driverd, uint16_t vif_id)
{
    int ret = 0;
    MMLOG_INF("Stop beaconing on vif %u\n", vif_id);
    if (driverd->beacon.enabled_vif_mask & (uint8_t)(1u << vif_id))
    {
        ret = morse_beacon_set_irq_enabled(driverd, vif_id, false);
        driverd->beacon.enabled_vif_mask &= (uint8_t)~(1u << vif_id);
        atomic_fetch_and(&driverd->beacon.pending_vif_mask, ~(1u << vif_id));
    }

    if (ret != 0)
    {
        MMLOG_WRN("Failed to stop beaconing\n");
    }

    return ret;
}

int morse_beacon_work(struct driver_data *driverd)
{

    if (driverd->beacon.beacon_work_fn != NULL)
    {
        return driverd->beacon.beacon_work_fn(driverd);
    }
    return -MM_EINVAL;
}
