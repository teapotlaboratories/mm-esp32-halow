/*
 * Copyright 2021 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */


#pragma once

#include "common/morse_error.h"
#include "driver/morse_driver/morse.h"


void morse_trns_init(void);


void morse_trns_deinit(void);


morse_error_t morse_trns_start(struct driver_data *driverd);


void morse_trns_stop(struct driver_data *driverd);


/* FIX-1 (bus-preserving hw_restart): the "soft" variants reset/quiesce the chip-facing state over the
 * EXISTING SPI2_HOST bus. morse_trns_soft_start = morse_trns_start MINUS mmhal_wlan_init (no
 * spi_bus_initialize / spi_bus_add_device / esp_intr_alloc); morse_trns_soft_stop = morse_trns_stop MINUS
 * the bus_lock/semb delete + mmhal_wlan_deinit (no spi_bus_free / esp_intr_free / gpio_isr_handler_remove).
 * Used only via mmdrv_soft_restart on a hw_restart; first-boot/shutdown keep using start/stop unchanged. */
morse_error_t morse_trns_soft_start(struct driver_data *driverd);


void morse_trns_soft_stop(struct driver_data *driverd);


void morse_trns_set_irq_enabled(struct driver_data *driverd, bool enabled);


void morse_trns_claim(struct driver_data *driverd);


void morse_trns_release(struct driver_data *driverd);


morse_error_t morse_trns_read_multi_byte(struct driver_data *driverd,
                                         uint32_t address,
                                         uint8_t *data,
                                         uint32_t len);


morse_error_t morse_trns_write_multi_byte(struct driver_data *driverd,
                                          uint32_t address,
                                          const uint8_t *data,
                                          uint32_t len);


morse_error_t morse_trns_read_le32(struct driver_data *driverd, uint32_t address, uint32_t *data);


morse_error_t morse_trns_write_le32(struct driver_data *driverd, uint32_t address, uint32_t data);


