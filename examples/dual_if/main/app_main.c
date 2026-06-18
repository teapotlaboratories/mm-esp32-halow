/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "server.h"
#include "halow.h"

SemaphoreHandle_t sem = NULL;

void app_main(void)
{
    // NVS is required by Wi-Fi
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    wifi_init_softap();
    start_webserver();

    sem = xSemaphoreCreateBinary();
    halow_init();
    if (halow_connect())
    {
        /* halow_tx is an infinite loop */
        halow_tx();
    }
}
