/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_http_server.h"

#define AP_SSID      "ESP32-HELLO"
#define AP_PASS      "hello1234" // >= 8 chars for WPA2
#define WIFI_CHANNEL 1
#define MAX_STA_CONN 4

void wifi_init_softap(void);
void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
httpd_handle_t start_webserver(void);
esp_err_t root_get_handler(httpd_req_t *req);
