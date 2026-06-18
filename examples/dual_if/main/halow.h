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
#include "mmhalow.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define HALOW_SSID              CONFIG_HALOW_SSID
#define HALOW_PSK               CONFIG_HALOW_PSK
#define UDP_IP                  "192.168.12.1"
#define UDP_PORT                12345
#define WIFI_CONNECT_TIMEOUT_MS 10000

void halow_tx(void);
void connect_status_callback(enum mmwlan_sta_state sta_state);
void halow_init();
bool halow_connect();
