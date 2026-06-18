/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_log.h"
#include "esp_netif.h"
#include "mmhalow.h"
#include <unistd.h>
#include "nvs_flash.h"

#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define WIFI_SSID CONFIG_WIFI_SSID
#define WIFI_PSK  CONFIG_WIFI_PSK
#define UDP_IP                  "192.168.12.1"
#define UDP_PORT                12345
#define WIFI_CONNECT_TIMEOUT_MS 10000

static const char *TAG = "sta_connect";

SemaphoreHandle_t sem = NULL;

static void connect_status_callback(enum mmwlan_sta_state sta_state)
{
    switch (sta_state)
    {
        case MMWLAN_STA_DISABLED:
            ESP_LOGI(TAG, "WLAN STA disabled");
            break;

        case MMWLAN_STA_CONNECTING:
            ESP_LOGI(TAG, "WLAN STA connecting");
            break;

        case MMWLAN_STA_CONNECTED:
            ESP_LOGI(TAG, "WLAN STA connected");
            xSemaphoreGive(sem);
            break;
    }
}

void udp_tx(void)
{
    const char *dst_ip = UDP_IP;
    const int dst_port = UDP_PORT;
    const char *msg = "Hello from esp32\n";

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        return;
    }

    struct sockaddr_in dest_addr = { 0 };
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dst_port);
    inet_pton(AF_INET, dst_ip, &dest_addr.sin_addr);

    ESP_LOGI(TAG, "Sending UDP packet to %s:%d", UDP_IP, UDP_PORT);
    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    close(sock);
}

void app_main(void)
{
    ESP_LOGI(TAG, "Booted. Initialising Wi-Fi HaLow Interface...");
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(esp_netif_init());
    mmhalow_init(NULL);
    ESP_LOGI(TAG, "Wi-Fi HaLow Interface Initialised");
    mmhalow_print_version_info();

    mmhalow_wifi_config_t conf = {
        .sta = MMWLAN_STA_ARGS_INIT,
    };

    memcpy(conf.sta.ssid, WIFI_SSID, strlen(WIFI_SSID));
    conf.sta.ssid_len = strlen(WIFI_SSID);

    memcpy(conf.sta.passphrase, WIFI_PSK, strlen(WIFI_PSK));
    conf.sta.passphrase_len = strlen(WIFI_PSK);

    conf.sta.security_type = MMWLAN_SAE;

    mmhalow_set_config(WIFI_IF_STA, &conf);
    ESP_LOGI(TAG, "Connecting to SSID: %s with PSK: %s", WIFI_SSID, WIFI_PSK);
    mmhalow_connect(connect_status_callback);

    sem = xSemaphoreCreateBinary();

    /* Wait 10s to connect to the AP */
    if (pdTRUE == xSemaphoreTake(sem, pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS)))
    {
        ESP_LOGI(TAG, "Connected successfully.");
        /* Give the system time to be ready before TX'ing data */
        sleep(2);
        udp_tx();
    }
    else
    {
        ESP_LOGE(TAG, "Unable to connected: Timed Out");
    }
}
