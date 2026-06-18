/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "halow.h"

extern SemaphoreHandle_t sem;
static const char *TAG = "dual_if-HaLow";

void halow_tx(void)
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
    while (true)
    {
        sleep(2);
        sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    }

    close(sock);
}

void connect_status_callback(enum mmwlan_sta_state sta_state)
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

void halow_init()
{
    mmhalow_init(NULL);
    ESP_LOGI(TAG, "Wi-Fi HaLow Interface Initialised");
    mmhalow_print_version_info();
}

bool halow_connect()
{
    mmhalow_wifi_config_t conf = {
        .sta = MMWLAN_STA_ARGS_INIT,
    };

    memcpy(conf.sta.ssid, HALOW_SSID, strlen(HALOW_SSID));
    conf.sta.ssid_len = strlen(HALOW_SSID);

    memcpy(conf.sta.passphrase, HALOW_PSK, strlen(HALOW_PSK));
    conf.sta.passphrase_len = strlen(HALOW_PSK);

    conf.sta.security_type = MMWLAN_SAE;

    mmhalow_set_config(WIFI_IF_STA, &conf);
    ESP_LOGI(TAG, "Connecting to SSID: %s with PSK: %s", HALOW_SSID, HALOW_PSK);

    mmhalow_connect(connect_status_callback);

    if (pdTRUE == xSemaphoreTake(sem, pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS)))
    {
        ESP_LOGI(TAG, "Connected successfully.");
        return true;
    }
    ESP_LOGE(TAG, "Unable to connect to HaLow AP");
    return false;
}
