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

#include "iperf_cmd.h"
#include "esp_console.h"

#define WIFI_SSID               CONFIG_WIFI_SSID
#define WIFI_PSK                CONFIG_WIFI_PSK
#define WIFI_CONNECT_TIMEOUT_MS 10000

static const char *TAG = "iperf";

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
    }
    else
    {
        ESP_LOGE(TAG, "Unable to connected: Timed Out");
        return;
    }

    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "iperf>";

#if CONFIG_ESP_CONSOLE_UART
    esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));
#elif CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    esp_console_dev_usb_serial_jtag_config_t usbjtag_config =
        ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&usbjtag_config, &repl_config, &repl));
#endif

    app_register_iperf_commands();

    printf("\n ==================================================\n");
    printf(" |       Steps to test WiFi throughput            |\n");
    printf(" |                                                |\n");
    printf(" |  1. Print 'help' to gain overview of commands  |\n");
    printf(" |  2. Run iperf to test UDP/TCP RX/TX throughput |\n");
    printf(" |                                                |\n");
    printf(" =================================================\n\n");

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
