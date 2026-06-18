/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "server.h"

static const char *TAG = "dual_if-AP";

esp_err_t root_get_handler(httpd_req_t *req)
{
    const char *resp = "Hello, world!\n"
                       "ESP32 SoftAP webserver is running.\n";
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

httpd_handle_t start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return NULL;
    }

    httpd_uri_t root = { .uri = "/",
                         .method = HTTP_GET,
                         .handler = root_get_handler,
                         .user_ctx = NULL };
    httpd_register_uri_handler(server, &root);

    ESP_LOGI(TAG, "HTTP server started");
    return server;
}

void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_data;

    if (event_base == WIFI_EVENT)
    {
        switch (event_id)
        {
            case WIFI_EVENT_AP_START:
                ESP_LOGI(TAG, "SoftAP started. Connect to SSID: %s", AP_SSID);
                ESP_LOGI(TAG, "Then browse: http://192.168.4.1/");
                break;
            case WIFI_EVENT_AP_STACONNECTED:
            {
                wifi_event_ap_staconnected_t *e = (wifi_event_ap_staconnected_t *)event_data;
                ESP_LOGI(TAG, "STA connected: %s, AID=%d", e->mac, e->aid);
                break;
            }
            case WIFI_EVENT_AP_STADISCONNECTED:
            {
                wifi_event_ap_stadisconnected_t *e = (wifi_event_ap_stadisconnected_t *)event_data;
                ESP_LOGI(TAG, "STA disconnected: %s, AID=%d", e->mac, e->aid);
                break;
            }
            default:
                break;
        }
    }
}

void wifi_init_softap(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Creates default AP netif with IP 192.168.4.1/24 and DHCP server enabled */
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    wifi_config_t wifi_config = { 0 };

    memcpy((char *)wifi_config.ap.ssid, AP_SSID, strlen(AP_SSID));
    wifi_config.ap.ssid_len = strlen(AP_SSID);

    if (strlen(AP_PASS) > 0)
    {
        memcpy((char *)wifi_config.ap.password, AP_PASS, strlen(AP_PASS));
        wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    }
    else
    {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    wifi_config.ap.channel = WIFI_CHANNEL;
    wifi_config.ap.max_connection = MAX_STA_CONN;
    wifi_config.ap.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG,
             "SoftAP configured: SSID=%s PASS=%s CH=%d",
             AP_SSID,
             (strlen(AP_PASS) ? AP_PASS : "<open>"),
             WIFI_CHANNEL);
}
