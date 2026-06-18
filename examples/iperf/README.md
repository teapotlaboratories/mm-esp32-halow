<!--
Copyright 2026 Morse Micro

SPDX-License-Identifier: Apache-2.0
-->

# Iperf

## About
This sample is a half-and-half implementation of the ESP32 iperf and MM-IoT-SDK iperf tests.
We pull in the the iperf component from the registry and access it via the REPL.
We do not allow for Wi-Fi configuration by using the REPL. Instead you bake in your AP's
SSID and PSK using the KConfig parameters, similar to how MM-IoT-SDK uses config_store.

## Local Testing

Local testing using a XIAO ESP32-C3 shows that we need to use the USB_SERIAL_JTAG for console output rather than standard UART.

> CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y