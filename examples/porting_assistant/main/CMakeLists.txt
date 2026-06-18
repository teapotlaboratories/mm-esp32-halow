# Copyright 2026 Morse Micro
#
# SPDX-License-Identifier: Apache-2.0

idf_component_register(
    SRCS "porting_assistant.c"
         "sdio_spi.c"
         "test_os.c"
         "test_wlan_fw_bcf.c"
         "test_wlan_io.c"
         "chip_cfg.c"
    INCLUDE_DIRS "."
    REQUIRES halow nvs_flash esp_wifi
)
