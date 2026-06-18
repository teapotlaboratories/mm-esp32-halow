# Copyright 2025-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(ROOT_DIR ${MM_IOT_SDK}/framework/src/mmregdb)

set(inc
    ${ROOT_DIR})
set(src
    ${ROOT_DIR}/mmregdb.c
)

add_library(regdb STATIC ${src})

if(CONFIG_WIFI_MORSE_AU_CHANNELISATION_2020)
  target_compile_definitions(regdb PRIVATE MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_2020)
elseif(CONFIG_WIFI_MORSE_AU_CHANNELISATION_2024)
  target_compile_definitions(regdb PRIVATE MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_2024)
else()
  target_compile_definitions(regdb PRIVATE MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_revmf)
endif()

target_include_directories(regdb PUBLIC ${inc})
add_dependencies(regdb shims morselib)
target_link_libraries(regdb PUBLIC shims morselib)
