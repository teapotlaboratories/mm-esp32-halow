# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(ROOT_DIR ${MM_IOT_SDK}/framework/src/mmutils)

set(inc
    ${ROOT_DIR})
set(src
    ${ROOT_DIR}/mmutils_wlan.c
)

add_library(mmutils STATIC ${src})
add_dependencies(mmutils morselib)
target_link_libraries(mmutils INTERFACE morselib)
target_include_directories(mmutils INTERFACE ${inc})
