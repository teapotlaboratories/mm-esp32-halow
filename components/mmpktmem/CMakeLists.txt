# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(ROOT_DIR ${MM_IOT_SDK}/framework/src/mmpktmem)

set(inc
    ${ROOT_DIR})
set(src
    ${ROOT_DIR}/mmpktmem_heap.c
)

add_compile_definitions(MMPKTMEM_TX_POOL_N_BLOCKS=CONFIG_MMPKTMEM_TX_POOL_N_BLOCKS)
add_compile_definitions(MMPKTMEM_RX_POOL_N_BLOCKS=CONFIG_MMPKTMEM_RX_POOL_N_BLOCKS)

add_library(mmpktmem STATIC ${src})
target_include_directories(mmpktmem PUBLIC ${inc})

add_dependencies(mmpktmem mmutils morselib)
target_link_libraries(mmpktmem PUBLIC mmutils morselib)
