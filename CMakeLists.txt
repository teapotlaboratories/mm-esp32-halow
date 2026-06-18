# Copyright 2025 Robert Carey
# Copyright 2025-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(src "mmhalow.c")

set(inc ".")

set(reqs
	firmware
	esp_netif
	esp_wifi
)

idf_component_register(
	INCLUDE_DIRS
	${inc}
	SRCS
	${src}
	REQUIRES
	${reqs}
)

list(FIND reqs firmware _idx)
idf_component_get_property(_halow_reqs ${COMPONENT_NAME} __REQUIRES)
list(GET _halow_reqs ${_idx} _firmware)
get_property(MM_FIRMWARE_LIB TARGET ${_firmware} PROPERTY COMPONENT_LIB)

add_subdirectory(components)
add_dependencies(${COMPONENT_TARGET} mmpktmem shims mmutils morselib regdb)
target_link_libraries(${COMPONENT_TARGET} PUBLIC mmpktmem shims mmutils morselib regdb)
