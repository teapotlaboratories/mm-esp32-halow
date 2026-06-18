# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(src "mmosal_shim_freertos_esp32.c"
	"mmhal_core.c"
	"mmhal_os.c"
	"mmhal_wlan_binaries.c"
	"mmhal_wlan.c"
	"crypto_mbedtls_mm.c"
)

# Define architecture specific paths and variables
if(${IDF_TARGET} STREQUAL "esp32s3")
	set(inc "include/esp32s3" ".")
elseif(${IDF_TARGET} STREQUAL "esp32c6")
	set(inc "include/esp32c6" ".")
elseif(${IDF_TARGET} STREQUAL "esp32c3")
	set(inc "include/esp32c3" ".")
else()
	message(FATAL_ERROR "Target ${IDF_TARGET} not known. Exiting...")
endif()

add_library(shims STATIC ${src})
target_include_directories(shims PUBLIC ${inc})
target_link_libraries(shims PUBLIC
	${MM_FIRMWARE_LIB}
	idf::log
	idf::driver
	idf::mbedtls
	idf::esp_timer
)

target_link_libraries(shims PUBLIC
	morselib
	mmutils
)

add_dependencies(shims morselib ${MM_FIRMWARE_LIB})

