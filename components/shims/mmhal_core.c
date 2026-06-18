/*
 * Copyright 2021-2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmhal_core.h"
#include "mmutils.h"

#include "sdkconfig.h"
#include "esp_random.h"

uint32_t mmhal_random_u32(uint32_t min, uint32_t max)
{
    /* Note: the below implementation does not guarantee a uniform distribution. */

    uint32_t random_value = esp_random();

    if (min == 0 && max == UINT32_MAX)
    {
        return random_value;
    }
    else
    {
        /* Calculate the range and shift required to fit within [min, max] */
        return (random_value % (max - min + 1)) + min;
    }
}

void mmhal_set_deep_sleep_veto(uint8_t veto_id)
{
    MM_UNUSED(veto_id);
}

void mmhal_clear_deep_sleep_veto(uint8_t veto_id)
{
    MM_UNUSED(veto_id);
}
