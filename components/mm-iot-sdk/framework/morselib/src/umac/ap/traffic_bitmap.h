/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#pragma once

#include "common/common.h"


/*
 * 256 == four S1G TIM blocks (each block covers 64 AIDs). Was 64 (single
 * block) then 128 (two blocks). Raising this lets the AP support up to 255
 * associated STAs (AID 1..255 — also the ceiling of the public uint8_t
 * mmwlan_ap_args.max_stas field; 256+ would need widening that to uint16_t).
 * The S1G TIM partial-virtual-bitmap encoder in s1g_tim.c (ie_s1g_tim_build)
 * already emits multiple blocks generically, so only the bitmap storage size
 * and the PVB-length tripwire assert there change with it. Stays < 512 so all
 * AIDs remain in TIM page 0 (no page-slice handling needed), and the 5-bit
 * block-offset field (<=31) easily covers blocks 0..3.
 */
#define MAX_SUPPORTED_AID    256
#define S1G_BITMAP_SUBBLOCKS ((MAX_SUPPORTED_AID + 7) / 8)
MM_STATIC_ASSERT((MAX_SUPPORTED_AID >> 3) == S1G_BITMAP_SUBBLOCKS, "");


static bool aid_is_valid(uint16_t aid)
{
    return aid && aid < MAX_SUPPORTED_AID;
}


static inline void ap_traffic_bitmap_set_aid_bit(uint8_t *bitmap, uint16_t aid)
{
    MMOSAL_ASSERT(aid_is_valid(aid));
    uint8_t aid_octet = (aid >> 3);
    uint8_t aid_bit = BIT(aid & 0x07);
    MMOSAL_TASK_ENTER_CRITICAL();
    bitmap[aid_octet] |= aid_bit;
    MMOSAL_TASK_EXIT_CRITICAL();
}


static inline void ap_traffic_bitmap_clear_aid_bit(uint8_t *bitmap, uint16_t aid)
{
    MMOSAL_ASSERT(aid_is_valid(aid));
    uint8_t aid_octet = (aid >> 3);
    uint8_t aid_bit = BIT(aid & 0x07);
    MMOSAL_TASK_ENTER_CRITICAL();
    bitmap[aid_octet] &= ~aid_bit;
    MMOSAL_TASK_EXIT_CRITICAL();
}


static inline bool ap_traffic_bitmap_get_aid_bit(const uint8_t *bitmap, uint16_t aid)
{
    MMOSAL_ASSERT(aid_is_valid(aid));
    uint8_t aid_octet = (aid >> 3);
    uint8_t aid_bit = BIT(aid & 0x07);
    return bitmap[aid_octet] & aid_bit;
}
