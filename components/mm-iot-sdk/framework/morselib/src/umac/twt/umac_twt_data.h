/*
 * Copyright 2023 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#pragma once

#include "umac_twt.h"

struct umac_twt_data
{

    uint16_t vif_id;

    bool requester;

    bool responder;

    /* Responder (AP): the STA MAC that the pending/installed agreement in
     * agreements[0] belongs to (single-STA bench scope; Linux keeps a per-STA list). */
    uint8_t responder_peer[MMWLAN_MAC_ADDR_LEN];

    struct umac_twt_agreement_data agreements[UMAC_TWT_NUM_AGREEMENTS];

    struct mmwlan_twt_config_args twt_config;
};
