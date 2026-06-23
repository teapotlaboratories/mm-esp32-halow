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

    struct umac_twt_agreement_data agreements[UMAC_TWT_NUM_AGREEMENTS];

    /* Responder (AP): owner STA MAC for each agreement slot above (parallel to
     * agreements[]). responder_peers[i] is valid iff agreements[i].state != EMPTY.
     * Mirrors morse_driver keeping a per-STA agreement; a vif is either requester
     * or responder, so the requester (which only uses slot 0) leaves this unused. */
    uint8_t responder_peers[UMAC_TWT_NUM_AGREEMENTS][MMWLAN_MAC_ADDR_LEN];

    struct mmwlan_twt_config_args twt_config;
};
