/*
 * Copyright 2022 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */



#pragma once

#include <stdint.h>

#include "mmpkt.h"
#include "common/mac_address.h"
#include "common/consbuf.h"
#include "dot11/dot11.h"
#include "umac/data/umac_data.h"


typedef void (*mgmt_frame_builder_t)(struct umac_data *umacd, struct consbuf *buf, void *params);


struct mmpkt *build_mgmt_frame(struct umac_data *umacd, mgmt_frame_builder_t builder, void *params);


bool frame_is_robust_mgmt(struct mmpktview *view);

/* Group-addressed Mesh/Multihop Action frame (mac80211 _ieee80211_is_group_privacy_action): exempt
 * from the unprotected-robust-mgmt RX drop (these are MGTK/group-privacy class, not BIP). */
bool frame_is_group_privacy_action(struct mmpktview *view);


