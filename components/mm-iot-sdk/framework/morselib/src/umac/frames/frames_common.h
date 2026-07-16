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

/* S3 — as build_mgmt_frame but allocates the frame on the per-TID data class (MMDRV_PKT_CLASS_DATA_TID0
 * + tid) so a forwarded mesh unicast lands on the aggregating data queue instead of the mgmt queue. */
struct mmpkt *build_mesh_data_frame(struct umac_data *umacd, mgmt_frame_builder_t builder, void *params,
                                    uint8_t tid);


bool frame_is_robust_mgmt(struct mmpktview *view);

/* Group-addressed Mesh/Multihop Action frame (mac80211 _ieee80211_is_group_privacy_action): exempt
 * from the unprotected-robust-mgmt RX drop (these are MGTK/group-privacy class, not BIP). */
bool frame_is_group_privacy_action(struct mmpktview *view);

/* Mesh/Multihop Action frame of any addressing (group OR unicast). Mesh peers are MFP=no, so mac80211
 * never drops their unprotected robust mesh actions (incl. the unicast PREP); use this to exempt them
 * from the unprotected-robust-mgmt RX drop. Broader than frame_is_group_privacy_action (no group-DA req). */
bool frame_is_mesh_action(struct mmpktview *view);


