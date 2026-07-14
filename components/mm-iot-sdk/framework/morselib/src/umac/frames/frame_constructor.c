/*
 * Copyright 2022-2024 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "frames_common.h"
#include "common/consbuf.h"
#include "mmlog.h"
#include "umac/datapath/umac_datapath.h"
#include "dot11/dot11.h"
#include "mmdrv.h"

static struct mmpkt *build_frame_with_class(struct umac_data *umacd, mgmt_frame_builder_t builder,
                                            void *params, uint8_t pkt_class)
{

    struct consbuf cbuf = CONSBUF_INIT_WITHOUT_BUF;
    builder(umacd, &cbuf, params);
    /* Reserve CCMP header headroom + MIC tailroom so a mesh frame that gets host-side CCMP-encrypted
     * (#P5: forwarded unicast / re-broadcast group / unicast PREP) has room to expand in place. Slack
     * is harmless for unencrypted frames (beacon, broadcast HWMP) and the FW HW-crypto path. */
    struct mmpkt *mmpkt = umac_datapath_alloc_raw_tx_mmpkt(
        pkt_class, DOT11_CCMP_HEADER_LEN, cbuf.offset + DOT11_CCMP_256_MIC_LEN);
    if (mmpkt == NULL)
    {
        MMLOG_WRN("Failed to allocate frame (len %lu, class %u)\n", cbuf.offset, pkt_class);
        return NULL;
    }
    struct mmpktview *view = mmpkt_open(mmpkt);
    consbuf_reinit_from_mmpkt(&cbuf, view);
    builder(umacd, &cbuf, params);
    uint8_t *ret = mmpkt_append(view, cbuf.offset);
    MMOSAL_ASSERT(ret != NULL);
    mmpkt_close(&view);
    return mmpkt;
}

struct mmpkt *build_mgmt_frame(struct umac_data *umacd, mgmt_frame_builder_t builder, void *params)
{
    return build_frame_with_class(umacd, builder, params, MMDRV_PKT_CLASS_MGMT);
}

/* S3 — build a forwarded mesh DATA frame on a per-TID data-path class (MMDRV_PKT_CLASS_DATA_TIDx)
 * rather than MMDRV_PKT_CLASS_MGMT, so the FW enqueues it on the aggregating per-TID data queue (the
 * mgmt queue never A-MPDUs; pageset.c:202). Same CCMP headroom/tailroom as build_mgmt_frame so the
 * forwarded unicast can be host SW-CCMP-encrypted in place. */
struct mmpkt *build_mesh_data_frame(struct umac_data *umacd, mgmt_frame_builder_t builder, void *params,
                                    uint8_t tid)
{
    return build_frame_with_class(umacd, builder, params, MMDRV_PKT_CLASS_DATA_TID0 + tid);
}
