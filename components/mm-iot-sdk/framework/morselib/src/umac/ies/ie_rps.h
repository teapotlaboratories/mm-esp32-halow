/*
 * Copyright 2026 Robert Carey
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#pragma once

#include "common/consbuf.h"

/**
 * RPS (RAW Parameter Set) element builder -- 802.11ah 9.4.2.191, Element ID 208.
 *
 * Ported from the Linux morse_driver reference implementation, `raw.c` at tag 1.17.8. The code map
 * (docs/mesh-ap/rimba-raw-code-map.md) carries the function-level anchors and every deliberate
 * divergence; the divergences are summarised here because they change how this is CALLED:
 *
 *  - Linux keeps a persistent kmalloc'd `rps_ie` buffer on the vif and regenerates it only when the
 *    config changes. This builder writes straight into the beacon's consbuf on every TBTT, so there
 *    is no cached element and no allocation.
 *  - Linux's builder emits the element PAYLOAD only; the caller adds Element ID and Length. This one
 *    emits the full element, matching its sibling `ie_s1g_tim_build()`.
 *  - Linux supports a list of configs (multiple RAW assignments in one element). This is one GENERIC
 *    assignment, which is the S1 scope.
 */

/** Slot definition for a RAW assignment. Mirrors `morse_raw_config.slot_definition` (raw.h:163-173). */
struct ie_rps_slot_definition
{
    /** Allow transmitting STAs to bleed into the next slot. */
    bool cross_slot_boundary;
    /** Number of slots in the RAW. Silently capped -- see ie_rps_build(). */
    uint16_t num_slots;
    /** Slot duration in microseconds. Quantised to 500 + 120k; capped per slot format. */
    uint32_t slot_duration_us;
};

/** Optional periodic (PRAW) parameters. Mirrors `morse_raw_config.periodic` (raw.h:176-193). */
struct ie_rps_periodic
{
    /** Validity in beacons. NON-ZERO IS WHAT MAKES THIS A PRAW (`morse_raw_cfg_is_periodic`). */
    uint8_t cur_validity;
    /** Period of the RAW in beacons. */
    uint8_t periodicity;
    /** Start offset in beacons. */
    uint8_t cur_start_offset;
};

/**
 * One RAW assignment. Mirrors the fields of `struct morse_raw_config` (raw.h:124-215) that the
 * element encoder actually reads -- the Linux struct additionally carries list heads, AID indices
 * and beacon-spreading state that belong to stages beyond this one.
 */
struct ie_rps_config
{
    /**
     * Start time from the END OF THE BEACON carrying this element -- not from the TBTT
     * (raw.c:176-179). Zero omits the field entirely and clears START_IND.
     */
    uint32_t start_time_us;
    /** First AID in the RAW group. */
    uint16_t start_aid;
    /** Last AID in the RAW group. */
    uint16_t end_aid;
    struct ie_rps_slot_definition slot_definition;
    struct ie_rps_periodic periodic;
};

/**
 * Append a complete RPS element (EID 208 + length + payload) to @c buf.
 *
 * @param buf     Destination. MUST tolerate the two-pass beacon-build discipline: on the sizing
 *                pass (`buf->buf == NULL`) this reserves the worst-case length rather than the
 *                exact one, exactly as `ie_s1g_tim_build()` does.
 * @param config  The RAW assignment to encode. NOT const: the slot-count cap is written back into
 *                it, replicating Linux (`raw.c:329-333`).
 *
 * Only GENERIC RAW is supported (the only type Linux's own size calculator accepts without
 * warning -- `raw.c:393-399`). The Channel Indication subfield is never emitted, matching Linux
 * ("channel indication subfield not supported", `raw.c:474`).
 */
void ie_rps_build(struct consbuf *buf, struct ie_rps_config *config);

/**
 * Worst-case encoded length of an RPS element, in bytes, including the EID and Length octets.
 *
 * This is what the sizing pass reserves. It is deliberately the maximum rather than the exact
 * size: over-reserving is safe (the frame allocator rounds up anyway and the beacon has ~200 bytes
 * of slack), whereas a sizing pass that disagreed with the fill pass by even one byte would trip
 * the MMOSAL_ASSERT inside consbuf_append() -- which is live in this build and expands to an
 * infinite loop, hanging the AP task rather than truncating the beacon.
 */
#define IE_RPS_MAX_LEN  (2 + 3 + 1 + 3 + 3)
