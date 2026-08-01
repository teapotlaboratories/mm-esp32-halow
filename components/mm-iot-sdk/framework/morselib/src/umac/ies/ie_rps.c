/*
 * Copyright 2026 Robert Carey
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include <string.h>

#include "umac/ies/ie_rps.h"
#include "dot11/dot11.h"
#include "mmosal.h"

/*
 * RPS element encoder, ported from morse_driver `raw.c` (tag 1.17.8) -- the same tree and the same
 * revision the bench runs, so the bytes this produces can be diffed against a live Linux AP.
 *
 * Every constant below is transcribed from the Linux masks at raw.c:15-76 rather than re-derived
 * from the standard. That is deliberate: the point of a follow-Linux port is that a disagreement
 * with the reference is a porting bug, not an interpretation difference.
 */

#ifndef GENMASK16
/* Inclusive bit range, as the kernel's GENMASK does, narrowed to 16 bits. */
#define GENMASK16(h, l) ((uint16_t)((0xFFFFu << (l)) & (0xFFFFu >> (15 - (h)))))
#endif

#ifndef BIT
#define BIT(n) (1u << (n))
#endif

/* raw.c:15-16 */
#define RPS_RAW_CONTROL_TYPE_SHIFT          0
#define RPS_RAW_CONTROL_TYPE                GENMASK16(1, 0)

/* raw.c:33-38 -- indication flags in the RAW Control octet. */
#define RPS_RAW_CONTROL_START_IND           BIT(4)
#define RPS_RAW_CONTROL_GROUP_IND           BIT(5)
#define RPS_RAW_CONTROL_CHAN_IND            BIT(6)
#define RPS_RAW_CONTROL_PERIODIC_IND        BIT(7)

/* raw.c:47-48 -- slot definition flags. */
#define RPS_RAW_SLOT_DEF_FORMAT             BIT(0)
#define RPS_RAW_SLOT_CROSS_BOUNDARY         BIT(1)

/*
 * raw.c:50-51,53-54.
 *
 * ⚠ THESE ARE BIT COUNTS BEING USED AS SLOT-COUNT MAXIMA, AND THAT IS NOT A TRANSCRIPTION ERROR.
 * Linux assigns max_slots = IEEE80211_S1G_RPS_RAW_SLOT_NUM_{3,6}BITS (raw.c:318-325), i.e. 3 and 6
 * -- the *widths* of the slot-count field, not the field maxima 7 and 63. So the number of slots is
 * silently capped at 6 (format 0) or 3 (format 1) even though both `morse_cli` and hostapd advertise
 * a 1-63 range. Replicated verbatim: byte-fidelity with the reference is the whole point, and the
 * cap is observable on air. It is also a real constraint on any RAW schedule built on this stack.
 */
#define RPS_RAW_SLOT_NUM_3BITS              3
#define RPS_RAW_SLOT_NUM_6BITS              6

/* raw.c:56-57 -- slot duration field widths. */
#define RPS_RAW_SLOT_DUR_8BITS              8
#define RPS_RAW_SLOT_DUR_11BITS             11

/* raw.c:59-61 */
#define RPS_RAW_SLOT_DCOUNT_SHIFT           2
#define RPS_RAW_SLOT_DCOUNT_8               GENMASK16(9, 2)
#define RPS_RAW_SLOT_DCOUNT_11              GENMASK16(12, 2)

/*
 * raw.c:63-66. NOTE the 6-bit slot-count mask spans bit 16, which is outside the __le16 it is
 * OR'd into (raw.c:349-354). Harmless only because the count is capped at 6 above. Transcribed as
 * a 16-bit mask so the behaviour is identical, with the difference recorded rather than silently
 * "fixed" -- a port that widened it would diverge from the reference.
 */
#define RPS_RAW_SLOT_NUM_6_SHIFT            10
#define RPS_RAW_SLOT_NUM_3_SHIFT            13
#define RPS_RAW_SLOT_NUM_6                  GENMASK16(15, 10)
#define RPS_RAW_SLOT_NUM_3                  GENMASK16(15, 13)

/* raw.c:69-79 -- RAW Group, hierarchical AID addressing. */
#define RPS_RAW_GROUP_PAGE_IDX              GENMASK16(1, 0)
#define RPS_AID_BITS                        11
#define RPS_AID_END_BITS_SHIFT              (16 - 2 - RPS_AID_BITS)
#define RPS_RAW_GROUP_START_AID_SHIFT       2
#define RPS_RAW_GROUP_START_AID             GENMASK16(RPS_AID_BITS + 1, 2)
#define RPS_RAW_GROUP_END_AID_SHIFT         13
#define RPS_RAW_GROUP_END_AID               GENMASK16(RPS_AID_END_BITS_SHIFT + 12, 13)

/* raw.c:95,103 -- slot duration quantisation. Durations are 500 + 120k microseconds, nothing else. */
#define RPS_MIN_SLOT_DURATION_US            500
#define RPS_US_TO_CSLOT(x)                  (((x) - RPS_MIN_SLOT_DURATION_US) / 120)

/* raw.c:122 -- start time is carried in units of 2 TU (2048 us). */
#define RPS_US_TO_TWO_TU(x)                 ((x) / (1024 * 2))

/** GENERIC is the only RAW type this stage encodes (raw.c:58, enum value 0). */
#define RPS_RAW_TYPE_GENERIC                0

/** Sizes of the wire structures (raw.c:165-235), used by the size calculation. */
#define RPS_ASSIGNMENT_LEN                  3   /* raw_control(1) + slot_definition(2) */
#define RPS_START_TIME_LEN                  1
#define RPS_GROUP_LEN                       3
#define RPS_PERIODIC_LEN                    3

/** raw.c:303-306 -- a config is a PRAW iff its validity is non-zero. */
static bool rps_cfg_is_periodic(const struct ie_rps_config *config)
{
    return config->periodic.cur_validity != 0;
}

/**
 * Encode the RAW Slot Definition field.
 *
 * Port of `morse_raw_generate_slot_definition()` (raw.c:287-357), GENERIC branch only. Returns the
 * field in host order; the caller writes it little-endian.
 *
 * The format choice is Linux's, and its comment is worth preserving: "Give longer durations
 * preference over greater number of slots" (raw.c:316). Format 1 (11-bit duration, 3-bit count) is
 * selected only when the duration will not fit in 8 bits.
 */
static uint16_t rps_generate_slot_definition(struct ie_rps_config *config)
{
    uint16_t slot_def = 0;
    uint16_t cslot_max;
    uint8_t max_slots;
    uint32_t cslot;

    if (config->slot_definition.slot_duration_us < RPS_MIN_SLOT_DURATION_US)
    {
        /* raw.c:294-297: clamp up rather than underflow the unsigned subtraction in US_TO_CSLOT. */
        cslot = RPS_US_TO_CSLOT(RPS_MIN_SLOT_DURATION_US);
    }
    else
    {
        cslot = RPS_US_TO_CSLOT(config->slot_definition.slot_duration_us);
    }

    if (config->slot_definition.cross_slot_boundary)
    {
        slot_def |= RPS_RAW_SLOT_CROSS_BOUNDARY;
    }

    /* raw.c:318-325. The threshold is written against the 8-bit field's range, not a named max. */
    if (cslot > UINT8_MAX)
    {
        slot_def |= RPS_RAW_SLOT_DEF_FORMAT;
        cslot_max = (uint16_t)((1u << RPS_RAW_SLOT_DUR_11BITS) - 1);
        max_slots = RPS_RAW_SLOT_NUM_3BITS;
    }
    else
    {
        cslot_max = (uint16_t)((1u << RPS_RAW_SLOT_DUR_8BITS) - 1);
        max_slots = RPS_RAW_SLOT_NUM_6BITS;
    }

    /*
     * raw.c:329-333. The cap is written BACK into the caller's config, so a request for more slots
     * than the format allows permanently changes the configuration rather than just this element.
     * Replicated because it is the reference behaviour; harmless in practice only because capping
     * is idempotent, so the emitted bytes are the same either way.
     */
    if (config->slot_definition.num_slots > max_slots)
    {
        config->slot_definition.num_slots = max_slots;
    }

    if (cslot > cslot_max)
    {
        cslot = cslot_max;
    }

    if (slot_def & RPS_RAW_SLOT_DEF_FORMAT)
    {
        slot_def |= (uint16_t)((cslot << RPS_RAW_SLOT_DCOUNT_SHIFT) & RPS_RAW_SLOT_DCOUNT_11);
        slot_def |= (uint16_t)((config->slot_definition.num_slots << RPS_RAW_SLOT_NUM_3_SHIFT) &
                               RPS_RAW_SLOT_NUM_3);
    }
    else
    {
        slot_def |= (uint16_t)((cslot << RPS_RAW_SLOT_DCOUNT_SHIFT) & RPS_RAW_SLOT_DCOUNT_8);
        slot_def |= (uint16_t)((config->slot_definition.num_slots << RPS_RAW_SLOT_NUM_6_SHIFT) &
                               RPS_RAW_SLOT_NUM_6);
    }

    return slot_def;
}

/**
 * Exact encoded payload length for one GENERIC assignment.
 *
 * Port of `morse_raw_calc_rps_ie_size()` (raw.c:378-418) reduced to a single config. Linux's
 * comment on always including the group is preserved in behaviour: "While we could omit the RAW
 * group configuration if the same as the last RAW we will include it for simplicity" (raw.c:405).
 */
static uint8_t rps_calc_payload_len(const struct ie_rps_config *config)
{
    uint8_t size = 0;

    /* raw.c:401-403: the start time field is omitted entirely when the offset is zero. */
    if (config->start_time_us != 0)
    {
        size += RPS_START_TIME_LEN;
    }

    size += RPS_GROUP_LEN;

    if (rps_cfg_is_periodic(config))
    {
        size += RPS_PERIODIC_LEN;
    }

    size += RPS_ASSIGNMENT_LEN;

    return size;
}

void ie_rps_build(struct consbuf *buf, struct ie_rps_config *config)
{
    uint8_t element[IE_RPS_MAX_LEN];
    uint8_t *p = element;
    uint8_t raw_control;
    uint16_t slot_def;
    uint16_t raw_group12;
    uint8_t payload_len;

    MMOSAL_ASSERT(config != NULL);

    /*
     * Two-pass beacon discipline, copied from ie_s1g_tim_build() (s1g_tim.c:420-425).
     * build_frame_with_class() (frame_constructor.c:17-32) runs every beacon builder twice: once
     * with a NULL buffer to size the ALLOCATION, then again to fill it.
     *
     * The contract is an UPPER BOUND, not an equality. The frame's final length comes from pass
     * TWO -- `mmpkt_append(view, cbuf.offset)` at frame_constructor.c:32 -- so pass 1 only has to
     * be large enough. ie_s1g_tim_build proves it: it reserves 256 bytes and then writes at most
     * 45. Under-reserving is the dangerous direction; it would trip the live MMOSAL_ASSERT inside
     * consbuf_append() (consbuf.c:30), which expands to an infinite loop and hangs the AP task
     * rather than truncating the beacon.
     *
     * ⚠ Do NOT "balance" the passes by padding the element out to the reserved length. The bytes
     * after this element are hostapd's tail; padding would insert zeros between them and every
     * subsequent element would be parsed at the wrong offset.
     */
    if (consbuf_reserve(buf, 0) == NULL)
    {
        consbuf_reserve(buf, IE_RPS_MAX_LEN);
        return;
    }

    payload_len = rps_calc_payload_len(config);

    /*
     * Element ID and Length. Linux's builder emits payload only and leaves this to its caller
     * (dot11ah/ie.c:467-468); this builder is EID-framed to match its sibling ie_s1g_tim_build().
     */
    *p++ = DOT11_IE_S1G_RPS;
    *p++ = payload_len;

    /* raw.c:440-442: RAW type occupies bits 1:0 of RAW Control. */
    raw_control = (uint8_t)((RPS_RAW_TYPE_GENERIC << RPS_RAW_CONTROL_TYPE_SHIFT) &
                            RPS_RAW_CONTROL_TYPE);

    slot_def = rps_generate_slot_definition(config);

    /*
     * raw.c:456. GROUP_IND is set UNCONDITIONALLY -- not only when a group differs from the
     * previous assignment. The PSTA and RAFRAME option bits (raw.c:25-26,29-30) are dead code in
     * the reference: defined, never written. So RAW Control bits 3:2 are always zero here.
     */
    raw_control |= RPS_RAW_CONTROL_GROUP_IND;

    if (config->start_time_us != 0)
    {
        raw_control |= RPS_RAW_CONTROL_START_IND;
    }

    if (rps_cfg_is_periodic(config))
    {
        raw_control |= RPS_RAW_CONTROL_PERIODIC_IND;
    }

    /*
     * Field order on the wire is fixed by the assignment structure (raw.c:165-169): RAW Control,
     * then Slot Definition, then the optional fields in the order Start Time, Group, Channel,
     * Periodic. RAW Control is written first even though two of its bits are only known after the
     * optional fields have been decided, which is why they are computed above.
     */
    *p++ = raw_control;
    *p++ = (uint8_t)(slot_def & 0xFF);
    *p++ = (uint8_t)(slot_def >> 8);

    if (config->start_time_us != 0)
    {
        /* raw.c:450: units of 2 TU, measured from the end of the beacon carrying this element. */
        *p++ = (uint8_t)RPS_US_TO_TWO_TU(config->start_time_us);
    }

    /*
     * RAW Group, hierarchical AID addressing (raw.c:458-470). Page index is hard-zero in the
     * reference -- "Pages aren't used yet so always use zero" (raw.c:436-437).
     */
    raw_group12 = (uint16_t)(0u & RPS_RAW_GROUP_PAGE_IDX);
    raw_group12 |= (uint16_t)((config->start_aid << RPS_RAW_GROUP_START_AID_SHIFT) &
                              RPS_RAW_GROUP_START_AID);
    raw_group12 |= (uint16_t)((config->end_aid << RPS_RAW_GROUP_END_AID_SHIFT) &
                              RPS_RAW_GROUP_END_AID);

    *p++ = (uint8_t)(raw_group12 & 0xFF);
    *p++ = (uint8_t)(raw_group12 >> 8);
    /* raw.c:469: the top bits of End AID spill into the third group octet. */
    *p++ = (uint8_t)(config->end_aid >> RPS_AID_END_BITS_SHIFT);

    /* raw.c:472-474: the Channel Indication subfield is never emitted. */

    if (rps_cfg_is_periodic(config))
    {
        /* raw.c:478-480 */
        *p++ = config->periodic.periodicity;
        *p++ = config->periodic.cur_validity;
        *p++ = config->periodic.cur_start_offset;
    }

    /*
     * The length octet and the bytes actually written must agree, or the element is malformed on
     * air in a way no compiler check would catch. Linux asserts the same invariant after building
     * (raw.c:666,669).
     */
    MMOSAL_ASSERT((uint8_t)(p - element) == payload_len + 2);

    consbuf_append(buf, element, (uint32_t)(p - element));
}

#ifdef RIMBA_RAW_SELFTEST
/**
 * Build the reference RAW schedule through the real encoder, for the fixture's self-test.
 *
 * Named with the mmwlan_ prefix so it survives the library mangler's protected-symbol glob and is
 * callable from application code; compile-gated behind RIMBA_RAW_SELFTEST so it exists only in the fixture that asserts on it.
 *
 * The expected bytes deliberately live in the APPLICATION, not here. If this function returned both
 * the produced and the expected value the test would be comparing the encoder against itself and
 * would pass for any consistent-but-wrong encoding. The config below is the reference AP's schedule
 * -- one GENERIC assignment, AIDs 1-255, start_time 0, 2 slots of 10100 us -- so the bytes it
 * produces are the ones captured off air from a live Linux AP.
 *
 * @returns the number of bytes written, or 0 if @c out_len is too small.
 */
uint32_t mmwlan_rps_build_reference(uint8_t *out, uint32_t out_len)
{
    struct ie_rps_config config = {
        .start_time_us = 0,
        .start_aid = 1,
        .end_aid = 255,
        .slot_definition = {
            .cross_slot_boundary = false,
            .num_slots = 2,
            .slot_duration_us = 10100,
        },
        .periodic = { 0 },
    };

    if (out == NULL || out_len < IE_RPS_MAX_LEN)
    {
        return 0;
    }

    struct consbuf cbuf = CONSBUF_INIT_WITH_BUF(out, out_len);
    ie_rps_build(&cbuf, &config);
    return cbuf.offset;
}
#endif
