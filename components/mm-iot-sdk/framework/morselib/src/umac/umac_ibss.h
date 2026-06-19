/*
 * IBSS / ad-hoc support (RISK-01) — host-generated beacon hooks.
 *
 * EXPERIMENTAL Rimba addition, not part of the stock MorseMicro SDK. See
 * docs/worklog/2026-06-18-risk01-ibss-recon.md.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UMAC_IBSS_H
#define UMAC_IBSS_H

#include <stdbool.h>

struct umac_data;
struct mmpkt;

/** True once mmwlan_ibss_enable() has brought an ad-hoc interface up. */
bool umac_ibss_is_active(void);

/** Build the next host-generated IBSS beacon (called from the beacon worker via
 *  mmdrv_host_get_beacon when an IBSS is active). Returns NULL on failure. */
struct mmpkt *umac_ibss_get_beacon(struct umac_data *umacd);

#endif /* UMAC_IBSS_H */
