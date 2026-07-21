/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "umac/datapath/umac_datapath.h"
#include "dot11/dot11_frames.h"

#pragma once

MM_STATIC_ASSERT(sizeof(struct umac_8023_hdr) == 14, "Invalid 802.3 definition");
MM_STATIC_ASSERT(
    offsetof(struct umac_8023_hdr, ethertype_be) ==
        sizeof(struct umac_8023_hdr) - MM_MEMBER_SIZE(struct umac_8023_hdr, ethertype_be),
    "Ethernet Type must be the last field");


struct umac_datapath_ops
{

    void (*process_rx_mgmt_frame)(struct umac_data *umacd,
                                  struct umac_sta_data *stad,
                                  struct mmpktview *rxbufview);


    struct umac_sta_data *(*lookup_stad_by_peer_addr)(struct umac_data *umacd,
                                                      const uint8_t *peer_addr);


    struct umac_sta_data *(*lookup_stad_by_tx_dest_addr)(struct umac_data *umacd,
                                                         const uint8_t *dest_addr);


    struct umac_sta_data *(*lookup_stad_by_aid)(struct umac_data *umacd, uint16_t aid);


    bool (*update_stad_state_rx)(struct umac_sta_data *stad,
                                 const struct mmdrv_rx_metadata *metadata,
                                 uint16_t frame_control_le);


    bool (*is_stad_tx_paused)(struct umac_sta_data *stad);


    void (*enqueue_tx_frame)(struct umac_data *umacd,
                             struct umac_sta_data *stad,
                             struct mmpkt *txbuf);


    bool (*dequeue_tx_frame)(struct umac_data *umacd,
                             struct umac_sta_data **stad,
                             struct mmpkt **txbuf);


    void (*construct_80211_data_header)(struct umac_sta_data *stad,
                                        const struct umac_8023_hdr *hdr_8023,
                                        struct dot11_data_hdr *data_hdr);


    enum mmwlan_sta_state (*get_sta_state)(struct umac_sta_data *stad);


    void (*supp_l2_sock_receive)(struct umac_data *umacd,
                                 const uint8_t *payload,
                                 size_t payload_len,
                                 const uint8_t *src_addr);


    void (*handle_frame_unknown_sta)(struct umac_data *umacd, const uint8_t *ta);


    const uint16_t *frames_allowed_pre_association;


    const char *type;
};


/*
 * Per-vif 802.11 data-header builders, exposed so the common TX path can pick the
 * builder by the frame's egress vif TYPE when a mesh and a concurrent AP are up at
 * once (the single global data->ops can't serve both). Mirrors mac80211 selecting
 * the header format by sdata->vif.type.
 */
void umac_datapath_construct_80211_data_header_ap(struct umac_sta_data *stad,
                                                  const struct umac_8023_hdr *hdr_8023,
                                                  struct dot11_data_hdr *data_hdr);

void umac_datapath_construct_80211_data_header_mesh(struct umac_sta_data *stad,
                                                    const struct umac_8023_hdr *hdr_8023,
                                                    struct dot11_data_hdr *data_hdr);

/* AP RX mgmt handler, exposed so the gateway ops can route an AP-vif mgmt frame to it. */
void umac_datapath_process_rx_mgmt_frame_ap(struct umac_data *umacd,
                                            struct umac_sta_data *stad,
                                            struct mmpktview *rxbufview);


void umac_datapath_process_rx_action_frame(struct umac_data *umacd,
                                           struct umac_sta_data *stad,
                                           struct mmpktview *rxbufview);


enum mmwlan_status umac_datapath_wait_for_tx_ready_(struct umac_datapath_data *data,
                                                    uint32_t timeout_ms,
                                                    uint16_t mask);
