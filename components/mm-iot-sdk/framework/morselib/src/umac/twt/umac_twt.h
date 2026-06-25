/*
 * Copyright 2023 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */



#pragma once

#include "mmwlan.h"
#include "mmdrv.h"
#include "umac/umac.h"
#include "umac/data/umac_data.h"
#include "common/morse_commands.h"
#include "umac/ies/ies_common.h"


#define MORSE_INT_CEIL(_num, _div) (((_num) + (_div) - 1) / (_div))


#define TWT_ENABLE_IMPLICIT (1)

#define TWT_WAKE_DURATION_UNIT (256)

#define TWT_WAKE_INTERVAL_EXPONENT_MAX_VAL (31)

/* Requester (STA) uses slot 0. Responder (AP) uses this as a per-STA agreement table:
 * one slot per associated STA that negotiated TWT, keyed by responder_peers[] (see
 * umac_twt_data.h). Sized to the AP's max-STA cap so every associable leaf can hold TWT
 * (mirrors Linux morse_driver, which keeps TWT per-STA); the responder logs and rejects
 * only if it ever overflows. ~46 B/slot, so the full table is ~1 KB. */
#define UMAC_TWT_NUM_AGREEMENTS MMWLAN_AP_MAX_STAS_LIMIT


enum umac_twt_cmd_type
{

    UMAC_TWT_CMD_TYPE_CONFIGURE,

    UMAC_TWT_CMD_TYPE_FORCE_INSTALL_AGREEMENT,

    UMAC_TWT_CMD_TYPE_REMOVE_AGREEMENT,

    UMAC_TWT_CMD_TYPE_CONFIGURE_EXPLICIT,
};


struct umac_twt_command
{

    enum umac_twt_cmd_type type;

    uint64_t target_wake_time;

    union
    {

        uint64_t wake_interval_us;


        struct
        {

            uint16_t wake_interval_mantissa;

            uint8_t wake_interval_exponent;
        } expl;
    };


    uint32_t min_wake_duration_us;

    uint8_t twt_setup_command;

    uint8_t flow_id;
};


struct MM_PACKED umac_twt_params
{

    uint16_t req_type;

    uint64_t twt;

    uint8_t min_twt_dur;

    uint16_t mantissa;

    uint8_t channel;
};


enum umac_twt_agreement_state
{

    UMAC_TWT_AGREEMENT_STATE_EMPTY,

    UMAC_TWT_AGREEMENT_STATE_PENDING_RESPONSE,

    UMAC_TWT_AGREEMENT_STATE_PENDING_INSTALLATION,

    UMAC_TWT_AGREEMENT_STATE_INSTALLED,
};


struct MM_PACKED umac_twt_agreement_data
{

    enum umac_twt_agreement_state state;

    uint64_t wake_time_us;

    uint64_t wake_interval_us;

    uint32_t wake_duration_us;

    uint8_t control;

    struct umac_twt_params params;
};


void umac_twt_init(struct umac_data *umacd);


void umac_twt_init_vif(struct umac_data *umacd, uint16_t *vif_id, bool is_responder);


void umac_twt_deinit_vif(struct umac_data *umacd, uint16_t *vif_id);


enum mmwlan_status umac_twt_handle_command(struct umac_data *umacd,
                                           const struct umac_twt_command *cmd);


struct umac_twt_agreement_data *umac_twt_get_agreement(struct umac_data *umacd, uint16_t flow_id);


enum mmwlan_status umac_twt_process_ie(struct umac_data *umacd, const struct dot11_ie_twt *twt_ie);


enum mmwlan_status umac_twt_install_pending_agreements(struct umac_data *umacd, bool is_reinstall);


/* --- TWT responder (AP), mirrors morse_driver's driver-level handling -----------
 * The AP parses a STA's TWT request from a received (re)assoc-request, accepts
 * REQUEST/SUGGEST (rejects DEMAND/GROUPING), inserts the accept IE into the
 * (re)assoc-response, and installs the agreement to firmware once the STA is
 * authorized. Per-STA: each TWT-requesting STA gets its own slot in agreements[]
 * keyed by responder_peers[] (up to UMAC_TWT_NUM_AGREEMENTS), freed on STA leave —
 * mirrors morse_driver keeping a per-STA agreement (Linux stores it on the sta). */

/* RX hook (assoc-req): parse + accept the STA's TWT request, stash the agreement. */
void umac_twt_responder_handle_assoc_req(struct umac_data *umacd,
                                         const uint8_t *frame, size_t frame_len);

/* TX hook (assoc-resp): if @frame is a (re)assoc-resp to the accepted STA, serialise
 * the responder TWT IE into @out (cap @out_cap); returns the IE length or 0. */
size_t umac_twt_responder_build_response_ie(struct umac_data *umacd,
                                            const uint8_t *frame, size_t frame_len,
                                            uint8_t *out, size_t out_cap);

/* Install hook (STA authorized): program the firmware with the accepted agreement. */
void umac_twt_responder_install(struct umac_data *umacd, const uint8_t *sta_addr);

/* STA-leave hook: free the agreement slot owned by @sta_addr (deauth/disassoc), so the
 * table does not leak slots as leaves come and go (mirrors Linux freeing the sta's TWT). */
void umac_twt_responder_free_agreement(struct umac_data *umacd, const uint8_t *sta_addr);

/* RX hook (S1G unprotected action frame from @stad): handle a TWT Teardown (free the
 * STA's agreement) — mirrors morse_driver morse_mac_process_rx_twt_mgmt for the
 * action-frame path. (Mid-session TWT Setup action frames are recognised but not yet
 * negotiated; the assoc-IE path covers the common requester flow.) */
void umac_twt_responder_handle_action(struct umac_data *umacd, struct umac_sta_data *stad,
                                      const uint8_t *frame, size_t frame_len);

/* TWT requester (STA): mid-session action-frame negotiation. _tx_setup TXes a TWT-Setup
 * REQUEST action for the pending agreement; _tx_teardown TXes a TWT-Teardown and frees the
 * local slot; _handle_action processes the AP's Setup-response (ACCEPT) and installs it.
 * The TX functions run on the umac task (queued from the public mmwlan_twt_* APIs). */
void umac_twt_requester_tx_setup(struct umac_data *umacd);
void umac_twt_requester_tx_teardown(struct umac_data *umacd);
void umac_twt_requester_handle_action(struct umac_data *umacd, const uint8_t *frame,
                                      size_t frame_len);


enum mmwlan_status umac_twt_add_configuration(struct umac_data *umacd,
                                              const struct mmwlan_twt_config_args *twt_config_args);


const struct mmwlan_twt_config_args *umac_twt_get_config(struct umac_data *umacd);


