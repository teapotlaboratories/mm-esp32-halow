/*
 * Copyright 2023 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "umac_twt.h"
#include "umac_twt_data.h"
#include "umac/config/umac_config.h"
#include "umac/connection/umac_connection.h"
#include "umac/interface/umac_interface.h"
#include "umac/ies/twt_ie.h"
#include "dot11/dot11.h"
#include "dot11/dot11_frames.h"
#include "umac/frames/action.h"
#include "umac/datapath/umac_datapath.h"
#include "mmlog.h"
#include <string.h>

/* S1G unprotected action codes for TWT (mirror Linux WLAN_S1G_TWT_SETUP/TEARDOWN). */
#define UMAC_S1G_ACTION_TWT_SETUP    (6)
#define UMAC_S1G_ACTION_TWT_TEARDOWN (7)

static uint32_t umac_twt_calculate_wake_duration(uint32_t wake_duration)
{

    return MORSE_INT_CEIL(wake_duration, TWT_WAKE_DURATION_UNIT);
}


static uint64_t umac_twt_calculate_wake_interval(uint16_t mantissa, int exponent)
{

    return ((uint64_t)mantissa << exponent);
}


static uint64_t umac_twt_calculate_wake_interval_fields(uint64_t wake_interval_us,
                                                        uint16_t *mantissa,
                                                        int *exponent)
{

    uint64_t m = wake_interval_us;
    int e = 0;

    while (m > UINT16_MAX)
    {

        e++;
        m >>= 1;
    }
    *exponent = e;
    *mantissa = (uint16_t)m;

    return umac_twt_calculate_wake_interval(m, e);
}

void umac_twt_init(struct umac_data *umacd)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    MM_UNUSED(data);
}

void umac_twt_init_vif(struct umac_data *umacd, uint16_t *vif_id, bool is_responder)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    data->vif_id = *vif_id;
    /* Mirror morse_driver morse_twt_init_vif (twt.c): an AP vif is the TWT
     * responder, a STA vif is the requester. (Requester has extra PS gating in
     * Linux; responder is default-on for AP when the fw supports it.) */
    data->requester = !is_responder;
    data->responder = is_responder;
}

void umac_twt_deinit_vif(struct umac_data *umacd, uint16_t *vif_id)
{
    MM_UNUSED(vif_id);

    struct umac_twt_data *data = umac_data_get_twt(umacd);

    memset(data, 0, sizeof(*data));
}


struct umac_twt_agreement_data *umac_twt_get_empty_agreement(struct umac_twt_data *data,
                                                             uint16_t *flow_id)
{
    int i;
    for (i = 0; i < UMAC_TWT_NUM_AGREEMENTS; i++)
    {
        if (data->agreements[i].state == UMAC_TWT_AGREEMENT_STATE_EMPTY)
        {
            *flow_id = i;
            return &data->agreements[i];
        }
    }

    return NULL;
}


static bool is_requestor_setup_cmd(uint8_t twt_setup_cmd)
{
    switch (twt_setup_cmd)
    {
        case DOT11_TWT_SETUP_CMD_REQUEST:
        case DOT11_TWT_SETUP_CMD_SUGGEST:
        case DOT11_TWT_SETUP_CMD_DEMAND:
        case DOT11_TWT_SETUP_CMD_GROUPING:
            return true;
            break;

        default:
            return false;
            break;
    }
}


static enum mmwlan_status umac_twt_handle_configure(struct umac_data *umacd,
                                                    const struct umac_twt_command *cmd)
{
    int ret;
    int exponent = 0;
    uint16_t mantissa = 0;
    uint16_t flow_id = 0;
    struct umac_twt_agreement_data *agreement;
    struct mmdrv_twt_data mmdrv_twt_data = { 0 };

    struct umac_twt_data *data = umac_data_get_twt(umacd);

    agreement = umac_twt_get_empty_agreement(data, &flow_id);
    if (agreement == NULL)
    {
        MMLOG_INF("No emtpy agreements for VIF: %d\n", data->vif_id);
        return MMWLAN_UNAVAILABLE;
    }

    if (cmd->type == UMAC_TWT_CMD_TYPE_CONFIGURE_EXPLICIT)
    {
        mantissa = cmd->expl.wake_interval_mantissa;
        exponent = cmd->expl.wake_interval_exponent;
        agreement->wake_interval_us = umac_twt_calculate_wake_interval(mantissa, exponent);
    }
    else
    {
        agreement->wake_interval_us =
            umac_twt_calculate_wake_interval_fields(cmd->wake_interval_us, &mantissa, &exponent);
    }

    agreement->params.mantissa = mantissa;
    uint32_t min_twt_dur = umac_twt_calculate_wake_duration(cmd->min_wake_duration_us);
    if (min_twt_dur > UINT8_MAX)
    {
        MMLOG_INF("Requested minimum TWT duration %dus too large. Restricting to %dus\n",
                  cmd->min_wake_duration_us,
                  UINT8_MAX * TWT_WAKE_DURATION_UNIT);
        min_twt_dur = UINT8_MAX;
    }
    agreement->params.min_twt_dur = min_twt_dur;

    DOT11_TWT_REQUEST_TYPE_FIELD_SET_IMPLICIT(agreement->params.req_type, TWT_ENABLE_IMPLICIT);
    DOT11_TWT_REQUEST_TYPE_FIELD_SET_FLOW_IDENTIFIER(agreement->params.req_type, flow_id);
    DOT11_TWT_REQUEST_TYPE_FIELD_SET_WAKE_INTERVAL_EXP(agreement->params.req_type, exponent);

    MMOSAL_ASSERT(data->requester);
    if (!is_requestor_setup_cmd(cmd->twt_setup_command))
    {
        MMLOG_WRN("TWT requester trying to send response\n");
        return MMWLAN_INVALID_ARGUMENT;
    }

    DOT11_TWT_REQUEST_TYPE_FIELD_SET_REQUEST(agreement->params.req_type, 1);
    DOT11_TWT_REQUEST_TYPE_FIELD_SET_SETUP_COMMAND(agreement->params.req_type,
                                                   cmd->twt_setup_command);


    mmdrv_twt_data.interface_id = data->vif_id;
    mmdrv_twt_data.flow_id = flow_id;
    mmdrv_twt_data.agreement = &agreement->control;
    mmdrv_twt_data.agreement_len = (sizeof(agreement->control) + sizeof(agreement->params));

    ret = mmdrv_twt_agreement_validate_req(&mmdrv_twt_data);

    if (ret)
    {
        MMLOG_WRN("TWT req invalid\n");
        agreement->state = UMAC_TWT_AGREEMENT_STATE_EMPTY;
        return MMWLAN_ERROR;
    }

    agreement->state = UMAC_TWT_AGREEMENT_STATE_PENDING_RESPONSE;
    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_twt_handle_command(struct umac_data *umacd,
                                           const struct umac_twt_command *cmd)
{
    enum mmwlan_status status = MMWLAN_ERROR;

    switch (cmd->type)
    {
        case UMAC_TWT_CMD_TYPE_CONFIGURE:
        case UMAC_TWT_CMD_TYPE_CONFIGURE_EXPLICIT:
            status = umac_twt_handle_configure(umacd, cmd);
            break;

        case UMAC_TWT_CMD_TYPE_FORCE_INSTALL_AGREEMENT:
        case UMAC_TWT_CMD_TYPE_REMOVE_AGREEMENT:
            MMLOG_INF("Command type currently unsupported\n");
            status = MMWLAN_INVALID_ARGUMENT;
            break;

        default:
            MMLOG_DBG("Unrecognised command\n");
            status = MMWLAN_ERROR;
            break;
    }

    return status;
}

struct umac_twt_agreement_data *umac_twt_get_agreement(struct umac_data *umacd, uint16_t flow_id)
{
    if (flow_id >= UMAC_TWT_NUM_AGREEMENTS)
    {
        return NULL;
    }

    struct umac_twt_data *data = umac_data_get_twt(umacd);

    if (data->agreements[flow_id].state == UMAC_TWT_AGREEMENT_STATE_EMPTY)
    {
        return NULL;
    }

    return &data->agreements[flow_id];
}

enum mmwlan_status umac_twt_process_ie(struct umac_data *umacd, const struct dot11_ie_twt *twt_ie)
{
    struct umac_twt_agreement_data *agreement = NULL;
    uint16_t flow_id = 0;

    if (dot11_twt_request_type_field_get_setup_command(twt_ie->request_type) !=
        DOT11_TWT_SETUP_CMD_ACCEPT)
    {
        MMLOG_WRN("TWT negotiation not accepted\n");
        return MMWLAN_ERROR;
    }

    flow_id = dot11_twt_request_type_field_get_flow_identifier(twt_ie->request_type);
    agreement = umac_twt_get_agreement(umacd, flow_id);
    if (agreement == NULL)
    {
        MMLOG_WRN("TWT agreement not found for flow id: %u\n", flow_id);
        return MMWLAN_ERROR;
    }


    if (dot11_twt_control_field_get_negotiation_type(twt_ie->control) ||
        dot11_twt_control_field_get_ndp_paging_indicator(twt_ie->control))
    {
        MMLOG_WRN("Unsupported TWT control options\n");
        return MMWLAN_UNAVAILABLE;
    }

    if (dot11_twt_request_type_field_get_flow_type(twt_ie->request_type) ||
        !dot11_twt_request_type_field_get_implicit(twt_ie->request_type) ||
        dot11_twt_request_type_field_get_protection(twt_ie->request_type))
    {
        MMLOG_WRN("Unsupported TWT request type options\n");
        return MMWLAN_UNAVAILABLE;
    }

    if (twt_ie->channel > 0)
    {
        MMLOG_WRN("Unsupported TWT channel\n");
        return MMWLAN_UNAVAILABLE;
    }


    if (dot11_twt_request_type_field_get_setup_command(agreement->params.req_type) ==
        DOT11_TWT_SETUP_CMD_SUGGEST)
    {
        agreement->params.twt = twt_ie->twt;
    }

    agreement->state = UMAC_TWT_AGREEMENT_STATE_PENDING_INSTALLATION;
    return MMWLAN_SUCCESS;
}


static int umac_twt_install_agreement(struct umac_twt_data *data,
                                      uint16_t flow_id,
                                      const struct umac_twt_agreement_data *agreement)
{
    int ret = 0;
    struct mmdrv_twt_data mmdrv_twt_data = { 0 };


    mmdrv_twt_data.interface_id = data->vif_id;
    mmdrv_twt_data.flow_id = flow_id;
    mmdrv_twt_data.agreement = &agreement->control;
    mmdrv_twt_data.agreement_len = (sizeof(agreement->control) + sizeof(agreement->params));

    ret = mmdrv_twt_agreement_install_req(&mmdrv_twt_data);
    if (ret != 0)
    {
        MMLOG_WRN("TWT agreement %u installation failed (ret=%d)\n", flow_id, ret);
    }
    return ret;
}

enum mmwlan_status umac_twt_install_pending_agreements(struct umac_data *umacd, bool is_reinstall)
{
    int ret = 0;
    uint16_t i;
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    struct umac_twt_agreement_data *agreement;

    for (i = 0; i < UMAC_TWT_NUM_AGREEMENTS; i++)
    {
        agreement = &data->agreements[i];
        if ((agreement->state == UMAC_TWT_AGREEMENT_STATE_PENDING_INSTALLATION) ||
            (is_reinstall && (agreement->state == UMAC_TWT_AGREEMENT_STATE_INSTALLED)))
        {
            ret = umac_twt_install_agreement(data, i, agreement);
            if (ret != 0)
            {
                return MMWLAN_ERROR;
            }
            agreement->state = UMAC_TWT_AGREEMENT_STATE_INSTALLED;
        }
    }

    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_twt_add_configuration(struct umac_data *umacd,
                                              const struct mmwlan_twt_config_args *twt_config_args)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);

    memcpy(&data->twt_config, twt_config_args, sizeof(*twt_config_args));

    if (data->twt_config.twt_wake_interval_mantissa || data->twt_config.twt_wake_interval_exponent)
    {
        data->twt_config.twt_wake_interval_us =
            umac_twt_calculate_wake_interval(data->twt_config.twt_wake_interval_mantissa,
                                             data->twt_config.twt_wake_interval_exponent);
    }

    return MMWLAN_SUCCESS;
}

const struct mmwlan_twt_config_args *umac_twt_get_config(struct umac_data *umacd)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);

    return &data->twt_config;
}

/* --- TWT responder (AP) — mirrors morse_driver's driver-level handling --------- */

/* Return the IE section of a received (re)assoc-request and the transmitter (addr2),
 * or NULL if @frame is not a (re)assoc-request. */
static const uint8_t *umac_twt_assoc_req_ies(const uint8_t *frame, size_t frame_len,
                                             const uint8_t **sa, size_t *ies_len)
{
    if (frame == NULL || frame_len < sizeof(struct dot11_hdr))
    {
        return NULL;
    }
    const struct dot11_hdr *hdr = (const struct dot11_hdr *)frame;
    if (dot11_frame_control_get_type(hdr->frame_control) != DOT11_FC_TYPE_MGMT)
    {
        return NULL;
    }
    /* assoc-req: hdr + capability(2) + listen_interval(2). reassoc-req: + current_ap(6). */
    size_t fixed;
    switch (dot11_frame_control_get_subtype(hdr->frame_control))
    {
        case DOT11_FC_SUBTYPE_ASSOC_REQ:   fixed = sizeof(*hdr) + 4;     break;
        case DOT11_FC_SUBTYPE_REASSOC_REQ: fixed = sizeof(*hdr) + 4 + 6; break;
        default:                           return NULL;
    }
    if (frame_len <= fixed)
    {
        return NULL;
    }
    *sa = hdr->addr2;
    *ies_len = frame_len - fixed;
    return frame + fixed;
}

/* Find the responder agreement slot owned by @addr, or -1. A slot is owned iff it is
 * non-EMPTY and its responder_peers[] entry matches @addr. */
static int umac_twt_responder_slot_for_peer(struct umac_twt_data *data, const uint8_t *addr)
{
    int i;
    for (i = 0; i < UMAC_TWT_NUM_AGREEMENTS; i++)
    {
        if (data->agreements[i].state != UMAC_TWT_AGREEMENT_STATE_EMPTY &&
            memcmp(data->responder_peers[i], addr, MMWLAN_MAC_ADDR_LEN) == 0)
        {
            return i;
        }
    }
    return -1;
}

/* Pick a slot for @sa: reuse the STA's existing slot (re-negotiation) if it has one,
 * else the first EMPTY slot; -1 if the table is full. */
static int umac_twt_responder_alloc_slot(struct umac_twt_data *data, const uint8_t *sa)
{
    int i = umac_twt_responder_slot_for_peer(data, sa);
    if (i >= 0)
    {
        return i;
    }
    for (i = 0; i < UMAC_TWT_NUM_AGREEMENTS; i++)
    {
        if (data->agreements[i].state == UMAC_TWT_AGREEMENT_STATE_EMPTY)
        {
            return i;
        }
    }
    return -1;
}

/* Fill a dot11_ie_twt from a stored (already ACCEPT-form) agreement. */
static void umac_twt_responder_fill_ie(const struct umac_twt_agreement_data *agr,
                                       struct dot11_ie_twt *ie)
{
    memset(ie, 0, sizeof(*ie));
    ie->header.element_id = DOT11_IE_TWT;
    ie->header.length     = sizeof(*ie) - sizeof(ie->header);
    ie->control           = agr->control;
    ie->request_type      = agr->params.req_type;
    ie->twt               = agr->params.twt;
    ie->min_twt_duration  = agr->params.min_twt_dur;
    ie->mantissa          = agr->params.mantissa;
    ie->channel           = agr->params.channel;
}

/* Apply the accept policy to a received TWT request IE from @sa and, if accepted,
 * allocate/refresh that STA's slot in ACCEPT form. Returns the slot index, or -1 if
 * rejected (DEMAND/GROUPING) or the table is full. Shared by the assoc-IE path and the
 * mid-session TWT-Setup action-frame path. */
static int umac_twt_responder_accept_ie(struct umac_twt_data *data,
                                        const struct dot11_ie_twt *twt_ie, const uint8_t *sa)
{
    /* Accept REQUEST and SUGGEST; reject DEMAND and GROUPING (mirror
     * morse_twt_enter_state_consider_*). */
    uint16_t setup_cmd = dot11_twt_request_type_field_get_setup_command(twt_ie->request_type);
    if (setup_cmd != DOT11_TWT_SETUP_CMD_REQUEST && setup_cmd != DOT11_TWT_SETUP_CMD_SUGGEST)
    {
        MMLOG_INF("TWT responder: setup_cmd %u not REQUEST/SUGGEST, rejecting\n", setup_cmd);
        return -1;
    }

    /* Reuse the STA's slot on re-negotiation, else a free one; -1 if the table is full. */
    int slot = umac_twt_responder_alloc_slot(data, sa);
    if (slot < 0)
    {
        MMLOG_WRN("TWT responder: agreement table full (%u slots), rejecting "
                  "%02x:%02x:%02x:%02x:%02x:%02x\n", UMAC_TWT_NUM_AGREEMENTS,
                  sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
        return -1;
    }

    /* Build the accepted agreement: copy the request params as-is, set setup_cmd=ACCEPT
     * and clear the request bit (mirror morse_twt_send_accept -> morse_twt_set_command).
     * The ACCEPT-form agreement feeds both the response IE and the firmware install. */
    struct umac_twt_agreement_data *agr = &data->agreements[slot];
    memset(agr, 0, sizeof(*agr));
    agr->control            = twt_ie->control;
    agr->params.req_type    = twt_ie->request_type;
    agr->params.twt         = twt_ie->twt;
    agr->params.min_twt_dur = twt_ie->min_twt_duration;
    agr->params.mantissa    = twt_ie->mantissa;
    agr->params.channel     = twt_ie->channel;
    DOT11_TWT_REQUEST_TYPE_FIELD_SET_REQUEST(agr->params.req_type, 0);
    DOT11_TWT_REQUEST_TYPE_FIELD_SET_SETUP_COMMAND(agr->params.req_type,
                                                   DOT11_TWT_SETUP_CMD_ACCEPT);
    agr->state = UMAC_TWT_AGREEMENT_STATE_PENDING_INSTALLATION;
    memcpy(data->responder_peers[slot], sa, MMWLAN_MAC_ADDR_LEN);
    MMLOG_INF("TWT responder: accepted agreement (slot %d) for "
              "%02x:%02x:%02x:%02x:%02x:%02x\n", slot,
              sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
    return slot;
}

void umac_twt_responder_handle_assoc_req(struct umac_data *umacd,
                                         const uint8_t *frame, size_t frame_len)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    if (!data->responder)
    {
        return;
    }

    const uint8_t *sa = NULL;
    size_t ies_len = 0;
    const uint8_t *ies = umac_twt_assoc_req_ies(frame, frame_len, &sa, &ies_len);
    if (ies == NULL)
    {
        return;
    }

    const struct dot11_ie_twt *twt_ie = ie_twt_find(ies, ies_len);
    if (twt_ie == NULL)
    {
        return;
    }

    /* Accept + stash the agreement; the ACCEPT IE is spliced into the assoc-response
     * later by umac_twt_responder_build_response_ie. */
    (void)umac_twt_responder_accept_ie(data, twt_ie, sa);
}

size_t umac_twt_responder_build_response_ie(struct umac_data *umacd,
                                            const uint8_t *frame, size_t frame_len,
                                            uint8_t *out, size_t out_cap)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    if (!data->responder || frame == NULL || frame_len < sizeof(struct dot11_hdr))
    {
        return 0;
    }

    /* Only a (re)assoc-response addressed to the STA we accepted gets the IE. */
    const struct dot11_hdr *hdr = (const struct dot11_hdr *)frame;
    if (dot11_frame_control_get_type(hdr->frame_control) != DOT11_FC_TYPE_MGMT)
    {
        return 0;
    }
    uint16_t subtype = dot11_frame_control_get_subtype(hdr->frame_control);
    if (subtype != DOT11_FC_SUBTYPE_ASSOC_RSP && subtype != DOT11_FC_SUBTYPE_REASSOC_RSP)
    {
        return 0;
    }

    /* Find the agreement for the STA this (re)assoc-response is addressed to (addr1). */
    int slot = umac_twt_responder_slot_for_peer(data, hdr->addr1);
    if (slot < 0 || out_cap < sizeof(struct dot11_ie_twt))
    {
        return 0;
    }
    struct umac_twt_agreement_data *agr = &data->agreements[slot];
    if (agr->state != UMAC_TWT_AGREEMENT_STATE_PENDING_INSTALLATION)
    {
        return 0;
    }

    /* The stored agreement is already ACCEPT-form, so the IE carries setup_cmd=ACCEPT
     * to the STA — same agreement as the firmware install. */
    umac_twt_responder_fill_ie(agr, (struct dot11_ie_twt *)out);
    MMLOG_INF("TWT responder: inserting accept IE into assoc-resp\n");
    return sizeof(struct dot11_ie_twt);
}

void umac_twt_responder_install(struct umac_data *umacd, const uint8_t *sta_addr)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    if (!data->responder)
    {
        return;
    }
    int slot = umac_twt_responder_slot_for_peer(data, sta_addr);
    if (slot < 0 ||
        data->agreements[slot].state != UMAC_TWT_AGREEMENT_STATE_PENDING_INSTALLATION)
    {
        return;
    }
    struct umac_twt_agreement_data *agr = &data->agreements[slot];
    /* Try to install the agreement to the firmware (MORSE_CMD_ID_TWT_AGREEMENT_INSTALL).
     * NOTE: the embedded mm6108 firmware (verified 1.17.6 AND 1.17.8 .mbin) gates cmd 0x26
     * to interface_type==STA and returns 0xffff8000 for an AP vif — so this fails on an AP.
     * That is HARMLESS and EXPECTED: the firmware install would let the firmware schedule
     * the SP, but the responder does not need it. AP-side serving is done host-side — the
     * AP buffers the dozing STA's downlink (umac_ap PS path) and flushes it when the STA
     * wakes at its SP (the flush-on-wake in umac_ap_set_stad_sleep_state). So TWT leaf
     * power-save works on this firmware *without* the firmware install. (This mirrors the
     * Linux driver, whose firmware install is gated the same way; it also serves host-side.)
     * Install only THIS STA's slot (not the bulk installer) so multi-STA slots are independent. */
    (void)umac_twt_install_agreement(data, slot, agr);
    /* Mark the agreement installed regardless: host-side serving is what delivers traffic. */
    agr->state = UMAC_TWT_AGREEMENT_STATE_INSTALLED;
}

void umac_twt_responder_free_agreement(struct umac_data *umacd, const uint8_t *sta_addr)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    if (!data->responder)
    {
        return;
    }
    int slot = umac_twt_responder_slot_for_peer(data, sta_addr);
    if (slot < 0)
    {
        return;
    }
    /* Only free a fully-INSTALLED agreement. hostapd calls sta_remove transiently during
     * (re)association cleanup, when the slot is still PENDING_INSTALLATION (just accepted by
     * handle_assoc_req, assoc-response not yet built). Freeing it then would drop the ACCEPT
     * IE and the STA would never establish TWT. A real departure happens post-authorization,
     * when the slot is INSTALLED — that is the only case we free. */
    if (data->agreements[slot].state != UMAC_TWT_AGREEMENT_STATE_INSTALLED)
    {
        return;
    }
    /* state EMPTY is enum value 0, so the memset frees the slot. */
    memset(&data->agreements[slot], 0, sizeof(data->agreements[slot]));
    memset(data->responder_peers[slot], 0, MMWLAN_MAC_ADDR_LEN);
    MMLOG_INF("TWT responder: freed agreement slot %d for "
              "%02x:%02x:%02x:%02x:%02x:%02x\n", slot,
              sta_addr[0], sta_addr[1], sta_addr[2], sta_addr[3], sta_addr[4], sta_addr[5]);
}

/* Build and TX a TWT Setup response action frame carrying the ACCEPT IE for @slot back
 * to @stad (mid-session negotiation, mirroring morse_mac_send_twt_action_frame). */
static void umac_twt_responder_tx_setup_response(struct umac_data *umacd,
                                                 struct umac_sta_data *stad,
                                                 uint8_t dialog_token, int slot)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    /* Action body: [category][action][dialog_token][TWT IE]. */
    uint8_t buf[3 + sizeof(struct dot11_ie_twt)];
    buf[0] = DOT11_ACTION_CATEGORY_S1G_UNPROTECTED;
    buf[1] = UMAC_S1G_ACTION_TWT_SETUP;
    buf[2] = dialog_token;
    umac_twt_responder_fill_ie(&data->agreements[slot], (struct dot11_ie_twt *)&buf[3]);

    struct frame_data_action params = {
        .bssid            = umac_sta_data_peek_bssid(stad),
        .dst_address      = umac_sta_data_peek_peer_addr(stad),
        .src_address      = umac_interface_peek_mac_addr(stad),
        .action_field     = buf,
        .action_field_len = sizeof(buf),
    };
    enum mmwlan_status st =
        umac_datapath_build_and_tx_mgmt_frame(stad, frame_action_build, &params);
    if (st != MMWLAN_SUCCESS)
    {
        MMLOG_WRN("TWT responder: setup-response TX failed (%d)\n", st);
        return;
    }
    /* No AUTHORIZED event mid-session, so install + mark INSTALLED here (fw install is
     * gated off on an AP vif; host-side serving delivers traffic — same as the assoc
     * path's responder_install). */
    (void)umac_twt_install_agreement(data, slot, &data->agreements[slot]);
    data->agreements[slot].state = UMAC_TWT_AGREEMENT_STATE_INSTALLED;
    MMLOG_INF("TWT responder: sent TWT Setup ACCEPT (slot %d)\n", slot);
}

void umac_twt_responder_handle_action(struct umac_data *umacd, struct umac_sta_data *stad,
                                      const uint8_t *frame, size_t frame_len)
{
    struct umac_twt_data *data = umac_data_get_twt(umacd);
    if (!data->responder || stad == NULL || frame == NULL)
    {
        return;
    }
    const struct dot11_action *act = (const struct dot11_action *)frame;
    /* Need at least the fixed header + category + action_code. */
    if (frame_len < sizeof(*act) + 1 ||
        act->field.category != DOT11_ACTION_CATEGORY_S1G_UNPROTECTED)
    {
        return;
    }
    uint8_t action_code = act->field.action_details[0];
    const uint8_t *addr = umac_sta_data_peek_peer_addr(stad);
    if (addr == NULL)
    {
        return;
    }

    switch (action_code)
    {
        case UMAC_S1G_ACTION_TWT_TEARDOWN:
            /* Explicit teardown: free this STA's agreement. The per-STA table holds one
             * agreement per STA, so the teardown flow id is implicit (mirror morse_driver
             * morse_mac_process_rx_twt_mgmt, which removes the agreement on teardown). */
            MMLOG_INF("TWT responder: teardown action from "
                      "%02x:%02x:%02x:%02x:%02x:%02x\n",
                      addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
            umac_twt_responder_free_agreement(umacd, addr);
            break;

        case UMAC_S1G_ACTION_TWT_SETUP:
        {
            /* Mid-session setup: [category][action][dialog_token][TWT IE]. Accept it like
             * the assoc-IE path, then TX a TWT Setup response action frame with the ACCEPT
             * IE (mirror morse_mac_process_rx_twt_mgmt + morse_mac_send_twt_action_frame). */
            const uint8_t *details = act->field.action_details;
            if (frame_len < sizeof(*act) + 2 + sizeof(struct dot11_ie_twt))
            {
                MMLOG_WRN("TWT responder: setup action frame too short\n");
                break;
            }
            uint8_t dialog_token = details[1];
            const struct dot11_ie_twt *req_ie = (const struct dot11_ie_twt *)&details[2];
            if (req_ie->header.element_id != DOT11_IE_TWT)
            {
                break;
            }
            int slot = umac_twt_responder_accept_ie(data, req_ie, addr);
            if (slot < 0)
            {
                break; /* rejected or table full (accept_ie logged it) */
            }
            umac_twt_responder_tx_setup_response(umacd, stad, dialog_token, slot);
            break;
        }

        default:
            break;
    }
}
