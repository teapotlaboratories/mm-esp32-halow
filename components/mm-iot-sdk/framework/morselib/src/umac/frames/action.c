/*
 * Utils: Frame library: Build Action frame
 *
 * Copyright 2022 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "action.h"
#include "dot11/dot11_utils.h"
#include "umac/data/umac_data.h"

bool frame_is_robust_action(struct mmpktview *view)
{
    const struct dot11_action *frame = (struct dot11_action *)mmpkt_get_data_start(view);

    if (!(dot11_frame_control_get_type(frame->hdr.frame_control) == DOT11_FC_TYPE_MGMT) ||
        !(dot11_frame_control_get_subtype(frame->hdr.frame_control) == DOT11_FC_SUBTYPE_ACTION))
    {
        return false;
    }

    switch (frame->field.category)
    {
        case DOT11_ACTION_CATEGORY_PUBLIC:
        case DOT11_ACTION_CATEGORY_HT:
        case DOT11_ACTION_CATEGORY_WNM_UNPROTECTED:
        case DOT11_ACTION_CATEGORY_SELF_PROTECTED:
        case DOT11_ACTION_CATEGORY_DMG_UNPROTECTED:
        case DOT11_ACTION_CATEGORY_VHT:
        case DOT11_ACTION_CATEGORY_S1G_UNPROTECTED:
        case DOT11_ACTION_CATEGORY_HE:
        case DOT11_ACTION_CATEGORY_VENDOR_SPECIFIC:
            return false;
            break;

        default:
            return true;
            break;
    }
}

/* A group-addressed Mesh (13) or Multihop (14) Action frame — net/mac80211's
 * _ieee80211_is_group_privacy_action (include/linux/ieee80211.h). In 802.11s these group-addressed
 * HWMP/path-selection (PREQ/PERR/RANN) and congestion-control frames are a distinct class: they are
 * protected by the MGTK (group privacy) when group-addressed-frame protection is active, NOT by BIP
 * (no MMIE), and in the live morse mesh they are sent in the clear (mesh peers are MFP=no — confirmed
 * on chronite: `iw station dump` shows the peer with `MFP: no`). So they must NOT be subjected to the
 * unprotected-robust-mgmt / BIP-MMIE RX drop that applies to BIP-protected group robust mgmt frames. */
bool frame_is_group_privacy_action(struct mmpktview *view)
{
    const struct dot11_action *frame = (struct dot11_action *)mmpkt_get_data_start(view);

    if (!(dot11_frame_control_get_type(frame->hdr.frame_control) == DOT11_FC_TYPE_MGMT) ||
        !(dot11_frame_control_get_subtype(frame->hdr.frame_control) == DOT11_FC_SUBTYPE_ACTION))
    {
        return false;
    }

    /* group/multicast bit of the DA (addr1) — is_multicast_ether_addr(hdr->addr1) */
    if (!(dot11_get_da(&frame->hdr)[0] & 0x01))
    {
        return false;
    }

    return frame->field.category == DOT11_ACTION_CATEGORY_MESH ||
           frame->field.category == DOT11_ACTION_CATEGORY_MULTIHOP;
}

/* A Mesh (13) or Multihop (14) Action frame of ANY addressing (group OR unicast) — the broader sibling of
 * frame_is_group_privacy_action without the group-DA requirement. In the live morse/Linux mesh ALL mesh
 * peers are MFP=no (chronite `iw station dump` -> `MFP: no`), so net/mac80211 sends EVERY mesh path-selection
 * frame in the clear, including the UNICAST PREP, and its RX never drops them: ieee80211_drop_unencrypted_mgmt
 * (rx.c) gates the unprotected-robust-mgmt drop entirely on test_sta_flag(rx->sta, WLAN_STA_MFP), which is
 * false for a mesh peer, so the whole drop block is skipped. The morse stad is (incorrectly) PMF_REQUIRED, so
 * we mirror mac80211's BEHAVIOUR here by exempting every mesh action — not just the group-addressed ones the
 * #18 fix covered — from that drop. Without this a Linux peer's unprotected unicast PREP is dropped and the
 * cross-vendor relay can't resolve a forward path. */
bool frame_is_mesh_action(struct mmpktview *view)
{
    const struct dot11_action *frame = (struct dot11_action *)mmpkt_get_data_start(view);

    if (!(dot11_frame_control_get_type(frame->hdr.frame_control) == DOT11_FC_TYPE_MGMT) ||
        !(dot11_frame_control_get_subtype(frame->hdr.frame_control) == DOT11_FC_SUBTYPE_ACTION))
    {
        return false;
    }

    return frame->field.category == DOT11_ACTION_CATEGORY_MESH ||
           frame->field.category == DOT11_ACTION_CATEGORY_MULTIHOP;
}

void frame_action_build(struct umac_data *umacd, struct consbuf *buf, void *args)
{
    MM_UNUSED(umacd);
    const struct frame_data_action *data = (const struct frame_data_action *)args;

    struct dot11_hdr *header = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(struct dot11_hdr));
    if (header != NULL)
    {
        dot11_build_pv0_mgmt_header(header,
                                    DOT11_FC_SUBTYPE_ACTION,
                                    0,
                                    data->dst_address,
                                    data->src_address,
                                    data->bssid);
    }

    consbuf_append(buf, data->action_field, data->action_field_len);
}
