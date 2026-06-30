/*
 * Copyright 2022 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include <string.h>
#include <stdio.h>

#include "umac/keys/umac_keys.h"
#include "dot11/dot11.h"

/* AES-CCM (RFC 3610) from the hostap lib (P5a), via the mmint_ shim. ae: encrypt+auth; ad:
 * decrypt+verify (0 = MIC OK). NOT in-place safe: aes_ccm_encr writes the keystream into `out` before
 * XOR-ing `in`, so out==in yields zeros — callers must pass non-aliasing in/out buffers. */
extern int mmint_aes_ccm_ae(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t M,
                            const uint8_t *plain, size_t plain_len, const uint8_t *aad, size_t aad_len,
                            uint8_t *crypt, uint8_t *auth);
extern int mmint_aes_ccm_ad(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t M,
                            const uint8_t *crypt, size_t crypt_len, const uint8_t *aad, size_t aad_len,
                            const uint8_t *auth, uint8_t *plain);


#define CCMP_HEADER_KEY_OCT_KEY_ID 0xC0


static uint8_t parse_ccmp_key_id(uint8_t *ccmp_header)
{
    return (ccmp_header[3] & CCMP_HEADER_KEY_OCT_KEY_ID) >> 6;
}

/* Public: the 2-bit KeyID from a received CCMP header (for host-side key lookup on the RX SW path). */
uint8_t mesh_ccmp_key_id(const uint8_t *ccmp_header)
{
    return (ccmp_header[3] & CCMP_HEADER_KEY_OCT_KEY_ID) >> 6;
}


static uint64_t parse_ccmp_packet_number(const uint8_t *header)
{
    return (((uint64_t)(*(header)) << 0)) |
           (((uint64_t)(*(header + 1)) << 8)) |
           (((uint64_t)(*(header + 4)) << 16)) |
           (((uint64_t)(*(header + 5)) << 24)) |
           (((uint64_t)(*(header + 6)) << 32)) |
           (((uint64_t)(*(header + 7)) << 40));
}

bool ccmp_is_valid(struct umac_sta_data *stad,
                   uint8_t *ccmp_header,
                   enum umac_key_rx_counter_space space)
{
    if (ccmp_header == NULL || stad == NULL)
    {
        return false;
    }

    uint8_t key_id = parse_ccmp_key_id(ccmp_header);


    if (umac_keys_get_key_type(stad, key_id) == UMAC_KEY_TYPE_BLANK)
    {
        return false;
    }

    uint64_t packet_number = parse_ccmp_packet_number(ccmp_header);
    enum mmwlan_status status =
        umac_keys_check_and_update_rx_replay(stad, key_id, packet_number, space);

    return (status == MMWLAN_SUCCESS);
}

/* Host-side CCMP (P5d/P5c). Build the CCMP AAD + CCM nonce for a PV0 frame — a faithful port of hostap
 * wlantest/ccmp.c ccmp_aad_nonce, which is the canonical mac80211/CCMP recipe (so a Linux peer computes
 * the same MIC). `hdr` is the contiguous 802.11 header [FC|Dur|A1|A2|A3|Seq|(A4 if ToDS+FromDS)|(QoS if
 * QoS-Data)]; `ccmp_hdr` is the 8-byte CCMP header (its PN bytes drive the nonce). The Mesh Control field
 * is plaintext body (NOT in the AAD) — the QoS byte1 (mesh-ctrl-present bit) is forced to 0 in the AAD. */
static void mesh_ccmp_aad_nonce(const uint8_t *hdr, const uint8_t *ccmp_hdr,
                                uint8_t *aad, size_t *aad_len, uint8_t *nonce)
{
    uint16_t fc = (uint16_t)(hdr[0] | (hdr[1] << 8));
    uint16_t type = (uint16_t)((fc >> 2) & 0x3u);
    uint16_t stype = (uint16_t)((fc >> 4) & 0xfu);
    int qos = 0;
    int addr4 = ((fc & (DOT11_MASK_FC_TO_DS | DOT11_MASK_FC_FROM_DS)) ==
                 (DOT11_MASK_FC_TO_DS | DOT11_MASK_FC_FROM_DS)) ? 1 : 0;
    uint8_t *pos;

    nonce[0] = 0;
    if (type == DOT11_FC_TYPE_DATA)
    {
        fc &= (uint16_t)~0x0070u; /* mask subtype bits 4-6 (keep bit 7 = QoS) */
        if (stype & 0x08u)
        {
            qos = 1;
            fc &= (uint16_t)~DOT11_MASK_FC_PLUS_HTC; /* clear +HTC (0x8000) */
            nonce[0] = (uint8_t)(hdr[24 + (addr4 ? 6 : 0)] & 0x0fu); /* TID from QoS byte0 */
        }
    }
    else if (type == DOT11_FC_TYPE_MGMT)
    {
        nonce[0] |= 0x10u;
    }

    fc &= (uint16_t)~(DOT11_MASK_FC_RETRY | 0x1000u /* PwrMgmt */ | DOT11_MASK_FC_MORE_DATA);
    fc |= DOT11_MASK_FC_PROTECTED; /* ISWEP */
    aad[0] = (uint8_t)(fc & 0xff);
    aad[1] = (uint8_t)((fc >> 8) & 0xff);
    pos = aad + 2;
    memcpy(pos, hdr + 4, 18); /* A1, A2, A3 */
    pos += 18;
    {
        uint16_t seq = (uint16_t)(hdr[22] | (hdr[23] << 8));
        seq &= (uint16_t)~0xfff0u; /* mask Seq#, keep Frag# */
        pos[0] = (uint8_t)(seq & 0xff);
        pos[1] = (uint8_t)((seq >> 8) & 0xff);
        pos += 2;
    }
    memcpy(pos, hdr + 24, (size_t)(addr4 * 6 + qos * 2)); /* A4 (if 4-addr) + QoS (if QoS) */
    pos += addr4 * 6;
    if (qos)
    {
        pos[0] &= (uint8_t)~0x70u;
        pos[0] &= (uint8_t)~0x80u; /* SPP A-MSDU = 0 */
        pos++;
        *pos++ = 0x00;
    }
    *aad_len = (size_t)(pos - aad);

    memcpy(nonce + 1, hdr + 10, 6); /* A2 */
    nonce[7] = ccmp_hdr[7];  /* PN5 */
    nonce[8] = ccmp_hdr[6];  /* PN4 */
    nonce[9] = ccmp_hdr[5];  /* PN3 */
    nonce[10] = ccmp_hdr[4]; /* PN2 */
    nonce[11] = ccmp_hdr[1]; /* PN1 */
    nonce[12] = ccmp_hdr[0]; /* PN0 */
}

/* Write the 8-byte CCMP header (PN + ExtIV + KeyID) from a 48-bit packet number. */
static void mesh_ccmp_write_header(uint8_t *ccmp_hdr, uint64_t pn, uint8_t key_id)
{
    ccmp_hdr[0] = (uint8_t)(pn & 0xff);             /* PN0 */
    ccmp_hdr[1] = (uint8_t)((pn >> 8) & 0xff);      /* PN1 */
    ccmp_hdr[2] = 0x00;                             /* Rsvd */
    ccmp_hdr[3] = (uint8_t)(0x20u | (key_id << 6)); /* ExtIV + KeyID */
    ccmp_hdr[4] = (uint8_t)((pn >> 16) & 0xff);     /* PN2 */
    ccmp_hdr[5] = (uint8_t)((pn >> 24) & 0xff);     /* PN3 */
    ccmp_hdr[6] = (uint8_t)((pn >> 32) & 0xff);     /* PN4 */
    ccmp_hdr[7] = (uint8_t)((pn >> 40) & 0xff);     /* PN5 */
}

/* Encrypt `body_in[0..body_len)` into `body_out` under the CCMP key `tk`, write the 8-byte CCMP header
 * (from pn + key_id) into `ccmp_hdr`, and the MIC into `mic`. tk_len 16 = CCMP-128 (M=8) / 32 = CCMP-256
 * (M=16). Returns 0 on success. `body_in` and `body_out` MUST NOT alias (see ae note above). Caller lays
 * out [802.11 hdr | ccmp_hdr(8) | body_out(ciphertext) | mic(M)]. */
int mesh_ccmp_encrypt(const uint8_t *tk, size_t tk_len, const uint8_t *hdr, uint8_t *ccmp_hdr,
                      uint64_t pn, uint8_t key_id, const uint8_t *body_in, uint8_t *body_out,
                      size_t body_len, uint8_t *mic)
{
    size_t mlen = (tk_len == 32) ? 16 : 8;
    uint8_t aad[30], nonce[13];
    size_t aad_len;
    mesh_ccmp_write_header(ccmp_hdr, pn, key_id);
    mesh_ccmp_aad_nonce(hdr, ccmp_hdr, aad, &aad_len, nonce);
    return mmint_aes_ccm_ae(tk, tk_len, nonce, mlen, body_in, body_len, aad, aad_len, body_out, mic);
}

/* Decrypt `ct_in[0..ct_len)` into `pt_out` under `tk` + verify `mic` (M bytes). `ccmp_hdr` is the
 * received 8-byte CCMP header. Returns 0 on success (MIC verified). `ct_in`/`pt_out` MUST NOT alias. */
int mesh_ccmp_decrypt(const uint8_t *tk, size_t tk_len, const uint8_t *hdr, const uint8_t *ccmp_hdr,
                      const uint8_t *ct_in, uint8_t *pt_out, size_t ct_len, const uint8_t *mic)
{
    size_t mlen = (tk_len == 32) ? 16 : 8;
    uint8_t aad[30], nonce[13];
    size_t aad_len;
    mesh_ccmp_aad_nonce(hdr, ccmp_hdr, aad, &aad_len, nonce);
    return mmint_aes_ccm_ad(tk, tk_len, nonce, mlen, ct_in, ct_len, aad, aad_len, mic, pt_out);
}
