/*
 * Copyright 2022 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include <string.h>
#include <stdio.h>

#include "umac/keys/umac_keys.h"
#include "dot11/dot11.h"
#include <mbedtls/aes.h>

/* ===== Bulk-DMA AES-CCM (RFC 3610) for the mesh datapath ========================================
 * Replaces hostap aes-ccm.c's ~2·ceil(len/16) single-block HW-AES-ECB ops (each paying the full esp_aes
 * acquire/DMA-setup/heap/release wrapper + AES_LOCK churn) with THREE bulk HW-AES passes: one
 * mbedtls_aes_crypt_cbc (CBC-MAC over [B0 | len16‖AAD zero-pad | plaintext zero-pad], IV=0; MAC = last
 * block), one mbedtls_aes_crypt_ctr (from counter A_1), one ECB for S_0; MIC = T^S_0. Byte-identical to
 * hostap/mbedtls CCM (RFC-3610 KAT in esp_mesh_ccm_selftest) so MICs interop with Linux/mac80211. L=2,
 * aad<=30, M in {8,16}. Called ONLY from the single-task mesh datapath, so the static CBC scratch is
 * race-free. IN-PLACE SAFE: the CBC-MAC is taken over the scratch copy before the in==out-safe CTR pass,
 * so body_out == body_in is fine (the datapath crypts directly in the mmpkt).
 *
 * Provenance: original implementation of RFC 3610 (CCM), structured for BYTE-PARITY with the per-block
 * hostap aes-ccm.c it replaces (framework/src/hostap/src/crypto/aes-ccm.c) so MICs still match Linux/
 * mac80211; built on the mbedtls bulk-AES primitives. NOT derived from mbedtls_ccm.c (which loops
 * per-block ECB = the overhead removed) — that + the RFC-3610 Packet-Vector-#1 KAT are used only as
 * oracles in esp_mesh_ccm_selftest. Full provenance + rationale: PR teapotlaboratories/mm-esp32-halow#22. */
#define ESP_CCM_BODY_MAX 1600
#define ESP_CCM_CBC_MAX  (16 + 32 + (((ESP_CCM_BODY_MAX) + 15) & ~15))

static void esp_ccm_cbc_mac(mbedtls_aes_context *ctx, size_t M, const uint8_t *nonce,
                            const uint8_t *aad, size_t aad_len, const uint8_t *data, size_t data_len,
                            uint8_t T[16])
{
    static uint8_t cbc_in[ESP_CCM_CBC_MAX];
    static uint8_t cbc_out[ESP_CCM_CBC_MAX];
    size_t off;
    cbc_in[0] = (uint8_t)((aad_len ? 0x40 : 0) | (((M - 2) / 2) << 3) | 1u /* L-1 */);
    memcpy(&cbc_in[1], nonce, 13);
    cbc_in[14] = (uint8_t)((data_len >> 8) & 0xff);
    cbc_in[15] = (uint8_t)(data_len & 0xff);
    off = 16;
    if (aad_len)
    {
        cbc_in[off] = (uint8_t)((aad_len >> 8) & 0xff);
        cbc_in[off + 1] = (uint8_t)(aad_len & 0xff);
        memcpy(&cbc_in[off + 2], aad, aad_len);
        size_t at = 2 + aad_len;
        size_t ap = (at + 15) & ~(size_t)15;
        memset(&cbc_in[off + at], 0, ap - at);
        off += ap;
    }
    memcpy(&cbc_in[off], data, data_len);
    size_t dp = (data_len + 15) & ~(size_t)15;
    memset(&cbc_in[off + data_len], 0, dp - data_len);
    off += dp;
    uint8_t iv[16] = { 0 };
    mbedtls_aes_crypt_cbc(ctx, MBEDTLS_AES_ENCRYPT, off, iv, cbc_in, cbc_out);
    memcpy(T, &cbc_out[off - 16], 16);
}

static int esp_mesh_ccm_ae(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t M,
                           const uint8_t *plain, size_t plain_len, const uint8_t *aad, size_t aad_len,
                           uint8_t *crypt, uint8_t *auth)
{
    if (aad_len > 30 || M > 16 || plain_len > ESP_CCM_BODY_MAX)
    {
        return -1;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, key_len * 8) != 0)
    {
        mbedtls_aes_free(&ctx);
        return -1;
    }
    uint8_t T[16];
    esp_ccm_cbc_mac(&ctx, M, nonce, aad, aad_len, plain, plain_len, T);
    uint8_t A1[16];
    A1[0] = 1u; /* Flags = L-1 */
    memcpy(&A1[1], nonce, 13);
    A1[14] = 0;
    A1[15] = 1;
    uint8_t stream[16];
    size_t nc_off = 0;
    mbedtls_aes_crypt_ctr(&ctx, plain_len, &nc_off, A1, stream, plain, crypt);
    uint8_t A0[16], S0[16];
    memcpy(A0, A1, 16);
    A0[14] = 0;
    A0[15] = 0;
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, A0, S0);
    for (size_t i = 0; i < M; i++)
    {
        auth[i] = (uint8_t)(T[i] ^ S0[i]);
    }
    mbedtls_aes_free(&ctx);
    return 0;
}

static int esp_mesh_ccm_ad(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t M,
                           const uint8_t *crypt, size_t crypt_len, const uint8_t *aad, size_t aad_len,
                           const uint8_t *auth, uint8_t *plain)
{
    if (aad_len > 30 || M > 16 || crypt_len > ESP_CCM_BODY_MAX)
    {
        return -1;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, key_len * 8) != 0)
    {
        mbedtls_aes_free(&ctx);
        return -1;
    }
    uint8_t A1[16];
    A1[0] = 1u;
    memcpy(&A1[1], nonce, 13);
    A1[14] = 0;
    A1[15] = 1;
    uint8_t stream[16];
    size_t nc_off = 0;
    mbedtls_aes_crypt_ctr(&ctx, crypt_len, &nc_off, A1, stream, crypt, plain); /* CTR is symmetric */
    uint8_t T[16];
    esp_ccm_cbc_mac(&ctx, M, nonce, aad, aad_len, plain, crypt_len, T);
    uint8_t A0[16], S0[16];
    memcpy(A0, A1, 16);
    A0[14] = 0;
    A0[15] = 0;
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, A0, S0);
    mbedtls_aes_free(&ctx);
    uint8_t diff = 0;
    for (size_t i = 0; i < M; i++)
    {
        diff |= (uint8_t)((T[i] ^ S0[i]) ^ auth[i]); /* constant-time MIC compare */
    }
    return diff ? -1 : 0;
}

/* RFC-3610 Packet-Vector-#1 known-answer test + decrypt round-trip. Returns 0 = PASS. Not called at
 * runtime by default (correctness is proven); available for a boot check. */
int esp_mesh_ccm_selftest(void)
{
    static const uint8_t key[16] = { 0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF };
    static const uint8_t nonce[13] = { 0x00,0x00,0x00,0x03,0x02,0x01,0x00,0xA0,0xA1,0xA2,0xA3,0xA4,0xA5 };
    static const uint8_t aad[8] = { 0,1,2,3,4,5,6,7 };
    static const uint8_t pt[23] = { 8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30 };
    static const uint8_t exp_ct[23] = { 0x58,0x8C,0x97,0x9A,0x61,0xC6,0x63,0xD2,0xF0,0x66,0xD0,0xC2,0xC0,0xF9,0x89,0x80,0x6D,0x5F,0x6B,0x61,0xDA,0xC3,0x84 };
    static const uint8_t exp_mic[8] = { 0x17,0xE8,0xD1,0x2C,0xFD,0xF9,0x26,0xE0 };
    uint8_t ct[23], mic[8], dec[23];
    int bad = esp_mesh_ccm_ae(key, 16, nonce, 8, pt, 23, aad, 8, ct, mic) != 0 ||
              memcmp(ct, exp_ct, 23) != 0 || memcmp(mic, exp_mic, 8) != 0 ||
              esp_mesh_ccm_ad(key, 16, nonce, 8, ct, 23, aad, 8, mic, dec) != 0 ||
              memcmp(dec, pt, 23) != 0;
    return bad ? -1 : 0;
}


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
    return esp_mesh_ccm_ae(tk, tk_len, nonce, mlen, body_in, body_len, aad, aad_len, body_out, mic);
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
    return esp_mesh_ccm_ad(tk, tk_len, nonce, mlen, ct_in, ct_len, aad, aad_len, mic, pt_out);
}
