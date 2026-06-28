/*
 * Copyright 2026 Morse Micro
 * SPDX-License-Identifier: Apache-2.0
 *
 * mesh_sae — a thin morselib-facing shim over hostap's src/common/sae.c, so the umac 802.11s mesh can
 * run the SAE (Dragonfly) handshake per peer and derive a real PMK/PMKID (P3), reusing the
 * already-compiled SAE crypto. Compiled into mmhostap (where the hostap types are native); morselib
 * (umac_mesh.c) calls these clean uint8_t-based entry points via local `extern` declarations, exactly
 * like it reaches mmint_sha256_prf. The hostap headers (and their u8/wpabuf types) stay isolated here.
 */

#include "includes.h"
#include "common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/sae.h"
#include "utils/wpabuf.h"
#include "hostap_morse_common.h" /* the mmint_* mangle (wpabuf_* -> mmint_wpabuf_*, etc.) */

/* Fixed mesh SAE policy (P3): group 19 (ECC P-256), hunting-and-pecking PWE (h2e=0). Match the Linux
 * peer's config for cross-vendor interop (P3d). */
#define MESH_SAE_GROUP 19
#define MESH_SAE_H2E   0

/* Allocate a per-peer SAE protocol instance (heap; struct sae_data embeds a tmp heap + bignums). */
void *mesh_sae_alloc(void)
{
    return os_zalloc(sizeof(struct sae_data));
}

void mesh_sae_free(void *handle)
{
    struct sae_data *sae = handle;
    if (sae != NULL)
    {
        sae_clear_data(sae);
        os_free(sae);
    }
}

/* Build our SAE Commit (group | scalar | element) for the (our_mac, peer_mac, password) pair. The
 * dragonfly PWE is derived here (sae_prepare_commit). Returns 0 on success; *out_len = body length. */
int mesh_sae_build_commit(void *handle, const uint8_t *our_mac, const uint8_t *peer_mac,
                          const char *password, size_t password_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct sae_data *sae = handle;
    struct wpabuf *buf;
    int ret = -1;

    if (sae_set_group(sae, MESH_SAE_GROUP) != 0)
    {
        return -1;
    }
    if (sae_prepare_commit(our_mac, peer_mac, (const u8 *)password, password_len, sae) != 0)
    {
        return -1;
    }
    buf = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
    if (buf == NULL)
    {
        return -1;
    }
    if (sae_write_commit(sae, buf, NULL, NULL) == 0 && wpabuf_len(buf) <= out_cap)
    {
        *out_len = wpabuf_len(buf);
        os_memcpy(out, wpabuf_head(buf), *out_len);
        ret = 0;
    }
    wpabuf_free(buf);
    return ret;
}

/* Process a received peer Commit body, then derive the keys (sae_process_commit fills pmk/pmkid).
 * Returns 0 on success. */
int mesh_sae_process_commit(void *handle, const uint8_t *body, size_t len)
{
    struct sae_data *sae = handle;
    const u8 *token = NULL;
    size_t token_len = 0;
    int allowed_groups[] = { MESH_SAE_GROUP, 0 };
    int ie_offset = 0;

    if (sae_parse_commit(sae, body, len, &token, &token_len, allowed_groups, MESH_SAE_H2E,
                         &ie_offset) != WLAN_STATUS_SUCCESS)
    {
        return -1;
    }
    if (sae_process_commit(sae) != 0)
    {
        return -1;
    }
    return 0;
}

/* Build our SAE Confirm (send-confirm counter | confirm hash). Returns 0; *out_len = body length. */
int mesh_sae_build_confirm(void *handle, uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct sae_data *sae = handle;
    struct wpabuf *buf;
    int ret = -1;

    buf = wpabuf_alloc(2 + SAE_CONFIRM_MAX_LEN);
    if (buf == NULL)
    {
        return -1;
    }
    if (sae_write_confirm(sae, buf) == 0 && wpabuf_len(buf) <= out_cap)
    {
        *out_len = wpabuf_len(buf);
        os_memcpy(out, wpabuf_head(buf), *out_len);
        ret = 0;
    }
    wpabuf_free(buf);
    return ret;
}

/* Verify a received peer Confirm body. Returns 0 on success (confirm hash matches). */
int mesh_sae_check_confirm(void *handle, const uint8_t *body, size_t len)
{
    struct sae_data *sae = handle;
    int ie_offset = 0;
    return sae_check_confirm(sae, body, len, &ie_offset) == 0 ? 0 : -1;
}

/* After process_commit: copy out the 32-byte PMK + 16-byte PMKID. Returns 0 if the PMK is ready. */
int mesh_sae_get_keys(void *handle, uint8_t *pmk32, uint8_t *pmkid16)
{
    struct sae_data *sae = handle;
    if (sae->pmk_len != 32)
    {
        return -1;
    }
    os_memcpy(pmk32, sae->pmk, 32);
    os_memcpy(pmkid16, sae->pmkid, 16);
    return 0;
}

/* The SAE protocol state (enum sae_state: NOTHING/COMMITTED/CONFIRMED/ACCEPTED) as a plain int. */
int mesh_sae_state(void *handle)
{
    struct sae_data *sae = handle;
    return (int)sae->state;
}
