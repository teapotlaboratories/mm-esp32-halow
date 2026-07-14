/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * 802.11s mesh — host-side bring-up (P1: mesh vif up + beacon).
 *
 * Mirrors the IBSS module (umac/ibss): an association-less, self-beaconing vif.
 * The protocol layers (peering / HWMP / path table) are added in later phases;
 * this module brings a mesh BSS up and self-beacons a mesh beacon (Mesh ID +
 * Mesh Configuration IEs), following morse_driver's mesh BSS config flow
 * (SET_MESH_CONFIG + MESH_CONFIG START).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mmwlan.h"
#include "mmpkt.h"
#include "umac/data/umac_data.h"

/* S3 — relay/forward onto the aggregation-eligible data path (design §5 S3, blocker B6). When 1, a
 * forwarded mesh UNICAST is built on the per-TID DATA class and marked A-MPDU-eligible on its next-hop
 * BA session (mirrors net/mac80211 ieee80211_rx_h_mesh_forward re-injecting into the normal data TX
 * path, TID preserved); when 0 it falls back to today's mgmt-class, non-aggregating forward. The
 * non-blocking TX of the forward path (FIX-2, the interrupt-WDT fix) is unconditional either way.
 * Kept as a compile-time toggle for bench A/B without reverting S1/S2. */
#ifndef MESH_FWD_DATA_AGGREGATE
#define MESH_FWD_DATA_AGGREGATE 1
#endif

/* Forwarded unicast rides best-effort TID 0 — matches the wire QoS TID that umac_mesh_build_forward
 * stamps (0x0100 = Mesh Control Present, TID bits 0), and 0 <= UMAC_BA_MAX_AGGR_TID so it aggregates. */
#define MESH_FWD_TID 0

/* Bounded TX-ready wait for a forwarded frame (ms). The forward runs in the umac-core evtloop; the
 * original code waited the full MMWLAN_TX_DEFAULT_TIMEOUT_MS (1000 ms) and a timeout=0 drop-on-full
 * forwarded ~nothing (bench 2026-07-12). This bound lets a transient pause clear so the forward actually
 * goes out (and can aggregate) while capping any evtloop stall well under the 300 ms interrupt-WDT window. */
#define MESH_FWD_TX_TIMEOUT_MS 250

/* TEMP 2026-07-12 — forward-drop instrumentation (bench-verify S3). Counters incremented at each point on the
 * relay forward path so an iperf run pins WHERE the relay drops forwards (the app dumps them via ESP_LOGI —
 * MMLOG is not on the UART). Remove after the drop point is confirmed. Order = along the code path. */
enum mesh_fwd_dbg_idx {
    FDBG_RX_FWD_REACHED,  /* umac_datapath.c: RX reached the umac_mesh_forward_data call */
    FDBG_FWD_ENTRY,       /* umac_mesh.c: entered forward_data past the multihop/active guards */
    FDBG_LOOKUP_MISS,     /* umac_mesh.c: next-hop lookup failed (D4) */
    FDBG_NHSTAD_NULL,     /* umac_mesh.c: next-hop stad NULL (D5) */
    FDBG_BUILD_NULL,      /* umac_mesh.c: forward frame build failed (buffer exhaustion) */
    FDBG_KEYED_ENTRY,     /* umac_datapath.c: entered tx_mesh_keyed_frame */
    FDBG_TXREADY_TIMEOUT, /* umac_datapath.c: wait_for_tx_ready dropped (D6b — leading) */
    FDBG_ENCRYPT_FAIL,    /* umac_datapath.c: SW-CCMP encrypt failed (D6a) */
    FDBG_MMDRV_FAIL,      /* umac_datapath.c: mmdrv_tx_frame < 0 (D6c) */
    FDBG_MMDRV_OK,        /* umac_datapath.c: mmdrv_tx_frame >= 0 — handed to FW (S1 fork) */
    /* RX-path counters (2026-07-12 pass 2 — the drop is BEFORE the forward call, rx_reached=6/~342) */
    FDBG_RX_MESH_SEEN,    /* umac_datapath.c: a mesh data frame reached the allowlist gate (denominator) */
    FDBG_RX_ALLOWLIST,    /* umac_datapath.c:696 allowlist drop (TA not allowed) */
    FDBG_RX_PLAINTEXT,    /* umac_datapath.c:707 non-EAPOL plaintext drop */
    FDBG_RX_HW_CCMP_FAIL, /* umac_datapath.c:721 FW-HW-decrypt ccmp_is_valid fail (incl. replay) */
    FDBG_RX_SW_CCMP_FAIL, /* umac_datapath.c:741 host SW-CCMP decrypt fail (incl. replay) */
    FDBG_RX_NO_DECRYPT,   /* umac_datapath.c:750 protected but no decrypt path -> drop */
    FDBG_RX_DECRYPT_OK,   /* umac_datapath.c: survived the decrypt block (past :752) */
    /* TEMP 2026-07-12 pass-3 — split the SW-CCMP drop (FDBG_RX_SW_CCMP_FAIL) into its two causes so the
     * ~99% forward drop is pinned as wrong-key/AAD (MIC) vs PN/ordering (replay). Incremented inside
     * umac_datapath_sw_ccmp_decrypt at each return-false. */
    FDBG_RX_SW_MIC_FAIL,    /* mesh_ccmp_decrypt MIC failed (wrong key / AAD / nonce mismatch) */
    FDBG_RX_SW_REPLAY_FAIL, /* MIC ok but ccmp_is_valid replay-window reject (PN old / duplicate) */
    /* TEMP 2026-07-12 pass-4 — board0 TX key_stad confirmation for the multi-hop MIC failure. For a mesh
     * multi-hop unicast (RA=next-hop != final DA), does key_stad override to the next-hop peer (correct
     * per-link MTK) or fall back to the dest stad (wrong link MTK -> the next hop MIC-fails the frame)? */
    FDBG_TX_MULTIHOP,    /* mesh unicast where RA (next-hop) != final DA */
    FDBG_TX_NH_NULL,     /* get_peer_stad(RA) == NULL -> key_stad falls back to dest stad (BUG) */
    FDBG_TX_NH_EQ_STAD,  /* get_peer_stad(RA) == stad (dest) -> key_stad still == dest (also wrong) */
    FDBG_TX_NH_OK,       /* get_peer_stad(RA) resolved to a distinct next-hop stad -> correct link key */
    FDBG_COUNT
};
/* DEFINED in the app as RTC_NOINIT_ATTR (survives the INT-WDT crash-reboot so the accumulated counts
 * can be read AFTER the relay crash-loop). morselib only references it; the app zeroes it on cold boot. */
extern uint32_t g_mesh_fwd_dbg[FDBG_COUNT];

/* TEMP 2026-07-12 — FIX-1 verification telemetry (RTC_NOINIT, defined in the app; survives a crash-reboot).
 * g_hwr_boot_count: app_main entries (crash-reboots increment it). g_hwr_attempts: hw_restart_evt_handler
 * entries. g_hwr_completions: restarts that returned success. DEFINITIVE FIX-1 test: boot_count stays ~1
 * while attempts>0 and completions==attempts => hw_restart fired AND the ESP did NOT reboot (crash fixed).
 * boot_count climbing with attempts => still crash-rebooting. attempts==0 => the flap wasn't the crash. */
extern uint32_t g_hwr_boot_count;
extern uint32_t g_hwr_attempts;
extern uint32_t g_hwr_completions;

/* TEMP 2026-07-12 — mesh-plink flap telemetry (RTC_NOINIT, app-defined). g_plink_estab: # times a peer
 * reached MESH_PLINK_ESTAB (a STABLE link establishes ONCE => count 1; a FLAPPING link re-establishes =>
 * count climbs). g_plink_close: # times an ESTABLISHED plink was torn down (mesh_peer_free while ESTAB).
 * Read from the ESP's own side (survives the console-open warm-reset), so ESP<->ESP peering stability can
 * be measured without a Linux peer or the monitor. */
extern uint32_t g_plink_estab;
extern uint32_t g_plink_close;
/* Copy the forward-drop counters into out[FDBG_COUNT] (app dumps them after an iperf run). */
void mmwlan_mesh_get_fwd_dbg(uint32_t *out);

/* ---- public API (mirrors mmwlan_ibss_*) ----------------------------------- */

/** Arguments to bring up an 802.11s mesh interface. */
struct mmwlan_mesh_args
{
    /** This node's interface MAC (locally administered). All-zero inherits the
     *  chip's factory MAC. Used as SA and BSSID in this node's mesh beacons. */
    uint8_t if_addr[MMWLAN_MAC_ADDR_LEN];
    /** Mesh ID — identifies the MBSS (the mesh equivalent of an SSID). */
    uint8_t mesh_id[MMWLAN_SSID_MAXLEN];
    /** Mesh ID length (1..32). */
    uint8_t mesh_id_len;
    /** S1G channel number (e.g. 27 for US 915.5 MHz 1 MHz). */
    uint8_t s1g_chan_num;
    /** Beacon interval in TU (typically 100). */
    uint16_t beacon_interval_tu;
    /** Maximum number of mesh peer links (firmware limit applies). */
    uint8_t max_plinks;
};

/**
 * Bring up an 802.11s mesh interface and start self-beaconing.
 *
 * Sequence (mirrors morse_driver mesh BSS config): ADD_INTERFACE(MESH) ->
 * SET_CHANNEL -> BSS_CONFIG -> SET_MESH_CONFIG -> MESH_CONFIG(START) ->
 * start beaconing.
 *
 * @returns MMWLAN_SUCCESS on success or an error code.
 */
enum mmwlan_status mmwlan_mesh_start(const struct mmwlan_mesh_args *args);

/** Tear down the mesh interface (MESH_CONFIG(STOP) + remove vif). */
enum mmwlan_status mmwlan_mesh_stop(void);

/** Initiate a mesh peer link to a neighbour (send a Mesh Peering Open, -> OPN_SNT).
 *  Idempotent and safe to call repeatedly — ignored if the peer is already known
 *  (handshake in progress / established) or is ourselves. Intended to be called when a
 *  peer's mesh beacon (same Mesh ID) is heard. No-op if no mesh vif is active. */
void mmwlan_mesh_peer_open(const uint8_t *peer_mac);

/* Number of ESTAB mesh peers; if @p estab_macs != NULL, copies up to UMAC_MESH_MAX_PEERS peer MACs into it.
 * Operational telemetry the app heartbeat logs so a node's mesh peering state is visible on the console
 * (morselib MMLOG does not reach the UART; without this app-visible getter, two ESP nodes peering with no
 * Linux node present reads falsely as "never peers"). */
uint8_t mmwlan_mesh_peer_count(uint8_t estab_macs[][6]);

/** Retired no-op (was a broadcast Peering-Open probe). Kept for ABI compatibility. */
void mmwlan_mesh_send_test_action(void);

/* ---- internal (used by the umac beacon shim + mesh datapath) -------------- */

/** True while a mesh interface is active (routes beacon generation here). */
bool umac_mesh_is_active(void);

/** #P5 — true when mesh CCMP data crypto runs on the HOST (no FW key offload), required for multi-hop
 *  forwarding (the FW keys decryption by the mesh-SA/A4, so it drops forwarded A4!=TA frames). When
 *  false the node uses FW HW crypto (single-hop only). Switches the FW-offload gate + the datapath
 *  TX/RX SW-CCMP paths together. */
bool umac_mesh_sw_crypto_enabled(void);

/** Build the next mesh beacon. Called from mmdrv_host_get_beacon() when a mesh
 *  interface is active. Returns NULL on failure. */
struct mmpkt *umac_mesh_get_beacon(struct umac_data *umacd);

/** The "common" stad representing the MBSS (broadcast/multicast + mgmt TX). NULL if
 *  no mesh vif is active. Used by the mesh datapath ops. */
struct umac_sta_data *umac_mesh_get_common_stad(void);

/** Maximum number of mesh peer links — the single source of truth for the per-peer stad arrays
 *  (MESH_MAX_PEERS in umac_mesh.c is defined from this). The mesh TX scheduler iterates
 *  [0, UMAC_MESH_MAX_PEERS) over umac_mesh_peer_stad_at(). */
#define UMAC_MESH_MAX_PEERS (16)

/** The per-peer stad for an ESTAB unicast peer (its pairwise+group-RX keychain), or NULL so the
 *  datapath falls back to the common stad. Used by the mesh unicast TX/RX stad lookups. */
struct umac_sta_data *umac_mesh_get_peer_stad(const uint8_t *addr);

/** The per-peer stad in mesh peer slot @p index, or NULL if that slot is empty or the peer is not
 *  yet ESTABLISHED. Lets the mesh TX scheduler enumerate established peers' per-peer TX queues
 *  (umac_datapath_tx_dequeue_frame_mesh) without exposing the mesh_peers[] table. @p index in
 *  [0, UMAC_MESH_MAX_PEERS); out of range returns NULL. */
struct umac_sta_data *umac_mesh_peer_stad_at(size_t index);

/** Next monotonic mesh sequence number for the Mesh Control header (data path). */
uint32_t umac_mesh_next_seqnum(void);

/** Handle a received mesh ACTION frame (Mesh Peering Management). Called from the mesh
 *  datapath's process_rx_mgmt_frame. */
void umac_mesh_handle_action(struct umac_data *umacd, struct mmpktview *rxbufview);

/** Handle a received mesh AUTHENTICATION frame (SAE). Called from the mesh datapath's
 *  process_rx_mgmt_frame. */
void umac_mesh_handle_auth(struct umac_data *umacd, struct mmpktview *rxbufview);

/** Handle a received peer S1G mesh beacon for peer discovery. `peer_mac` is the beacon's
 *  source address (= the peer's MAC, since a mesh BSSID equals the sender's own MAC); `ies`
 *  points at the beacon information elements. If the Mesh ID matches ours, initiates a peer
 *  link. Called from the datapath's S1G-beacon handler when a mesh vif is active. */
void umac_mesh_handle_peer_beacon(const uint8_t *peer_mac, const uint8_t *ies, uint32_t ies_len);

/** Refresh an established peer's inactivity timer on ANY received frame from it (mirrors Linux
 *  updating sta last_rx on every frame, rx.c:4810). `ta` is the frame's transmitter address.
 *  Called from the mesh data RX path so active data traffic — not just beacons — counts as liveness. */
void umac_mesh_note_peer_rx(const uint8_t *ta);

/** HWMP: look up an ACTIVE mesh path to `dest`, writing the next-hop MAC to `next_hop_out`.
 *  Returns false if there is no resolved path (the caller should send direct + start discovery). */
bool umac_mesh_lookup_next_hop(const uint8_t *dest, uint8_t *next_hop_out);

/** HWMP: originate a PREQ to discover a path to `dest` (rate-limited). No-op if no mesh vif. */
void umac_mesh_start_discovery(const uint8_t *dest);

/** Forward a received mesh data frame whose mesh DA isn't us, toward the next hop (ESP as an
 *  intermediate hop). `payload` is the LLC/SNAP + L3 payload (copied). Returns true if relayed,
 *  false if dropped (no path → discovery started). */
bool umac_mesh_forward_data(const uint8_t *mesh_da, const uint8_t *mesh_sa, const uint8_t *payload,
                            uint32_t payload_len);

/** Handle a received GROUP-addressed (bcast/mcast) mesh data frame: drop duplicates / our own
 *  echoes (RMC), else re-broadcast it through the mesh (ttl-1) and return false so the caller
 *  also delivers it locally. `mesh_sa`/`ttl`/`seqnum` come from the Mesh Control header.
 *  Returns true if the caller should DROP (duplicate / our own / no longer propagating). */
bool umac_mesh_handle_group_data(const uint8_t *mesh_sa, uint8_t ttl, uint32_t seqnum,
                                 const uint8_t *payload, uint32_t payload_len);

/** Restrict mesh peering to a fixed set of peer MACs (`count` x 6 bytes). Used to force a test
 *  topology (line / multi-hop) on a bench where all nodes are in range. count=0 = peer with
 *  anyone (default). */
void mmwlan_mesh_set_peer_allowlist(const uint8_t *macs, uint8_t count);

/** Enable/disable multi-hop forwarding + HWMP for this node (default enabled). When disabled the
 *  node is a pure mesh STA ("leaf"): it peers with direct neighbours normally but never relays
 *  another node's traffic (unicast or group), never uses a multi-hop path for its own TX, and
 *  emits no PREQ/PREP/PERR — so peers never route through it (no black hole). Runtime-settable
 *  before or after mmwlan_mesh_start; survives a restart. Stricter than Linux dot11MeshForwarding,
 *  which only stops forwarding-for-others. */
void mmwlan_mesh_set_multihop(bool enabled);

/** True if `mac` is an allowed peer (or the allowlist is empty). Used to drop frames whose
 *  immediate transmitter isn't an allowed neighbour, forcing a test topology. */
bool umac_mesh_peer_allowed(const uint8_t *mac);
