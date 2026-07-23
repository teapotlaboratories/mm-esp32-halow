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
 * path, TID preserved); when 0 it falls back to today's mgmt-class, non-aggregating forward. This flag
 * also selects the TX queue: mmdrv_tx_frame's 2nd arg is `is_mgmt` (queue select), so aggregate=1 -> data
 * queue, 0 -> mgmt queue. NB there is no "non-blocking forward TX": that arg was once misread as a
 * blocking flag (the since-retracted "FIX-2"). What bounds the forward's evtloop stall is the explicit
 * MESH_FWD_TX_TIMEOUT_MS wait below — keep that margin honest.
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
 * goes out (and can aggregate) while capping the evtloop stall.
 * BUDGET: the interrupt-WDT window is 300 ms and this wait is NOT the only work in an evtloop iteration
 * (CCMP encrypt, RX processing, peering run there too) — so the wait alone must leave room for the rest.
 * 250 ms was 83% of the window and could itself trip the very WDT this bounds; 100 ms rides out a
 * transient pause (the observed pauses are ms-scale) while leaving ~200 ms for everything else. */
#define MESH_FWD_TX_TIMEOUT_MS 100

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
 *  intermediate hop). `payload` is the LLC/SNAP + L3 payload (copied). If `ae` the frame is a 6-address
 *  proxied (AE_A5_A6) frame and `eaddr1`/`eaddr2` (the proxied final-DA/source) are re-emitted so a
 *  multi-hop gate keeps the proxied endpoints (S4c); if `!ae`, `eaddr1`/`eaddr2` are ignored. Returns
 *  true if relayed, false if dropped (no path → discovery started). */
bool umac_mesh_forward_data(const uint8_t *mesh_da, const uint8_t *mesh_sa, bool ae,
                            const uint8_t *eaddr1, const uint8_t *eaddr2, const uint8_t *payload,
                            uint32_t payload_len);

/** Handle a received GROUP-addressed (bcast/mcast) mesh data frame: drop duplicates / our own
 *  echoes (RMC), else re-broadcast it through the mesh (ttl-1) and return false so the caller
 *  also delivers it locally. `mesh_sa`/`ttl`/`seqnum` come from the Mesh Control header. If `ae_a4`
 *  the frame is a proxied multicast (net/mac80211 MESH_FLAGS_AE_A4) and `eaddr1` (the proxied off-mesh
 *  source) is preserved in the re-broadcast so a multi-hop mesh keeps it (the group analog of S4c).
 *  Returns true if the caller should DROP (duplicate / our own / no longer propagating). */
bool umac_mesh_handle_group_data(const uint8_t *mesh_sa, uint8_t ttl, uint32_t seqnum, bool ae_a4,
                                 const uint8_t *eaddr1, const uint8_t *payload, uint32_t payload_len);

/** S5 (broadcast bridging) — a gate ORIGINATES a proxied multicast frame: it injects an off-mesh
 *  source's broadcast/multicast (e.g. an AP client's ARP request) into the mesh as a group-addressed
 *  AE_A4 frame (mesh DA = broadcast, mesh SA = us, eaddr1 = `src` the off-mesh source). Mesh nodes learn
 *  mpp(src -> us) and deliver it locally as [dst=broadcast][src=src], so a node can then unicast-reply to
 *  `src` back through this gate. Mirrors net/mac80211's multicast Address-Extension. `payload` is the
 *  LLC/SNAP + L3 (copied). Returns false if the mesh is not active. */
bool mmwlan_mesh_tx_group_proxied(const uint8_t *src, const uint8_t *payload, uint32_t payload_len);

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

/** Enable proactive root/gate announcements (RANN). `root_rann` makes this node a PROACTIVE_RANN root
 *  that periodically floods a RANN so every mesh node learns a path back to it; `is_gate` sets
 *  RANN_FLAG_IS_GATE (advertising this root as a gate to off-mesh networks); `interval_ms` is the RANN
 *  period (0 keeps the current/default 5000 ms). Mirrors the Linux mesh config
 *  dot11MeshHWMPRootMode / dot11MeshGateAnnouncementProtocol / dot11MeshHWMPRannInterval. Runtime-
 *  settable before or after mmwlan_mesh_start. S1 of the 802.11s mesh-gate port (TX side only). */
void mmwlan_mesh_set_root_announcements(bool root_rann, bool is_gate, uint32_t interval_ms);

/** S3 test hook — originate a PROXIED 6-address (AE_A5_A6) mesh data frame to a directly-peered mesh
 *  node `mesh_da`, carrying the proxied endpoints `eaddr1_da` (final DA / addr5) + `eaddr2_sa` (original
 *  SA / addr6, an off-mesh host). Exercises the Address-Extension datapath primitive end-to-end so it can
 *  be on-air byte-diffed vs a Linux AE frame and confirm the MM6108 FW delivers/accepts AE frames. Returns
 *  false if not peered with `mesh_da`. A manual injector for verifying S3 — NOT the gate proxy path (S4/S5).
 *  Mirrors net/mac80211 ieee80211_new_mesh_header (MESH_FLAGS_AE_A5_A6). */
bool mmwlan_mesh_send_ae_test(const uint8_t *mesh_da, const uint8_t *eaddr1_da, const uint8_t *eaddr2_sa,
                              const uint8_t *payload, uint32_t payload_len);

/** Internal: the datapath RX records a received AE frame's proxied endpoints here (S3). */
void umac_mesh_note_ae_rx(const uint8_t *eaddr1, const uint8_t *eaddr2);

/** S3 probe — number of 6-address (AE_A5_A6) mesh frames this node has received + parsed, and (out) the
 *  proxied endpoints of the most recent one: `eaddr1_out` = final DA (addr5), `eaddr2_out` = original SA
 *  (addr6). A fixture polls this to confirm the MM6108 FW delivered the AE frame and the host decrypted +
 *  parsed the AE Mesh Control correctly (morselib MMLOG isn't on the ESP UART). Returns the running count;
 *  0 means no AE frame received yet. Either out pointer may be NULL. */
uint32_t mmwlan_mesh_ae_rx_probe(uint8_t *eaddr1_out, uint8_t *eaddr2_out);

/** Internal (S4): record that off-mesh host `dst` is reachable via the proxy mesh node `mpp` — the MPP
 *  (mesh proxy path) learned from a received AE frame (net/mac80211 mpp_path_add). Called by the datapath
 *  RX. Ignores `dst` == our own MAC or multicast. */
void umac_mesh_mpp_learn(const uint8_t *dst, const uint8_t *mpp);

/** S4 — MPP lookup: which mesh node proxies off-mesh host `dst`? Returns true + fills `mpp_out` (if
 *  non-NULL) with the proxy mesh node, or false if `dst` is not a known proxied host. Mirrors
 *  net/mac80211 mpp_path_lookup. Used by the send_to_gates TX fallback + as an S4 on-air probe. */
bool mmwlan_mesh_mpp_lookup(const uint8_t *dst, uint8_t *mpp_out);

/** S5 — callback for a received 6-address (AE_A5_A6) mesh frame's decoded contents: `eaddr1` = the final
 *  DA (addr5, the proxied off-mesh destination), `eaddr2` = the original SA (addr6, the off-mesh source),
 *  and the payload (LLC/SNAP + L3, after the Mesh Control was stripped). The gate registers this to bridge
 *  a proxied frame onto its AP side (deliver to eaddr1) — the mesh RX ext-cb only sees the frame AFTER the
 *  AE Mesh Control is stripped, so it cannot recover the proxied endpoints; this callback can. `arg` is the
 *  value passed to mmwlan_mesh_register_ae_rx_cb. */
/*  Return true if the callback CONSUMED the frame (delivered it off-mesh, e.g. a gate that injected it
 *  onto its AP side) — the datapath then SKIPS the normal local delivery to avoid a double-delivery
 *  (S5 finishing touch). Return false to let the normal local delivery proceed (the default; a plain
 *  mesh node whose own stack is the endpoint returns false / registers no callback). */
typedef bool (*mmwlan_mesh_ae_rx_cb_t)(const uint8_t *eaddr1, const uint8_t *eaddr2,
                                       const uint8_t *payload, uint32_t payload_len, void *arg);

/** S5 — register (or clear, with cb=NULL) a callback invoked for every received AE_A5_A6 mesh frame, with
 *  its proxied endpoints + payload. The gate uses it for the mesh->AP leg of the L2 bridge. One callback. */
void mmwlan_mesh_register_ae_rx_cb(mmwlan_mesh_ae_rx_cb_t cb, void *arg);

/** Internal (S5): the datapath invokes the registered AE-rx callback (if any) for a received AE frame.
 *  Returns true if the callback consumed the frame (so the datapath skips local delivery). */
bool umac_mesh_ae_rx_deliver(const uint8_t *eaddr1, const uint8_t *eaddr2, const uint8_t *payload,
                             uint32_t payload_len);

/** S4b — send-to-gates fallback (net/mac80211 mesh_path_send_to_gates + prepare_for_gate): reach an
 *  off-mesh destination `final_dst` through a discovered GATE by wrapping the frame as a 6-address
 *  AE_A5_A6 frame (mesh DA = gate, eaddr1 = final_dst, eaddr2 = `src` the original source) and sending it
 *  via each known gate (paths flagged is_gate by the S2 RANN RX). Returns true if it went out via at least
 *  one gate, false if there is no known/reachable gate. S5 calls this from the datapath on a next-hop miss;
 *  a fixture can call it directly to verify S4b. */
bool mmwlan_mesh_send_to_gates(const uint8_t *final_dst, const uint8_t *src, const uint8_t *payload,
                               uint32_t payload_len);

/** S5c — inject a PROXIED 6-address (AE_A5_A6) mesh data frame on behalf of an off-mesh source `src` (an
 *  AP client behind this gate) toward `final_dst`, resolving where to send: final_dst as a reachable mesh
 *  node, else its MPP proxy, else send_to_gates. eaddr1 = final_dst, eaddr2 = src, mesh SA = us. This is
 *  the AP->mesh leg of the gate L2 bridge (the gate calls it from its AP RX to proxy a client's frame into
 *  the mesh). `payload` is the LLC/SNAP + L3 (copied). Returns false if nothing routes it. */
bool mmwlan_mesh_tx_proxied(const uint8_t *final_dst, const uint8_t *src, const uint8_t *payload,
                            uint32_t payload_len);

/** Number of mesh gates this node currently knows — a gate is a proactive root whose RANN carried
 *  RANN_FLAG_IS_GATE (learned by the S2 RANN RX handler). > 0 means this node has discovered a way
 *  off the mesh; the value also drives the beacon "Connected to Mesh Gate" formation-info bit. Mirrors
 *  net/mac80211 mesh_gate_num / ifmsh->num_gates. S2 of the 802.11s mesh-gate port (RX side). */
uint8_t mmwlan_mesh_gate_count(void);

/** True if `mac` is an allowed peer (or the allowlist is empty). Used to drop frames whose
 *  immediate transmitter isn't an allowed neighbour, forcing a test topology. */
bool umac_mesh_peer_allowed(const uint8_t *mac);
