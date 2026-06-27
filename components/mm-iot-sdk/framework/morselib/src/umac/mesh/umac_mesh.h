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

/** Retired no-op (was a broadcast Peering-Open probe). Kept for ABI compatibility. */
void mmwlan_mesh_send_test_action(void);

/* ---- internal (used by the umac beacon shim + mesh datapath) -------------- */

/** True while a mesh interface is active (routes beacon generation here). */
bool umac_mesh_is_active(void);

/** Build the next mesh beacon. Called from mmdrv_host_get_beacon() when a mesh
 *  interface is active. Returns NULL on failure. */
struct mmpkt *umac_mesh_get_beacon(struct umac_data *umacd);

/** The "common" stad representing the MBSS (broadcast/multicast + mgmt TX). NULL if
 *  no mesh vif is active. Used by the mesh datapath ops. */
struct umac_sta_data *umac_mesh_get_common_stad(void);

/** Maximum number of mesh peer links — the single source of truth for the per-peer stad arrays
 *  (MESH_MAX_PEERS in umac_mesh.c is defined from this). The mesh TX scheduler iterates
 *  [0, UMAC_MESH_MAX_PEERS) over umac_mesh_peer_stad_at(). */
#define UMAC_MESH_MAX_PEERS (4)

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

/** Handle a received peer S1G mesh beacon for peer discovery. `peer_mac` is the beacon's
 *  source address (= the peer's MAC, since a mesh BSSID equals the sender's own MAC); `ies`
 *  points at the beacon information elements. If the Mesh ID matches ours, initiates a peer
 *  link. Called from the datapath's S1G-beacon handler when a mesh vif is active. */
void umac_mesh_handle_peer_beacon(const uint8_t *peer_mac, const uint8_t *ies, uint32_t ies_len);

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

/** True if `mac` is an allowed peer (or the allowlist is empty). Used to drop frames whose
 *  immediate transmitter isn't an allowed neighbour, forcing a test topology. */
bool umac_mesh_peer_allowed(const uint8_t *mac);
