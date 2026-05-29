# Fork changes vs upstream `ciniml/WireGuard-ESP32-Arduino`

This document tracks every diff from the upstream tree we forked.
Each entry lists the file, the upstream function, the change, and
the rationale. Crypto code (`src/crypto/refc/*`) is bit-identical to
upstream — no entries here for it.

## Version history

* **v0.1.1** — Reverted ALL `pbuf_alloc(PBUF_POOL)` changes from
  v0.1.0 (handshake init/response/cookie + transport TX/RX). Under
  live keepalive traffic the v0.1.0 build tripped a
  `multi_heap_free` assert at ~60 s into a tunnel: the lwIP UDP
  send path's internal pbuf_take/free interaction with a pool-backed
  pbuf doesn't preserve the refcount model the upstream code relies
  on. PBUF_RAM (heap-backed) tolerates the same handoff because the
  caller-owns-payload invariant holds. Kept the static
  `wireguard_device` BSS instance change — that one is independent
  of the pbuf lifecycle and worked cleanly. Saves ~1.1 KB of
  per-cycle max_alloc residue; the per-packet pbuf churn savings
  the PBUF_POOL change targeted are deferred until we have a deeper
  analysis of lwIP's pbuf refcount path.

* **v0.1.0** — Initial fork. (`pbuf_alloc → PBUF_POOL` everywhere,
  plus `wireguard_device → BSS`.) Asserts on live tunnel — DO NOT
  USE. Bumped pinning to v0.1.1 in `WireGuardModule`.

## `src/wireguardif.c`

### `wireguardif_initiate_handshake` (line ~413)
- **Was:** `pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct message_handshake_initiation), PBUF_RAM);`
- **Now:** `... PBUF_POOL` (same call shape; allocator changed).
- **Why:** Handshake initiation is fixed-size (~148 B) — fits in one `PBUF_POOL_BUFSIZE` entry. The MEMP pool is pre-allocated in BSS at boot; allocating from it doesn't touch the system heap. Eliminates one of the per-handshake-cycle fragmentation sources.

### `wireguardif_send_handshake_response` (line ~444)
- **Was:** `pbuf_alloc(... PBUF_RAM)`
- **Now:** `pbuf_alloc(... PBUF_POOL)`
- **Why:** Same as above — fixed-size packet, MEMP-friendly.

### `wireguardif_send_handshake_cookie` (line ~495)
- **Was:** `pbuf_alloc(... PBUF_RAM)`
- **Now:** `pbuf_alloc(... PBUF_POOL)`
- **Why:** Same.

### `wireguardif_output_to_peer` transport TX (line ~160)
- **Was:** single `pbuf_alloc(PBUF_TRANSPORT, header+padded+authtag, PBUF_RAM)`.
- **Now:** hybrid — `PBUF_POOL` when the total fits in one `PBUF_POOL_BUFSIZE` entry (true for typical MTU=1420), otherwise the original `PBUF_RAM`. The encrypt path below dereferences `pbuf->payload` across the whole length and requires a contiguous buffer; the size guard preserves that invariant either way.
- **Why:** Steady-state TX traffic now allocates from MEMP, zero heap touch. Atypical MTU configs degrade to upstream behaviour.

### `wireguardif_input` transport RX (line ~316)
- **Was:** `pbuf_alloc(PBUF_TRANSPORT, src_len - AUTHTAG, PBUF_RAM)` for the decrypted packet.
- **Now:** hybrid — same shape as TX.
- **Why:** Mirror of TX path.

### `wireguardif_init` device-struct allocation (line ~1011, original)
- **Was:** `device = mem_calloc(1, sizeof(struct wireguard_device));`
- **Now:** Reuse a file-scope `static struct wireguard_device s_wg_device`; guard with `static bool s_wg_device_inuse` to refuse a second concurrent init with `ERR_USE`.
- **Why:** `WIREGUARD_MAX_PEERS=1` enforces a single-tunnel invariant. Moving the ~1.1 KB struct from heap to BSS eliminates the largest single per-cycle fragmentation event. The inuse flag protects against re-init paths that would otherwise stomp the live struct.

### `wireguardif_init` failure path (line ~1108, original)
- **Was:** `mem_free(device); device = NULL;` after `wireguard_device_init` failed.
- **Now:** `s_wg_device_inuse = false; device = NULL;` — release the BSS slot so a retry can grab it.

### `wireguardif_shutdown` (line ~1010, original)
- **Was:** `free(device);` after disabling the UDP context.
- **Now:** `memset(device, 0, sizeof(*device)); s_wg_device_inuse = false;` — clear and release the slot.
- **Why:** No heap allocation to release, just state to reset.

### Includes
- Added `#include <stdbool.h>` for the `bool` type used by the inuse flag.

## `src/wireguard.c`, `src/wireguard.h`

No changes from upstream. The state machine + crypto are already
malloc-free.

## `src/wireguard-platform.c`, `src/wireguard-platform.h`

No changes. `WIREGUARD_MAX_PEERS=1` and `WIREGUARD_MAX_SRC_IPS=3`
defaults preserved.

## `src/WireGuard.cpp`, `src/WireGuard-ESP32.h`

No API changes. The C++ wrapper continues to call `netif_add` →
`wireguardif_init` → our patched device allocation path. Drop-in
compatible.

## Build files

- `library.json` — new (PlatformIO manifest).
- `library.properties` — new (Arduino IDE manifest).
- `README.md` — new.
- `docs/ANALYSIS.md` — new (design rationale + empirical heap data
  that motivated this fork).
- `CHANGES.md` — this file.
