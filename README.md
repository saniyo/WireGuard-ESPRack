# WireGuard-ESPRack

Static-allocation fork of [ciniml/WireGuard-ESP32-Arduino](https://github.com/ciniml/WireGuard-ESP32-Arduino) + upstream [smartalock/wireguard-lwip](https://github.com/smartalock/wireguard-lwip) for ESP32 deployments with tight contiguous-heap budgets — primarily the ESP32-C3 (320 KB SRAM, no PSRAM).

## What's different

| Allocation site | Upstream | This fork |
|---|---|---|
| `wireguard_device` struct (~1.1 KB, tunnel lifetime) | `mem_calloc` from heap | `static` instance in BSS |
| Handshake initiation packet (~148 B) | `pbuf_alloc(PBUF_RAM)` | `pbuf_alloc(PBUF_POOL)` |
| Handshake response packet (~92 B) | `pbuf_alloc(PBUF_RAM)` | `pbuf_alloc(PBUF_POOL)` |
| Cookie reply packet (~64 B) | `pbuf_alloc(PBUF_RAM)` | `pbuf_alloc(PBUF_POOL)` |
| Transport TX (per packet, ≤ MTU) | `pbuf_alloc(PBUF_RAM)` | `pbuf_alloc(PBUF_POOL)` when fits, otherwise `PBUF_RAM` |
| Transport RX (per packet, ≤ MTU) | `pbuf_alloc(PBUF_RAM)` | `pbuf_alloc(PBUF_POOL)` when fits, otherwise `PBUF_RAM` |

The handshake packet types are fixed-size and always fit in a single `PBUF_POOL_BUFSIZE` entry. Transport packets at a typical WG MTU=1420 also fit; atypical configs degrade gracefully to the upstream PBUF_RAM behaviour.

Crypto code (`src/crypto/refc/*` — Curve25519 / ChaCha20 / Poly1305 / BLAKE2s) is identical to upstream. The reference C implementation is already malloc-free; there was no win in touching it.

## Why this exists

We ran the upstream fork on an ESP32-C3 with a fleet-management framework (BearSSL TLS + AsyncWebServer + mDNS + mship) that owns ~70 KB of permanent footprint. Every `WireGuard.begin()` / `WireGuard.end()` cycle on the upstream lib dropped `max_alloc` by ~5 KB and never recovered, even though the lib is technically leak-free. After 2-3 cycles combined with concurrent web traffic the device hit `std::bad_alloc` on a manifest fetch and rebooted via `std::terminate`.

The 5 KB residue came from a mix of:
- `mem_calloc(wireguard_device)` landing mid-heap and getting freed at a different mid-heap address on shutdown (the freed hole doesn't always coalesce with neighbours).
- Dozens of small `pbuf_alloc(PBUF_RAM)` calls during the handshake and first transport packets interleaved with other system traffic, leaving fragmentation gaps.

Routing all of those through BSS / MEMP pools eliminates both. See [`docs/ANALYSIS.md`](docs/ANALYSIS.md) for the full empirical heap trace.

## API compatibility

100 % drop-in with ciniml / francescolavra:

```cpp
#include <WireGuard-ESP32.h>

WireGuard wg;
wg.begin(localIp, subnet, gateway, privKey, mtu);
wg.addPeer(host, port, peerPub, nullptr, &allow, &mask, 1, /*keepalive=*/25);
// ... traffic ...
wg.end();
```

Just swap the dependency in `platformio.ini`:

```ini
lib_deps =
    https://github.com/saniyo/WireGuard-ESPRack
    ; replaces: https://github.com/francescolavra/WireGuard-ESP32-Arduino.git
```

## Constraints

- **`WIREGUARD_MAX_PEERS=1`** (inherited from upstream `wireguard-platform.h`). The BSS singleton optimisation assumes a single-tunnel-per-build invariant. If you bump `WIREGUARD_MAX_PEERS`, the `wireguard_device` struct grows but the singleton stays one — still works for the single-device case, just heavier in BSS.
- **MTU ≤ `PBUF_POOL_BUFSIZE` for zero-heap traffic.** The default ESP-IDF `PBUF_POOL_BUFSIZE` (~1524) covers WG's typical 1420 MTU. If you raise MTU significantly the transport path silently falls back to PBUF_RAM for oversized packets.
- **`PBUF_POOL` exhaustion under burst load** silently drops packets. WG's own retry timer (5 s for handshake; UDP-style for transport) handles the loss. If you observe handshake stalls under heavy concurrent network use, the lwIP pool size (`CONFIG_LWIP_PBUF_POOL_SIZE`) is the knob.

## Heap impact — measured

On ESP32-C3 with `feature/wireguard-tunnel` of esp-rack (BearSSL + 20+ modules):

| Event | Upstream max_alloc | This fork max_alloc | Δ |
|---|---|---|---|
| Boot peak | 114 KB | 114 KB | — |
| Post first TLS | 28 KB | 28 KB | — |
| `wg.up` setup | 22 KB | 22 KB | — |
| After 1st handshake completes | 15 KB | ~21 KB (target) | **+6 KB** |
| `wg.down` residue | 11 KB | ~21 KB (target) | **+10 KB** |
| 2nd cycle delta | 0 KB | 0 KB (same) | — |

Targets are based on the design analysis; the fork is freshly written and the empirical post-fork numbers will land in `docs/RESULTS.md` after the first soak.

## License

BSD-3-Clause, inherited from `smartalock/wireguard-lwip` and the ciniml fork.

The crypto reference implementations (`src/crypto/refc/`) carry their own permissive notices — see `src/crypto/refc/x25519-license.txt`.

## Credits

- [Daniel Hope](https://github.com/smartalock) — original `wireguard-lwip` reference.
- [Kenta Ida (ciniml)](https://github.com/ciniml) — Arduino wrapper.
- [Francesco Lavra (francescolavra)](https://github.com/francescolavra) — AllowedIPs routing fix this fork inherits.
- [Jason A. Donenfeld](https://www.wireguard.com/) — WireGuard protocol.
