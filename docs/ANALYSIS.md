# WireGuard-ESPRack — analysis & design rationale

A static-allocation fork of [smartalock/wireguard-lwip](https://github.com/smartalock/wireguard-lwip) + [ciniml/WireGuard-ESP32-Arduino](https://github.com/ciniml/WireGuard-ESP32-Arduino) for ESP32-C3 (320 KB SRAM, no PSRAM).

## Why fork

We ran the upstream ciniml/francescolavra fork on an ESP32-C3 with a
fleet-management framework that owns ~70 KB of permanent footprint
(BearSSL TLS, AsyncWebServer, mDNS, mship). The framework reaches a
working max_alloc of ~28 KB at first checkin. Every WireGuard
up→down cycle drops max_alloc by ~5 KB, and after 2-3 cycles
combined with concurrent web traffic the device hits std::bad_alloc
on a manifest fetch and reboots via std::terminate. The data behind
that — measured on the device — is collected at the bottom of this
document.

The forks themselves (smartalock, ciniml, francescolavra, trombik,
droscy) all share the same `wireguardif.c` + `wireguard.c` + refc
crypto. None of them ship a static-allocation path. Researching
alternatives (microlink, esp_wireguard) found the same code with
different wrappers; no embedded-friendly version exists in the open
source ecosystem.

So we fork ciniml's tree and rewrite the allocation paths.

## What's wrong with the upstream allocation model

`wireguardif.c` (the lwIP integration shim) makes these heap calls:

| Site (line) | Call | Size | Lifetime | Cost |
|---|---|---|---|---|
| `wireguardif_initiate_handshake:413` | `pbuf_alloc(PBUF_RAM)` | ~148 B | one packet TX | freed within call |
| `wireguardif_send_handshake_response:444` | `pbuf_alloc(PBUF_RAM)` | ~92 B | one packet TX | freed within call |
| `wireguardif_send_cookie_reply:495` | `pbuf_alloc(PBUF_RAM)` | ~64 B | one packet TX | freed within call |
| `wireguardif_output_to_peer:160` | `pbuf_alloc(PBUF_RAM)` | up to MTU | one data packet TX | freed within call |
| `wireguardif_input:316` | `pbuf_alloc(PBUF_RAM)` | up to MTU | one data packet RX | freed within call |
| `wireguardif_add_peer:1011` | `mem_calloc(sizeof(wireguard_device))` | ~1.1 KB | lifetime of tunnel | freed in `wireguardif_shutdown` |
| internal | `udp_new()` | ~150 B (MEMP) | lifetime of tunnel | freed by `udp_remove` |
| internal | `netif_add()` | ~200 B (MEMP) | lifetime of tunnel | freed by `netif_remove` |
| internal | `sys_timeout()` | ~100 B (MEMP) | periodic | freed by `sys_untimeout` |

Theoretically all of this is symmetric — every alloc has a matching
free. In practice on the C3 with lwIP defaults (`PBUF_POOL_SIZE=12`
+ `MEMP_NUM_PBUF=16` + `MEM_SIZE=` baked in to ESP-IDF's prebuilt
arduino-esp32), the heap behaviour we measured is:

```
Boot peak              max_alloc=57,332  free=77,296
After 1st TLS checkin  max_alloc=15,860  free=49,148   (-41 KB transient holes)
WG up — setup only     max_alloc=15,860  free=42,704   (begin+addPeer = -1.6 KB free)
WG up + handshake done max_alloc=14,836  free=44,948   (-1 KB stable cost)
WG down                max_alloc=11,252  free=39,432   (-3.6 KB residue per cycle)
WG up — cycle 2        max_alloc=11,252  free=34,684   (0 KB additional max_alloc)
```

**Cycle 1 loses 4-5 KB max_alloc. Cycle 2 loses 0 KB.** So the
upstream library is technically leak-free — the 4-5 KB is a one-shot
cost of lwIP's lazy state expansion the first time WG transports a
packet. But:

1. The cost is paid *in the middle* of the heap — a contiguous hole
   right where a future TLS/web buffer would have fit. Even the
   first cycle is enough to break the "I'll need to alloc 8 KB for
   a manifest fetch later" calculation we depend on.
2. The cost compounds with the concurrent traffic during cycle 1:
   web fetches go through the WG tunnel, mship checkins retry over
   the same socket, AsyncWebServer's per-request state piles up on
   the residue → min_free_ever dropped to **912 B** in one of our
   soak runs. Two more cycles and the device aborts on a 5 KB
   ManifestBuilder allocation.

So even though cycle 1 is "only" 5 KB, the practical effect is the
difference between "device works indefinitely" and "device reboots
after 3-5 reconnects".

## What we can and can't fix

| Fixable in this library | Why |
|---|---|
| `mem_calloc(wireguard_device)` | The struct is a fixed size known at compile time. Make it a `static` instance in BSS. |
| `pbuf_alloc(PBUF_RAM)` for handshake packets | The three handshake messages have fixed sizes. Use `pbuf_alloc(PBUF_POOL, ...)` (preallocated MEMP) or a custom `PBUF_REF` wrapper around a BSS buffer. |
| `pbuf_alloc(PBUF_RAM)` for transport data | Variable size, but bounded by MTU (1420 B). Use `PBUF_POOL` chains. |
| `sys_timeout()` per device | Single timer per device. Statically register at boot if API allows. |

| NOT fixable in this library | Why |
|---|---|
| `udp_new()` | Goes to lwIP's `MEMP_UDP_PCB` pool — pre-allocated size set by `CONFIG_LWIP_UDP_PCB`. Tuning means rebuilding ESP-IDF, blocked on pioarduino's prebuilt arduino-esp32. |
| `netif_add()` | Same — `MEMP_NUM_NETIF`. Pre-allocated. |
| Route table expansion when WG netif up | lwIP's routing isn't a per-netif heap allocation; routes piggy-back on netif structures already in MEMP. |
| ARP cache for peer endpoint | lwIP's `MEMP_NUM_ARP_QUEUE`. Pre-allocated. |
| lwIP PBUF_POOL lazy growth | Pool fixed at compile time. |

**Implication:** the 4-5 KB cycle-1 residue we measured on stock
arduino-esp32 mostly comes from MEMP pool allocations that happen
in lwIP, *not* from heap. Those land in BSS once and don't grow per
cycle. The actual library-side heap deltas (the `mem_calloc` of the
device struct + a handful of `pbuf_alloc(PBUF_RAM)` calls) are
collectively under 1.5 KB.

So the upper bound of what this fork can save is **~1.5 KB
permanent + transient pbufs per packet**. The bigger win is
indirect:

* Transient pbufs that come and go (one per outbound packet, one
  per inbound packet, plus retries) DO fragment the heap because
  they alloc-then-free at unpredictable moments. Switching them to
  `PBUF_POOL` makes the alloc come out of a MEMP pool — zero heap
  fragmentation, zero `max_alloc` impact.

That's where the real win lives. Not in total bytes, but in
fragmentation behaviour.

## Design — what the fork changes

### Goals

1. Zero heap allocation in the steady-state TX/RX path.
2. Zero heap allocation in the handshake path.
3. Single one-time BSS cost for the `wireguard_device` struct.
4. Drop-in compatible API with ciniml/francescolavra so consumers
   (esp-rack's WireguardService) don't need code changes.
5. Same BSD-3 license as upstream.
6. No changes to the crypto code (refc/* stays bit-identical —
   already malloc-free, no point touching it).

### Changes

#### 1. Static `wireguard_device` instance

```c
// wireguardif.c — was:
device = mem_calloc(1, sizeof(struct wireguard_device));

// becomes:
static struct wireguard_device s_device;  // file scope, BSS
static bool s_device_inuse = false;
// ...
if (s_device_inuse) return ERR_USE;
s_device_inuse = true;
device = &s_device;
memset(device, 0, sizeof(*device));
```

Only one tunnel per program — matches the
`WIREGUARD_MAX_PEERS=1` invariant the upstream lib already enforces
on this build target.

Savings: 1.1 KB of one-shot heap → BSS.

#### 2. Handshake pbufs via PBUF_POOL

The three handshake packet types have fixed sizes (`sizeof(struct
message_handshake_initiation)` etc.). Use `PBUF_POOL` instead of
`PBUF_RAM` — comes from `MEMP_NUM_PBUF_POOL` (LWIP_PBUF_POOL_SIZE
default 16 on ESP-IDF arduino-esp32).

```c
// was:
pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct message_handshake_initiation), PBUF_RAM);

// becomes:
pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct message_handshake_initiation), PBUF_POOL);
```

Fallback to PBUF_RAM if `PBUF_POOL` is exhausted? Probably not —
under back-pressure we want to *drop* the handshake packet (WG will
retry on its own ~5 s timer) rather than fragment heap.

Savings: ~150 B × ~4 packets per handshake = ~600 B of heap churn,
moved to MEMP.

#### 3. Transport data pbufs via PBUF_POOL chains

For TX (`wireguardif_output_to_peer`) and RX
(`wireguardif_input`), the packet size is variable up to MTU. A
single `pbuf_alloc(PBUF_RAM)` call would still hit the heap. The
fix: allocate a `PBUF_POOL` *chain* — lwIP automatically links
multiple pool entries when the requested size exceeds one pool
slot. Each pool slot is `PBUF_POOL_BUFSIZE` (~512 B on ESP-IDF).
For an MTU-sized packet ~3 chain entries.

```c
pbuf = pbuf_alloc(PBUF_TRANSPORT, total_len, PBUF_POOL);
```

This is the bigger win — sustained traffic no longer fragments.

#### 4. Tunable BSS buffer mode (compile-time switch)

For users who want full BSS-resident allocation even for transport
data, expose:

```c
#ifndef WIREGUARD_USE_PBUF_POOL
#define WIREGUARD_USE_PBUF_POOL 1
#endif

#ifndef WIREGUARD_USE_STATIC_TX_BUFFER
#define WIREGUARD_USE_STATIC_TX_BUFFER 0
#endif
```

When `WIREGUARD_USE_STATIC_TX_BUFFER=1`, the TX path renders into a
single MTU-sized BSS buffer + uses `pbuf_alloc(PBUF_REF, ...)` to
wrap it. This serializes TX through one buffer (no concurrent
multi-packet TX) but guarantees zero heap touch. Default off
because most use cases don't need it.

#### 5. Diagnostic mode

Add `wireguard_heap_stats()` that reports:
- bytes allocated by THIS library since boot
- bytes freed since boot
- current outstanding allocations
- highest seen outstanding

Lets the caller verify the library lives within its declared budget
under their workload.

## Risks

1. **PBUF_POOL exhaustion** under burst load. Stock lwIP's pool is
   16 entries × 512 B = 8 KB total. If WG saturates it, other lwIP
   users (mship TLS, AsyncWebServer) starve. Mitigation: drop
   handshake packets gracefully (WG retries), drop transport
   packets gracefully (TCP retransmits / UDP is allowed to drop).

2. **MEMP pool pressure changes the contiguous-heap picture
   indirectly**. Allocating from `MEMP_PBUF_POOL` doesn't touch the
   "free heap" number but DOES consume the pre-allocated MEMP
   region. If we exhaust the pool, lwIP can't grow it (sizes are
   compile-time). Need to make sure we don't push other components
   off a cliff. Real-world soak will tell.

3. **API stability**. The drop-in goal pins us to ciniml's surface
   (`WireGuard::begin/end/addPeer/...`). If they evolve, we have to
   keep up.

## Acceptance criteria

After the fork is wired in:

1. Boot heap delta from upstream: ≤ +1 KB BSS (`wireguard_device`
   one-time → moved to BSS).
2. First WG cycle `max_alloc` delta: ≤ 1 KB (was ~5 KB).
3. Subsequent cycles: 0 KB (matches upstream behaviour).
4. 10 consecutive WG up/down cycles with concurrent web traffic on
   C3: no `std::terminate`, no reboot.
5. End-to-end traffic still works: ping over tunnel, HTTP over
   tunnel, no packet loss in normal soak.

## Empirical data this design is based on

Measurements from a real session on
`feature/wireguard-tunnel` branch of esp-rack on ESP32-C3:

```
Boot phase                  free     max_alloc  min_free_ever
boot:enter                  207,372  114,676    179,388
boot:wifi-mode-set          149,152  114,676    148,664   (-56 KB free, 0 max_alloc)
boot:modules-begun          118,476   98,292     98,496   (-30 KB free, -16 KB max_alloc)
boot:server-started          77,296   57,332     77,068   (further -41 KB free, -41 KB max_alloc)
post-warmup (1st TLS done)   49,148   28,660     38,016   (TLS handshake transient -29 KB max_alloc)

WG cycle 1 — clean (no concurrent web):
wg.up-pre                    44,564   22,516     40,108
wg.up-post                   42,704   22,516     31,424   (begin+addPeer = -1.6 KB free, 0 max_alloc)
wg.up+200ms                  47,300   15,860      6,888   (handshake fires: free dips then recovers)
wg.up+2s                     47,300   15,860      6,888   (steady)
wg.up+10s                    47,356   15,860      6,888
wg.down-pre                  39,504   12,788      2,092   (-5 KB max_alloc residue after 2 min idle)
wg.down-post                 41,372   12,788      2,092

WG cycle 2 — clean:
wg.up-pre                    41,068   11,252      1,960
wg.up-post                   39,656   11,252      1,960
wg.up+10s                    39,656   11,252      1,960   (ZERO additional max_alloc cost)

WG cycle 3 — with concurrent web (browser open via tunnel):
[abort()] __cxxabiv1::__terminate at ManifestBuilder std::make_shared
```

The story this tells:

* Per-cycle library overhead: ~5 KB once, 0 KB after.
* The handshake itself uses transient buffers freed within the
  same call — they appear as a momentary `min_free` dip (6 KB) but
  don't accumulate.
* The reboot is *not* a leak in the WG library. It's the
  combination of: small post-warmup max_alloc (28 KB),
  one-shot 5 KB residue from WG, plus concurrent web alloc that
  needs ≥5 KB contiguous, plus the device's heap fragmentation
  already eating into the budget elsewhere.

Eliminating the WG-side 5 KB is therefore necessary but not
sufficient. It buys ~2-3 more reconnect cycles before pressure
elsewhere bites. The framework still needs the per-request
ManifestBuilder + OOM guard work done on the esp-rack side. This
library handles the WG half.
