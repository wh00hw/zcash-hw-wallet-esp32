# Zcash Orchard Hardware Wallet PoC — ESP32-S2

> **Proof of Concept / Educational Project**
>
> This is a **non-production** hardware wallet that demonstrates Zcash Orchard shielded transaction signing on a microcontroller. It is **NOT** anti-tampering, does **NOT** use a secure element, and stores the mnemonic in unencrypted NVS flash. **Do not use this with real funds.** It exists purely as a reference implementation and learning tool for Zcash shielded hardware signing.

## What This Is

A complete, working Zcash Orchard hardware wallet firmware for the **Flipper Zero WiFi Dev Board v1** (ESP32-S2). Communicates via the HWP (Hardware Wallet Protocol) v2 binary protocol over USB. Any companion app built on the [zcash-hw-signer-sdk](https://github.com/wh00hw/zcash-hw-signer-sdk) Rust SDK can pair with and sign transactions through this device.

The firmware:

- Generates a BIP39 24-word mnemonic on first boot
- Derives Zcash Orchard keys via ZIP-32 (Pallas curve, Sinsemilla hash)
- Caches derived keys (FVK, UA) in NVS for instant subsequent boots
- Signs shielded transactions with RedPallas spend authorization
- **ZIP-244 on-device sighash verification** — recomputes header / orchard / transparent digests on-device; enforces sapling_digest equal to the ZIP-244 empty-bundle constant
- **NoteCommitment (cmx) verification** — recomputes Sinsemilla NoteCommit per Orchard action from the unencrypted note plaintext (recipient, value, rseed) and rejects recipient-substitution attempts before any data is shown to the user
- **Per-output user confirmation** — for each Orchard output, displays the recipient (encoded as a Bech32m Unified Address) and value on the debug log, requires an explicit BOOT-button press, and blocks signing until the libzcash signer state machine has every action confirmed
- **No-blind-signing invariant enforced by the C library** — the device cannot produce a signature unless sapling-empty + cmx-match + user-confirm + sighash-match all pass. Skipping any of them returns a typed error before RedPallas is invoked.
- Speaks HWP v3 over dual USB CDC (one port for protocol, one for debug logs)
- Never exposes the spending key — only the full viewing key leaves the device

## Architecture

```
                    USB Cable (single)
                    ┌────────────────────┐
                    │  /dev/ttyACM0      │  HWP binary protocol (companion app)
  ┌──────────┐      │  /dev/ttyACM1      │  Debug logs (ESP_LOG*)
  │ ESP32-S2 ├──────┤                    ├──────── Host PC
  │ WiFi Dev │      │  Dual USB CDC      │
  │ Board v1 │      │  (TinyUSB)         │
  └──────────┘      └────────────────────┘
```

## Dependencies

| Component | Description |
|---|---|
| [ESP-IDF v5.x](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/) | Espressif IoT Development Framework |
| [libzcash-orchard-c](https://github.com/wh00hw/libzcash-orchard-c) | Pure-C Zcash Orchard crypto (included as git submodule) |
| [zcash-hw-signer-sdk](https://github.com/AnyWHR/zcash-hw-signer) | Rust SDK for HWP protocol (companion app integration) |

## Project Structure

```
zcash-esp32/
├── CMakeLists.txt                          # ESP-IDF project root
├── sdkconfig.defaults                      # ESP32-S2 build defaults
├── main/
│   ├── CMakeLists.txt                      # Main component build
│   ├── main.c                              # Entry point, HWP command handler
│   ├── wallet.h / wallet.c                 # Key management (NVS + Orchard derivation)
│   ├── usb_transport.h / usb_transport.c   # Dual USB CDC driver (HWP + logs)
│   ├── led_status.h / led_status.c         # RGB LED status indicator
│   └── platform_rng.c                      # esp_random() → random32() bridge
├── components/
│   └── libzcash-orchard-c/
│       ├── CMakeLists.txt                  # ESP-IDF component wrapper
│       ├── platform_rng.c                  # Hardware RNG glue
│       └── lib/                            # Git submodule → libzcash-orchard-c
└── tools/
    ├── hwp_ping.py                         # PING/PONG test script
    └── hwp_test.py                         # Extended HWP protocol test
```

## Setup

### 1. Install ESP-IDF

Follow the [official guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/) for your platform. This project requires ESP-IDF **v5.x**.

```bash
# After installation, source the environment
. $HOME/esp/esp-idf/export.sh
```

### 2. Clone with Submodules

```bash
git clone --recurse-submodules https://github.com/wh00hw/zcash-hw-wallet-esp32.git
cd zcash-hw-wallet-esp32
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

### 3. Build

```bash
idf.py set-target esp32s2
idf.py build
```

### 4. Flash

The Flipper Zero WiFi Dev Board v1 requires **manual download mode** because the USB is driven by TinyUSB firmware (no auto-reset via DTR/RTS):

1. **Hold BOOT** button on the dev board
2. **Press and release RESET**
3. **Release BOOT** — the board is now in download mode
4. Flash:

```bash
idf.py -p /dev/ttyACM0 flash
```

5. Press **RESET** to boot the firmware

To erase everything (including the wallet/mnemonic):

```bash
# Enter download mode first (BOOT + RESET), then:
idf.py -p /dev/ttyACM0 erase-flash
```

## Usage

### First Boot

On first boot (empty NVS), the firmware:

1. Generates a 24-word BIP39 mnemonic
2. Stores it in NVS
3. Derives the full viewing key (FVK) and unified address (UA)
4. Caches derived keys in NVS for instant subsequent boots

The mnemonic is printed **once** to the debug log port (ACM1) during first boot. Open the log port **before** powering the board to capture it:

```bash
# Terminal 1: debug logs
cat /dev/ttyACM1

# Then plug in / reset the board
```

The first boot takes ~80 seconds due to Pallas curve operations on the ESP32-S2. Subsequent boots are instant (cached keys).

### Dual USB CDC

The device exposes **two serial ports** over a single USB cable:

| Port | Purpose | Usage |
|---|---|---|
| `/dev/ttyACM0` | HWP binary protocol | Companion app (via zcash-hw-signer-sdk) |
| `/dev/ttyACM1` | Debug logs (ESP_LOG) | `cat /dev/ttyACM1` or `picocom /dev/ttyACM1 -b 115200` |

### Companion App Integration

Any companion app built with the [zcash-hw-signer-sdk](https://github.com/AnyWHR/zcash-hw-signer) can communicate with this device over `/dev/ttyACM0`. The SDK handles the HWP framing, CRC, and handshake automatically.

**Pairing (FVK export):**

```
Device  ──PING──→  Companion
Device  ←─PONG───  Companion
Device  ←FVK_REQ─  Companion
Device  ─FVK_RSP─→ Companion  (96 bytes: ak || nk || rivk)
```

The companion creates a watch-only wallet from the exported FVK.

**Signing:**

```
Device  ──PING──→  Companion
Device  ←─PONG───  Companion
Device  ←SIGN_REQ─ Companion  (sighash + alpha + amount + fee + recipient)
Device  ─SIGN_RSP→ Companion  (sig[64] || rk[32])
```

### LED Status

The dev board's RGB LED indicates the current state:

| LED | State |
|---|---|
| Blue blinking | Initializing / deriving keys / signing |
| Green solid | Ready / companion connected |
| Cyan breathing | Receiving transaction outputs |
| **Magenta blinking** | **Awaiting per-output user confirmation — press BOOT to approve, hold to cancel** |
| Green flash | Operation succeeded |
| Red flash | Error (transient) |

### Per-Output User Confirmation

After the device has streamed and verified every Orchard action's NoteCommitment but **before** the ZIP-244 sighash is finalized and signing is allowed, the firmware drives a per-output review loop. For each output:

1. Encodes the recipient `(d, pk_d)` into a Bech32m Unified Address via `orchard_encode_ua_raw`
2. Logs to the debug port (`/dev/ttyACM1`):
   ```
   [Output i/N]
     To:    u1...
     Value: 0.50000000 ZEC (50000000 zatoshis)
   → press BOOT to confirm, hold to cancel
   ```
3. Sets the LED to magenta blinking (`LED_STATE_AWAITING_CONFIRM`)
4. Waits up to 2 minutes for a **BOOT button** press (GPIO0):
   - **Short press** → calls `orchard_signer_confirm_action(idx)`, advances to next output
   - **Long press (≥ 2 s)** → cancel; signing is aborted with `HWP_ERR_USER_CANCELLED`
   - **Timeout** → cancel as above

After all outputs are confirmed, the libzcash signer state machine accepts `verify()`, transitions to `SIGNER_VERIFIED`, and a subsequent `SIGN_REQ` produces a signature. Without all confirmations, `orchard_signer_verify()` returns `SIGNER_ERR_ACTION_NOT_CONFIRMED` and `orchard_signer_sign()` returns `NOT_VERIFIED` — the firmware cannot bypass this; it is a C-library state-machine invariant.

> **Note on UX limits.** GPIO0 is the BOOT button on the Flipper WiFi Dev Board v1 — a single momentary push-to-ground input is the only physical control the user has. This is sufficient to enforce the security invariant (refuse-without-confirm) but is a minimal UX. The full per-output UI (screen + 4 buttons + scrollable UA) lives on [FlipZcash](https://github.com/wh00hw/FlipZcash) — the ESP32 reference port is for protocol and library-level demonstrations.

### Test Scripts

```bash
# Send a PING and wait for PONG
python3 tools/hwp_ping.py /dev/ttyACM0

# Extended protocol test (PING + FVK request)
python3 tools/hwp_test.py /dev/ttyACM0
```

## HWP Protocol v2

Binary framed serial protocol over USB CDC at 115200 baud.

### Frame Format

```
[MAGIC:1][VERSION:1][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
```

- **MAGIC**: `0xFB`
- **VERSION**: `0x02`
- **CRC**: CRC-16/CCITT (poly `0x1021`, init `0xFFFF`)
- **Max payload**: 512 bytes

### Message Types

| Type | Value | Direction | Payload |
|---|---|---|---|
| PING | `0x01` | Device → Host | (empty) |
| PONG | `0x02` | Host → Device | (empty) |
| FVK_REQ | `0x03` | Host → Device | (empty) |
| FVK_RSP | `0x04` | Device → Host | `ak[32] \|\| nk[32] \|\| rivk[32]` |
| SIGN_REQ | `0x05` | Host → Device | `sighash[32] \|\| alpha[32] \|\| amount[8] \|\| fee[8] \|\| recipient_len[1] \|\| recipient[N]` |
| SIGN_RSP | `0x06` | Device → Host | `sig[64] \|\| rk[32]` |
| ERROR | `0x07` | Device → Host | `error_code[1] \|\| message[N]` |
| TX_OUTPUT | `0x08` | Host → Device | `index[2] \|\| total[2] \|\| data[N]` (see TX_OUTPUT layout below) |
| TX_OUTPUT_ACK | `0x09` | Device → Host | (empty) |
| ABORT | `0x0A` | Host → Device | (empty) |

**TX_OUTPUT data layout** depends on `index`:

- `index = 0xFFFF` (TxMeta): 129 bytes — `version[4] || version_group_id[4] || consensus_branch_id[4] || lock_time[4] || expiry_height[4] || orchard_flags[1] || value_balance[8 LE] || anchor[32] || transparent_sig_digest[32] || sapling_digest[32] || coin_type[4 LE]`
- `index = 0..N-1` (Orchard action, v4): 903 bytes — `cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80] || recipient[43] || value[8 LE] || rseed[32]`. The trailing 83 bytes (note plaintext) let the device recompute `cmx` and verify it commits to the claimed recipient/value/rseed.
- `index = N` (sentinel): 32 bytes — expected ZIP-244 sighash for device comparison.

**Selected error codes** (over the standard set):

| Code | Name | Meaning |
|---|---|---|
| `0x0B` | `TransparentDigestMismatch` | Device-recomputed transparent digest ≠ value in TxMeta |
| `0x0C` | `SaplingNotEmpty` | `sapling_digest` ≠ ZIP-244 empty-bundle constant — Orchard-only invariant violation |
| `0x0D` | `NoteCommitmentMismatch` | Device-recomputed cmx ≠ action.cmx — recipient-substitution attempt |
| `0x06` | `UserCancelled` | User long-pressed BOOT during per-output review or timed out |

## Security Considerations

This is a **proof of concept**. In a real hardware wallet, you would need:

- **Secure element** (e.g., ATECC608, Optiga Trust M) for key storage
- **NVS encryption** (ESP32-S2 lacks HMAC eFuse support, so this is not trivial)
- **Anti-tampering** mechanisms (tamper-detect mesh, potting, fuses)
- **Secure boot** with signed firmware images
- **PIN/passphrase** protection
- **Side-channel attack** mitigations beyond constant-time scalar math
- **Supply chain verification**
- **Production-grade UI** — a single BOOT button + serial log is enough to enforce the per-output confirmation invariant, but a real device would have a dedicated screen and dedicated approve/cancel buttons

What this PoC **does** implement correctly:

- **Constant-time scalar multiplication** — Montgomery ladder, no branching on secret bits
- **Immediate zeroing of all cryptographic intermediates** (`memzero()`)
- **Hardware RNG** — `esp_random()` for all randomness
- **Spending key never leaves the device** — only FVK and UA are exported
- **ZIP-244 on-device sighash verification** — `header_digest` and `orchard_digest` recomputed from streamed action data; `transparent_sig_digest` recomputed from streamed transparent inputs/outputs via `orchard_signer_verify_transparent` (or empty-bundle constant when no transparent components); `sapling_digest` enforced equal to the ZIP-244 empty-bundle constant on `TxMeta` receipt (non-empty values abort with `SIGNER_ERR_SAPLING_NOT_EMPTY` before any action data is hashed). No part of the sighash is taken on faith from the companion.
- **Per-action NoteCommitment recomputation** — for every Orchard action, the device recomputes `cmx = Extract_P(NoteCommit(g_d, pk_d, value, rho, psi))` from the unencrypted note plaintext (`recipient`, `value`, `rseed`) the companion declares, and rejects mismatches with `SIGNER_ERR_NOTE_COMMITMENT_MISMATCH`. Closes the recipient-substitution attack a hostile companion would otherwise mount inside the Orchard bundle.
- **Per-output user confirmation as a state-machine invariant** — `orchard_signer_verify()` refuses to advance to `SIGNER_VERIFIED` unless every action has been explicitly confirmed via `orchard_signer_confirm_action()`, and `orchard_signer_sign()` refuses with `NOT_VERIFIED` unless the state is `VERIFIED`. The firmware drives the confirmation loop (CDC log + BOOT-button press per output) but cannot bypass the lib's check; a build that skipped the UI would still be unable to extract a signature. This is the "no blind signing" guarantee, expressed as a C-library invariant.
- **Orchard-only by design** — no Sapling keys derived, no Sapling notes ever held, no Sapling-only recipients accepted. The Sapling-component lockout is a structural fit of the wallet, not an arbitrary restriction.

## License

MIT
