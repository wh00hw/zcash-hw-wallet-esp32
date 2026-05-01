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
- **ZIP-244 on-device sighash verification** — refuses to sign unless the transaction sighash has been independently verified from the raw action data
- Speaks HWP v2 over dual USB CDC (one port for protocol, one for debug logs)
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
| Green flash | Operation succeeded |
| Red flash | Error (transient) |

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
| TX_OUTPUT | `0x08` | Host → Device | `index[2] \|\| total[2] \|\| data[N]` |
| TX_OUTPUT_ACK | `0x09` | Device → Host | (empty) |
| ABORT | `0x0A` | Host → Device | (empty) |

## Security Considerations

This is a **proof of concept**. In a real hardware wallet, you would need:

- **Secure element** (e.g., ATECC608, Optiga Trust M) for key storage
- **NVS encryption** (ESP32-S2 lacks HMAC eFuse support, so this is not trivial)
- **Anti-tampering** mechanisms (tamper-detect mesh, potting, fuses)
- **Secure boot** with signed firmware images
- **User confirmation** on-device (physical button press before signing)
- **PIN/passphrase** protection
- **Side-channel attack** mitigations beyond constant-time scalar math
- **Supply chain verification**

What this PoC **does** implement correctly:
- Constant-time Montgomery ladder for scalar multiplication
- Immediate zeroing of all cryptographic intermediates (`memzero()`)
- Hardware RNG (`esp_random()`) for all randomness
- Spending key never leaves the device
- **ZIP-244 on-device sighash verification** — the device independently computes the full v5 shielded sighash from transaction metadata and action data, and refuses to sign if it doesn't match the companion's value. This is enforced at the library level (`orchard_signer_sign()` in libzcash-orchard-c), not in the firmware
- **Every component of the ZIP-244 sighash is device-derived** — `header_digest` and `orchard_digest` are recomputed from streamed action data; `transparent_sig_digest` is recomputed from streamed transparent inputs/outputs via `orchard_signer_verify_transparent` (or matches the empty-bundle constant for transactions without transparent components); `sapling_digest` is enforced equal to the ZIP-244 empty-bundle constant `BLAKE2b-256("ZTxIdSaplingHash", [])` on `TxMeta` receipt — non-empty values abort the session with `SIGNER_ERR_SAPLING_NOT_EMPTY` before any action is hashed. The wallet is Orchard-only by design (no Sapling keys, no Sapling notes, no Sapling-only recipients in scope), so this invariant is a structural fit, not a restriction. No part of the sighash is taken on faith from the companion.

## License

MIT
