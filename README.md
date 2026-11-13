# Zcash Orchard/Ironwood signer — ESP32-S2 reference port

> **This is not a hardware wallet.** It is a reference port of the
> [libzcash-ironwood-c](https://github.com/wh00hw/libzcash-ironwood-c) signing library to an
> ESP32-S2 development board, for protocol and library demonstrations. **Do not use it with
> real funds.** See [What this is not](#what-this-is-not).

> **Status (November 2026).** Ported to the November 2026 library API (on-device change
> detection, totals confirmation, transparent signing removed). The firmware **builds** with
> ESP-IDF v5.3 against library commit `65a8425` (the submodule pin), with no compiler warnings
> in the application or library components. It has **not been flashed or run since the port**: everything below
> about behaviour on the board describes what the code does, not something observed.
> The previous revision (3765ea5, library a55d168) could not complete a signature at all — see
> [Changes](#changes-november-2026).

## What this is

Firmware for the **Flipper Zero WiFi Dev Board v1** (ESP32-S2) that speaks the device side of
HWP (Hardware Wallet Protocol) over USB. A companion built on the
[zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk) Rust SDK can pair with it and
have shielded (Orchard / Ironwood, NU6.3) spends signed.

It uses the library's signer API directly (`orchard_signer.h`), with its own message loop in
`main/main.c`, rather than the library's `hwp_dispatcher`.

The firmware:

- generates a BIP-39 24-word mnemonic on first boot and seals it in NVS under a 5-digit PIN
  (AES-256-CTR + HMAC-SHA256, PBKDF2-HMAC-SHA512); 10 wrong PINs wipe the wallet;
- derives the Orchard keys via ZIP-32 for **one network, fixed at build time** (testnet unless
  `CONFIG_ZCASH_NETWORK_MAINNET` is set);
- exports the full viewing key to the companion (`FVK_RSP`);
- for each transaction, lets the library recompute the sighash, every note commitment and every
  ciphertext, classify each output as the wallet's own or not, and compute the totals;
- prints the review (outputs, memos, totals) to its **log port** and waits for the BOOT button
  for each step;
- signs with RedPallas only after the library's state machine has reached `SIGNER_VERIFIED`;
- answers device identity / attestation requests.

## What this is not

- **There is no display.** The board has one button and one LED. Everything the firmware
  "shows" for review — addresses, amounts, memos, totals — is written with `ESP_LOG*` to the
  second USB serial port (`/dev/ttyACM1`), i.e. **to the same computer that runs the
  companion**. A compromised host can hide or rewrite that text. Pressing BOOT therefore
  proves that someone pressed a button; it does not prove that they saw what the device
  verified. The property a hardware wallet exists to provide — a trusted screen — is absent.
- **The mnemonic is printed to that same log port** at first boot (and the PIN is entered by
  tap-count on the BOOT button).
- **No secure element, no tamper resistance.** Flash encryption and secure boot are not enabled
  by default; NVS encryption is off. Anyone who can read the flash gets the PIN-sealed mnemonic
  and can try all 100,000 PINs offline; anyone who can write it can replace the firmware.
- **Not audited.**

What is stored in NVS, all of it unencrypted at the NVS layer:

| Entry | Content | Protection |
|---|---|---|
| `pin_salt`, `pin_nonce`, `pin_tag`, `pin_sealed` | the mnemonic, sealed | AEAD under the PIN-derived key (5 digits: offline brute force is cheap) |
| `lockout` | failed-PIN counter | none (erasing it resets the counter) |
| `fvk_<coin>` | full viewing key `ak ‖ nk ‖ rivk` | **cleartext**. Not a spending key, but it reveals every incoming and outgoing transaction of the wallet |
| `ua2_<coin>` (and `ua_<coin>` from older firmware) | default Unified Address | cleartext |
| `device_sk` | device-identity secret scalar (attestation) | **cleartext**. Whoever reads the flash can impersonate this device's identity |
| `backed_up` | flag | — |

No spending key (`ask`), seed or mnemonic is stored in the clear. The cached FVK and address
are neither encrypted nor authenticated: someone who can rewrite the flash can make the device
announce a different viewing key or address at pairing. For that reason the signer does **not**
use the cache to decide which outputs are the wallet's own — it derives the viewing key from
the PIN-unsealed mnemonic for every transaction (`wallet_derive_fvk()`). The cache is still
what `FVK_RSP` and the boot banner use.

## Transparent inputs are not supported

The firmware signs **shielded spends only**. A frame announcing a transparent input is passed
to the library, which refuses it (`SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED`, HWP error
`0x18`); `TRANSPARENT_SIGN_REQ` is always refused with the same error. No transparent key is
derived (the BIP-32 and secp256k1 sources are not compiled in) and no transparent public key
is ever sent.

Earlier versions of this README claimed ECDSA signing of transparent inputs. That code is gone
from the firmware and disabled in the library, for the reasons the library's README gives:
what was signed for a transparent input was not the transaction's ZIP 244 signature hash (the
signatures were invalid on chain), a secp256k1 arithmetic bug made every derived public key
wrong (fixed since; the signing code stays disabled), and the scalar multiplication is not
constant-time in the nonce. Per the library, a transparent public key or t-address obtained
from an earlier revision is not the one the seed's standard BIP-44 key controls — do not use
one.

Paying **to** a transparent address from shielded funds is supported: the transparent outputs
are hashed into the transparent digest, printed as t-addresses in the review, and counted as
leaving the wallet. (The previous revision hashed them but never printed them.)

## The review

After the companion has streamed the transaction and sent the sighash sentinel, the firmware
prints, on `/dev/ttyACM1`, one block per step and waits up to 2 minutes for the BOOT button
(short press = approve, hold ≥ 2 s = cancel; cancel or timeout aborts the session):

```
[1/3] t-address PAYMENT - LEAVES THE WALLET            (transparent outputs first)
    Value: 1.50000000 TAZ (150000000 zatoshis)
    To:    tm...
[2/3] PAYMENT - LEAVES THE WALLET                      (shielded, not this wallet's)
    Value: 0.50000000 TAZ (50000000 zatoshis)
    To:    utest1...
    CHECK THIS ADDRESS: it is not one of this wallet's.
    Memo:  none                                        (or the memo, in full)
[3/3] CHANGE (your wallet)                             (decided on-device from its keys)
    Value: 0.49990000 TAZ (49990000 zatoshis)
    Memo:  none
TOTALS (computed on the device)
    TOTAL LEAVING THE WALLET: 2.00010000 TAZ
      of which fee:           0.00010000 TAZ
    payments to others: 1 shielded, 1 transparent
    change returning:         0.49990000 TAZ
    zero-value padding outputs (not shown): 0
```

- The label of each shielded output comes from the library's classification
  (`OrchardOutputInfo.ownership`): `CHANGE (your wallet)`, `YOUR ADDRESS` (one of the wallet's
  own receiving addresses), or a payment / message to an address that is not the wallet's.
  Nothing the host says is used for it.
- Outputs with `review_required == false` (zero value, verified to carry no memo — padding) are
  skipped; the library has already confirmed them and counts them in the totals.
- A memo is printed in full: text as printable ASCII (other bytes as `?`), anything else as hex.
- An amount above 21 million coins (it cannot exist on chain) is not printed: the review is
  refused and the session aborted.
- Approving the totals is the last confirmation: the firmware then calls
  `orchard_signer_confirm_totals()` and `orchard_signer_verify()`, and subsequent `SIGN_REQ`s
  are answered without a further prompt — at most one signature per action, after which the
  session is reset. The amount, fee and recipient fields of `SIGN_REQ` are ignored.

### What the library verifies

These are the library's claims (its README and `SECURITY.md`), not stronger ones:

- the device signs only the ZIP-244 (v6) sighash it computed itself; the header must be v6 with
  a consensus branch on the allow-list (NU6.3 and NU7 by default); Sapling must be empty; the
  transparent digest is recomputed from the streamed transparent outputs or must be empty;
- recipient and value of every output are recomputed through the note commitment;
- the ciphertext, memo included, of every output that carries value is re-encrypted and compared;
- whether an output is the wallet's change or own address is decided on-device from the
  device's own keys;
- fee and total leaving are computed on-device from data bound by the sighash; the total is an
  upper bound on what the wallet loses;
- `verify()` refuses until every output with a value or a memo, and the totals, were confirmed;
  `sign()` refuses before `verify()` succeeded.

### What is not verified

- the spend side (which notes are spent, their values, nullifiers, anchors) and the Halo 2 proof;
- expiry height and lock time: bound by the sighash, not printed;
- whether a transparent output is the wallet's own (always shown as leaving);
- **that the user saw the review** — see [What this is not](#what-this-is-not). The library
  orders the steps; it is not a barrier against the firmware, which holds the spending key and
  could bypass the library deliberately.

## Architecture

```
                    USB cable (single)
                    ┌────────────────────┐
                    │  /dev/ttyACM0      │  HWP binary protocol (companion app)
  ┌──────────┐      │  /dev/ttyACM1      │  logs AND the review text (ESP_LOG*)
  │ ESP32-S2 ├──────┤                    ├──────── Host PC
  │ WiFi Dev │      │  Dual USB CDC      │
  │ Board v1 │      │  (TinyUSB)         │
  └──────────┘      └────────────────────┘
```

## Dependencies

| Component | Description |
|---|---|
| [ESP-IDF v5.x](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/) | Espressif IoT Development Framework (built with v5.3) |
| [libzcash-ironwood-c](https://github.com/wh00hw/libzcash-ironwood-c) | Pure-C Zcash Orchard/Ironwood signing library, git submodule under `components/libzcash-ironwood-c/lib`. **Needs `17d4ee0` or later** (November 2026 API); this source does not compile against the older pin a55d168 |
| [zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk) | Rust SDK for the host side of HWP |

## Project structure

```
zcash-esp32/
├── CMakeLists.txt                          # ESP-IDF project root
├── sdkconfig.defaults                      # ESP32-S2 build defaults
├── main/
│   ├── main.c                              # Entry point, HWP message loop, review
│   ├── wallet.h / wallet.c                 # NVS storage, PIN flow, key derivation, attestation
│   ├── user_input.h / user_input.c         # BOOT-button driver (press, long press, PIN tap-count)
│   ├── usb_transport.h / usb_transport.c   # Dual USB CDC driver (HWP + logs)
│   ├── led_status.h / led_status.c         # RGB LED status indicator
│   └── Kconfig.projbuild                   # CONFIG_ZCASH_NETWORK_MAINNET, CONFIG_DEBUG_LOG_SECRETS
├── components/
│   └── libzcash-ironwood-c/
│       ├── CMakeLists.txt                  # ESP-IDF component wrapper (source list)
│       ├── platform_rng.c                  # esp_random() → random32() bridge
│       └── lib/                            # Git submodule → libzcash-ironwood-c
└── tools/                                  # Host-side test scripts
```

## Setup

### 1. Install ESP-IDF

Follow the [official guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/). ESP-IDF **v5.x** (built with v5.3).

```bash
. $HOME/esp/esp-idf/export.sh
```

### 2. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/wh00hw/zcash-hw-wallet-esp32.git
cd zcash-hw-wallet-esp32
```

To move the vendored library to a newer commit:

```bash
git submodule update --remote components/libzcash-ironwood-c/lib
git add components/libzcash-ironwood-c/lib
```

### 3. Build

```bash
idf.py set-target esp32s2
idf.py build
```

The device's network is a build option: `idf.py menuconfig` → *Zcash HW Wallet* →
*Device network: MAINNET*. Default is testnet; leave it there.

`sdkconfig.defaults` enables stack canaries and light heap poisoning and disables WiFi and
Bluetooth.

### 4. Flash

The Flipper Zero WiFi Dev Board v1 needs **manual download mode** (the USB port is driven by
the firmware's own TinyUSB stack):

1. Hold **BOOT**, press and release **RESET**, release **BOOT**
2. `idf.py -p /dev/ttyACM0 flash`
3. Press **RESET**

`idf.py -p /dev/ttyACM0 erase-flash` (in download mode) erases everything, wallet included.

## Usage

### First boot — provisioning

On first boot (empty NVS) the firmware:

1. generates a 24-word BIP-39 mnemonic and **prints it once to ACM1**;
2. asks for a 5-digit PIN by BOOT-button tap-count (`N` taps for digit `N`; 10 taps = `0`;
   a ~1.5 s pause confirms each digit; a long press cancels);
3. seals the mnemonic (PBKDF2-HMAC-SHA512, 150,000 iterations → AES-256-CTR + HMAC-SHA256) and
   stores salt, nonce, tag and ciphertext in NVS;
4. generates the device-identity scalar and prints its public key on ACM1;
5. derives the FVK and the default address and caches both in NVS.

Open the log port before powering the board to capture the mnemonic and the identity key:

```bash
cat /dev/ttyACM1
```

Timings on the board with the current library have not been measured.

### Later boots — PIN unlock

The firmware asks for the PIN, unseals the mnemonic into RAM (where it stays until power-off
or wipe) and only then accepts HWP traffic. Each wrong PIN increments a counter in NVS; after
10 in a row the wallet (seed, identity, caches) is wiped and the device halts.

If the default address cached by older firmware differs from the one derived now, both are
printed once with a notice: library releases up to a55d168 derived a different default address
for about half of all seeds; the old one still belongs to the same wallet.

### Dual USB CDC

| Port | Purpose |
|---|---|
| `/dev/ttyACM0` | HWP binary protocol (companion, via zcash-hw-wallet-sdk) |
| `/dev/ttyACM1` | Logs and the review text: `cat /dev/ttyACM1` |

### Protocol flow

```
Device  ──PING──→  Companion
Device  ←─PONG───  Companion
Device  ←FVK_REQ─  Companion   (coin_type[4 LE]; refused if it names the other network)
Device  ─FVK_RSP─→ Companion   (ak || nk || rivk)

Device  ←TX_OUTPUT──  Companion   (TxMeta @ index 0xFFFF)                    → ACK
        [ ←TX_TRANSPARENT_OUTPUT × n, then ←TX_TRANSPARENT_INPUT(0, 0, digest) ]   → ACK each
Device  ←TX_OUTPUT──  Companion   (action i of N, in order, 1416 bytes)      → ACK each
Device  ←TX_OUTPUT──  Companion   (sentinel @ index N: expected sighash[32])
            review on ACM1 + BOOT button, then sighash comparison            → ACK
Device  ←SIGN_REQ───  Companion   (sighash + alpha [+ amount, fee, recipient: ignored])
Device  ─SIGN_RSP──→  Companion   (sig[64] || rk[32])       at most one per action
```

Every `Error` frame the device sends ends the session and wipes the signer state, as does a
`PING` or `ABORT` from the host and a USB disconnect.

**Device identity / attestation:** `IDENTITY_REQ` → `device_pubkey[32]`; `ATTEST_REQ(challenge[32])`
→ `sig[64] || rk[32]`, a RedPallas signature with the identity scalar. It shows that the peer
holds that scalar — which is stored in cleartext in NVS (see above).

### LED status

| LED | State (`led_status.h`) |
|---|---|
| Blue blinking | `INITIALIZING` / `BUSY_KEY` / `BUSY_SIGN` |
| Green solid | `READY` / `CONNECTED` |
| Cyan breathing | `TX_PROGRESS` — receiving a transaction |
| **Magenta blinking** | **`AWAITING_CONFIRM` — press BOOT to approve, hold to cancel** |
| Green flash | `SUCCESS` (transient) |
| Red flash | `ERROR` (transient) |

### Test scripts

```bash
python3 tools/hwp_ping.py /dev/ttyACM0     # PING / PONG
python3 tools/hwp_test.py /dev/ttyACM0     # PING + FVK request
```

## HWP

Binary framed serial protocol over USB CDC. Frame:

```
[MAGIC:0xFB][VERSION:0x02][SEQ:1][TYPE:1][LENGTH:2 LE][PAYLOAD:N][CRC16:2 LE]
```

CRC-16/CCITT (poly `0x1021`, init `0xFFFF`); maximum payload 2048 bytes (library default).

| Type | Value | Direction | Payload / behaviour on this firmware |
|---|---|---|---|
| PING / PONG | `0x01` / `0x02` | either | empty. A PING resets the signing session |
| FVK_REQ | `0x03` | Host → Device | `coin_type[4 LE]` (optional) |
| FVK_RSP | `0x04` | Device → Host | `ak[32] \|\| nk[32] \|\| rivk[32]` |
| SIGN_REQ | `0x05` | Host → Device | `sighash[32] \|\| alpha[32] \|\| amount[8] \|\| fee[8] \|\| recipient_len[1] \|\| recipient[N]` — only sighash and alpha are used |
| SIGN_RSP | `0x06` | Device → Host | `sig[64] \|\| rk[32]` |
| ERROR | `0x07` | Device → Host | `error_code[1] \|\| message[N]` |
| TX_OUTPUT | `0x08` | Host → Device | `index[2] \|\| total[2] \|\| data[N]` (below) |
| TX_OUTPUT_ACK | `0x09` | Device → Host | empty |
| ABORT | `0x0A` | Host → Device | empty |
| TX_TRANSPARENT_INPUT | `0x0B` | Host → Device | accepted only as `(0, 0, digest[32])`, the sentinel closing the transparent outputs; anything announcing an input → error `0x18` |
| TX_TRANSPARENT_OUTPUT | `0x0C` | Host → Device | `index[2] \|\| total[2] \|\| value[8 LE] \|\| script_len[2 LE] \|\| script[N]`, P2PKH / P2SH only |
| TRANSPARENT_SIGN_REQ | `0x0D` | Host → Device | always refused, error `0x18` |
| TRANSPARENT_SIGN_RSP | `0x0E` | — | never sent |
| IDENTITY_REQ / RSP | `0x0F` / `0x10` | | `device_pubkey[32]` |
| ATTEST_REQ / RSP | `0x11` / `0x12` | | `challenge[32]` / `sig[64] \|\| rk[32]` |

**TX_OUTPUT data** by `index` (v6 tier only):

- `0xFFFF` — TxMeta, 170 bytes: `version[4] || version_group_id[4] || consensus_branch_id[4] || lock_time[4] || expiry_height[4] || orchard_flags[1] || value_balance[8 LE] || anchor[32] || ironwood_flags[1] || ironwood_value_balance[8 LE] || ironwood_anchor[32] || transparent_sig_digest[32] || sapling_digest[32] || coin_type[4 LE]`. The coin type must be the device's.
- `0..N-1` — one action, in order, **1416 bytes**: `pool_tag[1] || cv_net[32] || nullifier[32] || rk[32] || cmx[32] || ephemeral_key[32] || enc_ciphertext[580] || out_ciphertext[80] || recipient[43] || value[8 LE] || rseed[32] || memo[512]`; `pool_tag` is `0x00` (sealed Orchard) or `0x01` (Ironwood). The 904-byte body without memo is refused (error `0x14`).
- `N` — sentinel, 32 bytes: the companion's sighash.

Error codes are the library's (`HwpErrorCode` in `hwp.h`); among them `0x05` network mismatch,
`0x06` user cancelled, `0x09` sighash mismatch, `0x0A` invalid state, `0x0B` transparent digest
mismatch, `0x0C` Sapling not empty, `0x0D` note commitment mismatch, `0x0F` memo / ciphertext
mismatch, `0x14` memo required, `0x15` branch not allowed, `0x16` limit exceeded, `0x18`
transparent inputs unsupported.

## Other properties of the firmware

- **Sinsemilla table integrity** — the embedded S table is checked at boot against the digest
  compiled into the library; on mismatch the device halts.
- **AES** — FF1 diversifier derivation goes through the ESP32-S2 AES peripheral (via mbedTLS);
  the library's software AES is self-tested at boot.
- **RNG** — `bootloader_random_enable()` is kept on (WiFi/BT are off), for mnemonic generation,
  AEAD nonces, the identity scalar and signing nonces.
- **Build hardening** — stack canaries, light heap poisoning, GDB stub disabled.
- `CONFIG_DEBUG_LOG_SECRETS` (off by default) logs prefixes of secret material to ACM1; never
  enable it on a wallet that matters.

Constant-time properties are the library's; see its `SECURITY.md` for what was checked and with
which compilers (for Xtensa: a hand-read of two functions' disassembly, not a full analysis).

## Changes (November 2026)

- Ported to the library's November 2026 signer API: the device's full viewing key is passed to
  `orchard_signer_feed_meta()`; outputs are read with `orchard_signer_get_output()` and labelled
  by on-device ownership; `orchard_signer_get_totals()` / `orchard_signer_confirm_totals()` add a
  totals step with its own confirmation.
- **The previous revision could not sign.** At 3765ea5 the firmware never called the fee
  confirmation that library a55d168 already required, so `orchard_signer_verify()` returned
  `SIGNER_ERR_FEE_NOT_CONFIRMED` for every transaction and the device answered the sighash
  sentinel with "sighash verify failed". (Found by reading the code; not reproduced on a board.)
- Removed: transparent-input handling, the `TRANSPARENT_SIGN_REQ` ECDSA handler, BIP-32
  transparent key derivation, `wallet_get_seed()`, and the secp256k1 / BIP-32 sources from the
  build.
- Transparent outputs are now printed in the review (they were hashed but never shown).
- The network is fixed at build time; it used to be whatever coin type the host sent in
  `FVK_REQ`.
- `SIGN_REQ.recipient`, amount and fee are no longer read (the library function that
  cross-checked the recipient was removed because it could match an address no review had
  shown).
- Action frames must arrive in order; the compact (no-memo) action body is refused; every error
  resets the session; at most one signature per action.
- The cached default address moved to a new NVS key, so an address derived by the pre-fix
  library is not served from the cache any more.

## License

MIT
