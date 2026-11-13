# Contributing to zcash-hw-wallet-esp32

This is a reference port of the
[libzcash-ironwood-c](https://github.com/wh00hw/libzcash-ironwood-c) signing
library to the ESP32-S2. It is a proof of concept: no secure element, no
audit, not for real funds. Code, commits and pull requests follow the
[librustzcash style guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides)
where they apply to C.

## Building

```bash
idf.py set-target esp32s2
idf.py build
```

## Rules

- **Cryptography and signing policy live in the library**, in the submodule
  `components/libzcash-ironwood-c/lib`. Do not edit the submodule here:
  change the library in its own repository, then bump the pointer.
- **Never store or log a secret in the clear** (mnemonic, seed, spending key,
  PIN, PIN-derived key). `CONFIG_DEBUG_LOG_SECRETS` stays off by default and
  must never be required for normal operation.
- **What the user confirms must be what the device verified.** Anything shown
  for confirmation comes from the library's signer state, never directly
  from the host.
- **Keep "runs on an ESP32" separate from "is a hardware wallet"** in code
  comments and documentation. A development board has no tamper resistance.
- **Documentation** (`README.md`) is updated in the same pull request as the
  behaviour it describes, and states only what was observed on hardware.

## Commits

One logical change per commit; subject says what, body says why and how it
was tested. Rebase on `main`.
