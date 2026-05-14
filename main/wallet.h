/**
 * Wallet core — key management and signing for Zcash Orchard.
 *
 * Keys are derived from a BIP39 mnemonic stored in NVS (Non-Volatile Storage).
 * The spending key never leaves the device in plaintext.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/** Default account index */
#define ZCASH_ACCOUNT     0

/** Default coin type used when FvkReq has no payload (backward compat). */
#define ZCASH_DEFAULT_COIN_TYPE  1

/** PIN length, in digits. Each digit is 0..9 in a uint8_t.
 *  Trade-off: 5 digits gives 100k combinations, lockout=10 attempts wipes. */
#define WALLET_PIN_LEN  5

/** Return the Unified Address HRP for a given coin_type. */
static inline const char* wallet_hrp_for_coin_type(uint32_t coin_type)
{
    return (coin_type == 133) ? "u" : "utest";
}

/** Wallet status codes */
typedef enum {
    WALLET_OK = 0,
    WALLET_ERR_NOT_INITIALIZED,
    WALLET_ERR_ALREADY_INITIALIZED,
    WALLET_ERR_NVS,
    WALLET_ERR_INVALID_MNEMONIC,
    WALLET_ERR_SIGN_FAILED,
    /* PIN flows (audit H-5) */
    WALLET_ERR_PIN_WRONG,         /* PIN-derived AEAD tag mismatch */
    WALLET_ERR_LOCKED_OUT,        /* lockout threshold reached → wipe required */
    WALLET_ERR_PIN_NOT_SET,       /* unlock attempted before provisioning */
    WALLET_ERR_INVALID_STATE,     /* call invalid in current PIN status */
} WalletError;

/**
 * Initialize the wallet subsystem (NVS init).
 * Must be called once at boot.
 */
WalletError wallet_init(void);

/**
 * Check if a wallet (mnemonic seed) exists in NVS.
 */
bool wallet_is_initialized(void);

/**
 * Generate a new 24-word mnemonic and store in NVS.
 * @param mnemonic_out  Buffer for the mnemonic string (at least 256 bytes)
 * @param mnemonic_len  Size of mnemonic_out
 * @return WALLET_OK on success
 */
WalletError wallet_create(char *mnemonic_out, size_t mnemonic_len);

/**
 * Import an existing mnemonic and store in NVS.
 * @param mnemonic  Space-separated BIP39 words
 * @return WALLET_OK on success, WALLET_ERR_INVALID_MNEMONIC if invalid
 */
WalletError wallet_import(const char *mnemonic);

/**
 * Derive the full viewing key (ak || nk || rivk, 96 bytes).
 * @param fvk_out    96-byte output buffer
 * @param coin_type  ZIP-32 coin type (133 = mainnet, 1 = testnet)
 */
WalletError wallet_get_fvk(uint8_t fvk_out[96], uint32_t coin_type);

/**
 * Derive the 64-byte BIP-39 seed from the NVS-stored mnemonic.
 *
 * Required by the transparent ECDSA signing path, which needs the raw
 * seed for BIP-32 derivation. Caller MUST memzero the seed buffer
 * after use; the seed is the master secret.
 *
 * @param seed_out  64-byte output buffer
 */
WalletError wallet_get_seed(uint8_t seed_out[64]);

/**
 * Derive a Unified Address string.
 * @param ua_out     Output buffer for bech32m-encoded address
 * @param ua_len     Size of ua_out
 * @param coin_type  ZIP-32 coin type (133 = mainnet, 1 = testnet)
 */
WalletError wallet_get_address(char *ua_out, size_t ua_len, uint32_t coin_type);

/**
 * Sign via an OrchardSignerCtx (enforces ZIP-244 verification).
 * The context must be in VERIFIED state with matching sighash.
 *
 * @param ctx       Signing context (must be VERIFIED)
 * @param sighash   32-byte sighash
 * @param alpha     32-byte alpha randomizer
 * @param sig_out   64-byte signature output
 * @param rk_out    32-byte randomized key output
 * @param coin_type ZIP-32 coin type for key derivation
 */
#include "orchard_signer.h"
WalletError wallet_sign_via_ctx(const OrchardSignerCtx *ctx,
                                const uint8_t sighash[32], const uint8_t alpha[32],
                                uint8_t sig_out[64], uint8_t rk_out[32],
                                uint32_t coin_type);

/**
 * Export the mnemonic for user backup.
 * Marks the wallet as backed up after export.
 * @param mnemonic_out  Buffer for the mnemonic string (at least 256 bytes)
 * @param mnemonic_len  Size of mnemonic_out
 */
WalletError wallet_export_mnemonic(char *mnemonic_out, size_t mnemonic_len);

/**
 * Check if the mnemonic has been backed up (exported at least once).
 */
bool wallet_is_backed_up(void);

/**
 * Wipe the wallet (delete mnemonic from NVS). Irreversible!
 */
WalletError wallet_wipe(void);

/* --- PIN protection (audit H-5) ------------------------------------------ */

/**
 * Status of the wallet's PIN-protected storage.
 */
typedef enum {
    WALLET_PIN_NOT_SET,       /* fresh wallet — no PIN ever provisioned */
    WALLET_PIN_SET,           /* sealed seed exists; needs unlock */
    WALLET_PIN_UNLOCKED,      /* unsealed seed cached in RAM for this session */
    WALLET_PIN_LOCKED_OUT,    /* failure counter exceeded threshold; wipe required */
} WalletPinStatus;

WalletPinStatus wallet_pin_status(void);

/**
 * Provision a fresh wallet with a PIN. Generates a random salt, derives
 * the AEAD key, seals the mnemonic, persists everything to NVS.
 * Optional `passphrase` is the BIP-39 25th word; pass NULL or "" to skip.
 *
 * Must only be called when wallet_pin_status() == WALLET_PIN_NOT_SET.
 */
WalletError wallet_pin_provision(
    const char* mnemonic,
    const uint8_t pin[WALLET_PIN_LEN],
    const char* passphrase);

/**
 * Verify a PIN attempt and unseal the seed into RAM. On success, the
 * lockout counter is reset; on failure it is incremented and persisted
 * before returning. Returns WALLET_OK on unlock, WALLET_ERR_PIN_WRONG
 * on tag-mismatch, WALLET_ERR_LOCKED_OUT if the threshold was hit.
 *
 * The caller drives wipe-after-too-many-fails by checking
 * wallet_pin_status() == WALLET_PIN_LOCKED_OUT and calling wallet_wipe()
 * + halting/resetting.
 */
WalletError wallet_pin_unlock(const uint8_t pin[WALLET_PIN_LEN]);

/**
 * Lock the wallet (zero the in-RAM seed cache; subsequent operations
 * require unlock). Idempotent.
 */
void wallet_pin_lock(void);

/* --- Device identity + attestation (audit M1) ---------------------------- */

/**
 * Get the device's long-term identity public key. Generates the keypair on
 * first call (if not present in NVS) and persists `device_sk` so subsequent
 * calls return the same `device_pk`.
 *
 * The identity scalar is generated via the platform CSPRNG (which on ESP32
 * is `bootloader_random_enable()`-seeded — see main.c). It is INDEPENDENT
 * of the BIP-39 mnemonic: factory-resetting the device generates a fresh
 * identity, which the companion's pinned pubkey will not match. This is
 * a deliberate property — it lets a user (or a separate trusted CLI) detect
 * "device was reflashed while I was away" via attestation mismatch.
 *
 * @param device_pk_out  32-byte canonical Pallas pubkey (with y-bit-0
 *                       normalization applied by redpallas_derive_ak)
 */
WalletError wallet_get_or_create_device_identity(uint8_t device_pk_out[32]);

/**
 * Attest a 32-byte challenge using the device's identity scalar.
 *
 * The challenge is hashed via personalized BLAKE2b-256 (domain
 * `HWP_ATTEST_PERSONAL`) and signed with RedPallas using the identity
 * scalar and `alpha = 0`. Because alpha is zero, the returned `rk` is
 * exactly the device's pubkey, so the companion can verify both that
 *   1. `rk == pinned device_pk`  (device-substitution check), and
 *   2. the signature is valid    (replay / forgery check).
 *
 * @param challenge  32-byte fresh nonce from the companion
 * @param sig_out    64-byte signature
 * @param rk_out     32-byte randomized key (= device_pk when alpha=0)
 */
WalletError wallet_attest(const uint8_t challenge[32],
                          uint8_t sig_out[64],
                          uint8_t rk_out[32]);
