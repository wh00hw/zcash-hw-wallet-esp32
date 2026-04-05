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

/** Zcash Testnet coin type (ZIP-32) */
#define ZCASH_COIN_TYPE   1
/** Default account index */
#define ZCASH_ACCOUNT     0
/** Testnet HRP for Unified Addresses */
#define ZCASH_UA_HRP      "utest"

/** Wallet status codes */
typedef enum {
    WALLET_OK = 0,
    WALLET_ERR_NOT_INITIALIZED,
    WALLET_ERR_ALREADY_INITIALIZED,
    WALLET_ERR_NVS,
    WALLET_ERR_INVALID_MNEMONIC,
    WALLET_ERR_SIGN_FAILED,
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
 * @param fvk_out  96-byte output buffer
 */
WalletError wallet_get_fvk(uint8_t fvk_out[96]);

/**
 * Derive a Unified Address string.
 * @param ua_out   Output buffer for bech32m-encoded address
 * @param ua_len   Size of ua_out
 */
WalletError wallet_get_address(char *ua_out, size_t ua_len);

/**
 * Sign a transaction with the spending key.
 * @param sighash   32-byte sighash
 * @param alpha     32-byte alpha randomizer
 * @param sig_out   64-byte signature output
 * @param rk_out    32-byte randomized key output
 */
WalletError wallet_sign(const uint8_t sighash[32], const uint8_t alpha[32],
                        uint8_t sig_out[64], uint8_t rk_out[32]);

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
