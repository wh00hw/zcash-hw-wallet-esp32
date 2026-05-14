/**
 * Wallet core implementation.
 *
 * Manages BIP39 mnemonic in NVS and derives Zcash Orchard keys on demand.
 * Derived keys (FVK, UA) are cached in NVS after first derivation for fast boot.
 *
 * The mnemonic is the master secret. It is stored in NVS and can be exported
 * once via wallet_export_mnemonic() for user backup. After export, the
 * "exported" flag is set so the user knows the backup window has passed.
 */
#include "wallet.h"
#include "bip39.h"
#include "orchard.h"
#include "redpallas.h"  /* redpallas_derive_ak only */
#include "orchard_signer.h"
#include "rand.h"
#include "hwp.h"        /* HWP_ATTEST_PERSONAL constant */
#include "aead.h"       /* H-5: PIN-derived sealing of seed */
#include "wallet_lockout.h"
#include "memzero.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_timer.h"  /* monotonic clock for lockout timestamps */
#include "sdkconfig.h"
#include <string.h>

static const char *TAG = "wallet";
static const char *NVS_NAMESPACE    = "zcash_wallet";
/* Per-coin-type FVK / UA cache keys ("fvk_%u" / "ua_%u") are built at
 * runtime via snprintf — no bare "fvk" / "ua" constants are written.
 * The plain "mnemonic" slot used by pre-H-5 builds is no longer written;
 * any leftover plaintext in NVS is cleared by wallet_wipe() on first
 * boot of a reflashed device. */
static const char *NVS_KEY_BACKED_UP = "backed_up";
/* Device identity scalar — 32 bytes, Pallas-scalar, used for attestation
 * signatures (audit M1). Generated at first boot, persists across reboots,
 * regenerated on `wallet_wipe()`. */
static const char *NVS_KEY_DEV_SK    = "device_sk";

/* H-5: PIN-protected mnemonic storage. The plain NVS_KEY_MNEMONIC slot
 * (used by older builds) is replaced by:
 *   NVS_KEY_PIN_SALT       16-byte random salt for PIN KDF
 *   NVS_KEY_PIN_NONCE      16-byte AEAD nonce for the sealed mnemonic
 *   NVS_KEY_PIN_TAG        32-byte HMAC-SHA256 tag
 *   NVS_KEY_PIN_SEALED     ciphertext of the mnemonic (size = strlen(mn))
 *   NVS_KEY_LOCKOUT        32-byte serialized wallet_lockout_state_t
 *
 * The unsealed mnemonic only ever lives in RAM, in a `static` buffer
 * cleared on lock(). PBKDF2 iteration count is 150 000 (~1 s on
 * ESP32-S2 @ 240 MHz, balancing brute-force resistance vs UX). */
static const char *NVS_KEY_PIN_SALT   = "pin_salt";
static const char *NVS_KEY_PIN_NONCE  = "pin_nonce";
static const char *NVS_KEY_PIN_TAG    = "pin_tag";
static const char *NVS_KEY_PIN_SEALED = "pin_sealed";
static const char *NVS_KEY_LOCKOUT    = "lockout";

#define WALLET_PIN_KDF_ITERATIONS  150000u
#define WALLET_PIN_LOCKOUT_MAX     10u
#define WALLET_PIN_MAX_MNEMONIC    256

/* In-RAM unlocked state. Cleared on wallet_pin_lock() and on every
 * derive-failure path. */
static struct {
    bool unlocked;
    char mnemonic[WALLET_PIN_MAX_MNEMONIC];
    size_t mnemonic_len;
    /* Optional BIP-39 passphrase the user entered at unlock. NUL-
     * terminated so it can be passed straight to mnemonic_to_seed. */
    char passphrase[64];
} g_unlocked = {0};

WalletError wallet_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition truncated, erasing...");
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %s", esp_err_to_name(err));
        return WALLET_ERR_NVS;
    }
    return WALLET_OK;
}

bool wallet_is_initialized(void)
{
    /* Post H-5: a wallet is initialized iff a PIN-sealed mnemonic exists
     * in NVS. The legacy plain NVS_KEY_MNEMONIC slot is no longer used. */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    size_t len = 0;
    esp_err_t err = nvs_get_blob(h, NVS_KEY_PIN_SEALED, NULL, &len);
    nvs_close(h);
    return (err == ESP_OK && len > 0);
}

WalletError wallet_create(char *mnemonic_out, size_t mnemonic_len)
{
    /* Post H-5: this entry point now JUST generates a fresh mnemonic and
     * returns it to the caller. The PIN-protected persistence happens in
     * wallet_pin_provision() which the firmware calls after collecting
     * the user's PIN via tap-count. The two-step flow keeps the mnemonic
     * in RAM only between generation and the user's PIN entry. */
    if (wallet_is_initialized()) {
        return WALLET_ERR_ALREADY_INITIALIZED;
    }

    const char *mnemonic = mnemonic_generate(256);
    if (!mnemonic || !mnemonic_check(mnemonic)) {
        return WALLET_ERR_INVALID_MNEMONIC;
    }

    if (mnemonic_out && mnemonic_len > 0) {
        strncpy(mnemonic_out, mnemonic, mnemonic_len - 1);
        mnemonic_out[mnemonic_len - 1] = '\0';
    }

    ESP_LOGI(TAG, "Wallet mnemonic generated (call wallet_pin_provision next)");
    return WALLET_OK;
}

WalletError wallet_import(const char *mnemonic)
{
    /* Post H-5: import is now a thin validator. The firmware should
     * call this to validate the user-supplied mnemonic, then call
     * wallet_pin_provision() to seal it. We DO NOT touch NVS here —
     * the only writer of NVS_KEY_PIN_* is wallet_pin_provision(). */
    if (wallet_is_initialized()) {
        return WALLET_ERR_ALREADY_INITIALIZED;
    }
    if (!mnemonic || !mnemonic_check(mnemonic)) {
        return WALLET_ERR_INVALID_MNEMONIC;
    }
    return WALLET_OK;
}

/**
 * Export the mnemonic for backup.
 * Sets the backed_up flag after successful export.
 */
WalletError wallet_export_mnemonic(char *mnemonic_out, size_t mnemonic_len)
{
    /* Post H-5: export only works while the wallet is unlocked. The
     * mnemonic comes from the in-RAM cache, never from NVS plaintext. */
    if (!g_unlocked.unlocked) {
        return WALLET_ERR_INVALID_STATE;
    }
    if (!mnemonic_out || mnemonic_len == 0) {
        return WALLET_ERR_INVALID_STATE;
    }
    size_t len = g_unlocked.mnemonic_len;
    if (len + 1 > mnemonic_len) {
        return WALLET_ERR_INVALID_STATE;
    }
    memcpy(mnemonic_out, g_unlocked.mnemonic, len);
    mnemonic_out[len] = 0;

    /* Mark as backed up. */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVS_KEY_BACKED_UP, 1);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGW(TAG, "Mnemonic exported for backup (%d chars)", (int)len);
    return WALLET_OK;
}

bool wallet_is_backed_up(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    uint8_t val = 0;
    nvs_get_u8(h, NVS_KEY_BACKED_UP, &val);
    nvs_close(h);
    return (val != 0);
}

/**
 * Derive 64-byte BIP39 seed from the NVS-stored mnemonic.
 * Caller must memzero seed after use.
 */
/* Log first N bytes of a buffer as hex.
 *
 * Gated behind CONFIG_DEBUG_LOG_SECRETS because callers pass secret-bearing
 * buffers (seed, sk, ask, nk). When the flag is off (default and required for
 * any production build) this compiles to a no-op. Even an 8-byte prefix of
 * `ask` mirrored to USB CDC ACM1 over many signing operations leaks enough
 * material to dramatically narrow brute-force search.
 * Audit: docs/security-audit/03-firmware-esp32.md C-5.
 */
#if CONFIG_DEBUG_LOG_SECRETS
static void log_hex_prefix(const char *label, const uint8_t *buf, size_t prefix_len)
{
    char hex[64];
    size_t n = (prefix_len > 16) ? 16 : prefix_len;
    for (size_t i = 0; i < n; i++) {
        sprintf(hex + i * 2, "%02x", buf[i]);
    }
    hex[n * 2] = '\0';
    ESP_LOGI(TAG, "  %s: %s...", label, hex);
}
#else
static inline void log_hex_prefix(const char *label, const uint8_t *buf, size_t prefix_len)
{
    (void)label; (void)buf; (void)prefix_len;
}
#endif

static WalletError derive_seed(uint8_t seed[64])
{
    /* Post H-5: the mnemonic only exists in RAM after PIN unlock.
     * Refuse to derive otherwise — we cannot read NVS plaintext anymore. */
    if (!g_unlocked.unlocked) {
        ESP_LOGE(TAG, "derive_seed: wallet locked (run wallet_pin_unlock first)");
        return WALLET_ERR_INVALID_STATE;
    }

#if CONFIG_DEBUG_LOG_SECRETS
    ESP_LOGI(TAG, "derive_seed: mnemonic length=%d, first word='%.6s...'",
             (int)g_unlocked.mnemonic_len, g_unlocked.mnemonic);
#else
    ESP_LOGD(TAG, "derive_seed: mnemonic length=%d", (int)g_unlocked.mnemonic_len);
#endif

    /* BIP39: mnemonic + optional passphrase → seed (PBKDF2, 2048 rounds).
     * The passphrase lives in g_unlocked.passphrase, NUL-terminated.
     * Empty string = standard BIP-39 (no 25th word). */
    mnemonic_to_seed(g_unlocked.mnemonic, g_unlocked.passphrase, seed, NULL);

    log_hex_prefix("seed[0..8]", seed, 8);
    return WALLET_OK;
}

WalletError wallet_get_seed(uint8_t seed_out[64])
{
    return derive_seed(seed_out);
}

WalletError wallet_get_fvk(uint8_t fvk_out[96], uint32_t coin_type)
{
    /* Build NVS cache key per coin_type */
    char fvk_key[16];
    snprintf(fvk_key, sizeof(fvk_key), "fvk_%u", (unsigned)coin_type);

    /* Try NVS cache first */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        size_t len = 96;
        if (nvs_get_blob(h, fvk_key, fvk_out, &len) == ESP_OK && len == 96) {
            nvs_close(h);
            ESP_LOGI(TAG, "FVK loaded from NVS cache (coin_type=%u)", (unsigned)coin_type);
            log_hex_prefix("ak (cached)", fvk_out, 8);
            log_hex_prefix("nk (cached)", fvk_out + 32, 8);
            return WALLET_OK;
        }
        nvs_close(h);
    }

    /* Derive from scratch */
    ESP_LOGI(TAG, "Deriving FVK (coin_type=%u, may take seconds)...", (unsigned)coin_type);
    uint8_t seed[64];
    WalletError werr = derive_seed(seed);
    if (werr != WALLET_OK) return werr;

    /* Derive account spending key */
    uint8_t sk[32];
    orchard_derive_account_sk(seed, coin_type, ZCASH_ACCOUNT, sk);
    memzero(seed, sizeof(seed));
    log_hex_prefix("sk[0..8]", sk, 8);

    /* Derive ask, nk, rivk */
    uint8_t ask[32], nk[32], rivk[32];
    orchard_derive_keys(sk, ask, nk, rivk);
    memzero(sk, sizeof(sk));
    log_hex_prefix("ask[0..8]", ask, 8);
    log_hex_prefix("nk[0..8]", nk, 8);

    /* FVK = ak || nk || rivk */
    uint8_t ak[32];
    redpallas_derive_ak(ask, ak);
    memzero(ask, sizeof(ask));
    log_hex_prefix("ak[0..8]", ak, 8);

    memcpy(fvk_out,      ak,   32);
    memcpy(fvk_out + 32, nk,   32);
    memcpy(fvk_out + 64, rivk, 32);

    memzero(ak, sizeof(ak));
    memzero(nk, sizeof(nk));
    memzero(rivk, sizeof(rivk));

    /* Cache in NVS keyed by coin_type */
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_blob(h, fvk_key, fvk_out, 96);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "FVK cached in NVS (key=%s)", fvk_key);
    }

    return WALLET_OK;
}

WalletError wallet_get_address(char *ua_out, size_t ua_len, uint32_t coin_type)
{
    /* Build NVS cache key per coin_type */
    char ua_key[16];
    snprintf(ua_key, sizeof(ua_key), "ua_%u", (unsigned)coin_type);

    /* Try NVS cache first */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        size_t len = ua_len;
        if (nvs_get_str(h, ua_key, ua_out, &len) == ESP_OK && len > 1) {
            nvs_close(h);
            ESP_LOGI(TAG, "UA loaded from NVS cache (coin_type=%u)", (unsigned)coin_type);
            return WALLET_OK;
        }
        nvs_close(h);
    }

    /* Derive from scratch */
    const char *hrp = wallet_hrp_for_coin_type(coin_type);
    ESP_LOGI(TAG, "Deriving unified address (coin_type=%u, hrp=%s)...", (unsigned)coin_type, hrp);
    uint8_t seed[64];
    WalletError werr = derive_seed(seed);
    if (werr != WALLET_OK) return werr;

    uint8_t d[11], pk_d[32];
    int ret = orchard_derive_unified_address(
        seed, coin_type, ZCASH_ACCOUNT,
        hrp, ua_out, ua_len, d, pk_d);
    memzero(seed, sizeof(seed));

    if (ret <= 0) {
        return WALLET_ERR_SIGN_FAILED;
    }

    /* Cache in NVS keyed by coin_type */
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, ua_key, ua_out);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "UA cached in NVS (key=%s)", ua_key);
    }

    return WALLET_OK;
}

WalletError wallet_sign_via_ctx(const OrchardSignerCtx *ctx,
                                const uint8_t sighash[32], const uint8_t alpha[32],
                                uint8_t sig_out[64], uint8_t rk_out[32],
                                uint32_t coin_type)
{
    ESP_LOGI(TAG, "=== SIGN START (coin_type=%u) ===", (unsigned)coin_type);
    log_hex_prefix("sighash", sighash, 16);
    log_hex_prefix("alpha", alpha, 16);

    uint8_t seed[64];
    WalletError werr = derive_seed(seed);
    if (werr != WALLET_OK) return werr;

    uint8_t sk[32];
    orchard_derive_account_sk(seed, coin_type, ZCASH_ACCOUNT, sk);
    memzero(seed, sizeof(seed));
    log_hex_prefix("sk[0..8]", sk, 8);

    uint8_t ask[32], nk_discard[32], rivk_discard[32];
    orchard_derive_keys(sk, ask, nk_discard, rivk_discard);
    memzero(sk, sizeof(sk));
    memzero(nk_discard, sizeof(nk_discard));
    memzero(rivk_discard, sizeof(rivk_discard));
    log_hex_prefix("ask[0..8]", ask, 8);

    /* Sign via libzcash context — enforces ZIP-244 verification invariant */
    OrchardSignerError serr = orchard_signer_sign(ctx, sighash, ask, alpha, sig_out, rk_out);
    memzero(ask, sizeof(ask));

    if (serr != SIGNER_OK) {
        ESP_LOGE(TAG, "orchard_signer_sign failed (err=%d)", serr);
        ESP_LOGI(TAG, "=== SIGN END (FAILED) ===");
        return WALLET_ERR_SIGN_FAILED;
    }

    log_hex_prefix("rk", rk_out, 8);
    log_hex_prefix("sig[0..8]", sig_out, 8);
    ESP_LOGI(TAG, "=== SIGN END ===");

    return WALLET_OK;
}

WalletError wallet_wipe(void)
{
    /* Full reset (audit H-5): seed + identity + lockout state + cached
     * keys + UA. The user re-pairs (M1) and re-provisions PIN at next
     * boot. This is the "wipe seed + identity" policy chosen at design
     * time — a stolen-and-reflashed device gets a fresh device_pk that
     * the companion's pinned pubkey will not match, alerting the user. */
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return WALLET_ERR_NVS;
    }
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);

    /* Wipe the in-RAM unlock cache too. */
    memzero(&g_unlocked, sizeof(g_unlocked));

    ESP_LOGW(TAG, "Wallet wiped (seed + identity + cached keys)!");
    return WALLET_OK;
}

/* ------------------------------------------------------------------------ */
/*  Device identity + attestation (audit M1)                                */
/* ------------------------------------------------------------------------ */

/**
 * Load `device_sk` from NVS, or generate it (and persist) on first call.
 * The caller MUST memzero the returned scalar after use.
 */
static WalletError load_or_create_device_sk(uint8_t device_sk_out[32])
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return WALLET_ERR_NVS;

    size_t len = 32;
    err = nvs_get_blob(h, NVS_KEY_DEV_SK, device_sk_out, &len);
    if (err == ESP_OK && len == 32) {
        nvs_close(h);
        return WALLET_OK;
    }

    /* No identity yet: generate one. The CSPRNG is provided by
     * `random_buffer()` which on this board pulls from `esp_fill_random()`.
     * The bootloader RNG source must already be enabled (see main.c
     * app_main()'s `bootloader_random_enable()` call), otherwise the
     * resulting scalar would be from a degraded LFSR — which we cannot
     * detect after the fact, so fail loudly if NVS is read-only. */
    random_buffer(device_sk_out, 32);

    /* The Pallas scalar field order q is just under 2^254. random_buffer
     * gives us 256 bits; we clear the top 2 bits to keep the value below
     * 2^254 < q. The remaining ~254 bits are uniform. The scalar may still
     * be technically out of range in a tiny [2^254 - (2^254 - q), 2^254)
     * window, but redpallas_sign performs `fq_full_reduce` internally so
     * the on-curve key derivation is well-defined regardless. */
    device_sk_out[31] &= 0x3F;

    err = nvs_set_blob(h, NVS_KEY_DEV_SK, device_sk_out, 32);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);

    if (err != ESP_OK) {
        memzero(device_sk_out, 32);
        return WALLET_ERR_NVS;
    }

    ESP_LOGW(TAG, "Generated new device identity scalar (first boot or post-wipe)");
    return WALLET_OK;
}

WalletError wallet_get_or_create_device_identity(uint8_t device_pk_out[32])
{
    uint8_t device_sk[32];
    WalletError werr = load_or_create_device_sk(device_sk);
    if (werr != WALLET_OK) return werr;

    /* redpallas_derive_ak applies the y-bit-0 normalization that
     * redpallas_sign uses internally (audit H-2), so the returned pubkey
     * is the exact 32-byte value the companion needs to compare against
     * the rk in subsequent ATTEST_RSP frames. */
    redpallas_derive_ak(device_sk, device_pk_out);
    memzero(device_sk, sizeof(device_sk));

    return WALLET_OK;
}

/* ------------------------------------------------------------------------ */
/*  PIN-protected mnemonic storage (audit H-5)                              */
/* ------------------------------------------------------------------------ */

static WalletError lockout_load(wallet_lockout_state_t* s) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        wallet_lockout_init(s);
        return WALLET_OK;
    }
    uint8_t blob[WALLET_LOCKOUT_STATE_SIZE];
    size_t len = sizeof(blob);
    esp_err_t err = nvs_get_blob(h, NVS_KEY_LOCKOUT, blob, &len);
    nvs_close(h);

    if (err != ESP_OK || len != WALLET_LOCKOUT_STATE_SIZE) {
        wallet_lockout_init(s);
        return WALLET_OK;
    }
    if (!wallet_lockout_deserialize(s, blob)) {
        ESP_LOGW(TAG, "lockout state corrupted in NVS — reset");
    }
    return WALLET_OK;
}

static WalletError lockout_save(const wallet_lockout_state_t* s) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return WALLET_ERR_NVS;
    uint8_t blob[WALLET_LOCKOUT_STATE_SIZE];
    wallet_lockout_serialize(s, blob);
    err = nvs_set_blob(h, NVS_KEY_LOCKOUT, blob, sizeof(blob));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? WALLET_OK : WALLET_ERR_NVS;
}

WalletPinStatus wallet_pin_status(void) {
    if (g_unlocked.unlocked) return WALLET_PIN_UNLOCKED;
    if (!wallet_is_initialized()) return WALLET_PIN_NOT_SET;

    wallet_lockout_state_t s;
    lockout_load(&s);
    if (wallet_lockout_should_wipe(&s, WALLET_PIN_LOCKOUT_MAX)) {
        return WALLET_PIN_LOCKED_OUT;
    }
    return WALLET_PIN_SET;
}

WalletError wallet_pin_provision(
    const char* mnemonic,
    const uint8_t pin[WALLET_PIN_LEN],
    const char* passphrase)
{
    if (wallet_is_initialized()) return WALLET_ERR_ALREADY_INITIALIZED;
    if (!mnemonic || !mnemonic_check(mnemonic)) return WALLET_ERR_INVALID_MNEMONIC;

    /* 1. Derive AEAD key from PIN with a fresh random salt. */
    uint8_t salt[16], nonce[AEAD_NONCE_SIZE], key[AEAD_KEY_SIZE];
    random_buffer(salt, sizeof(salt));
    random_buffer(nonce, sizeof(nonce));

    ESP_LOGI(TAG, "Deriving PIN key (PBKDF2-HMAC-SHA512, %u iter, ~1s)...",
             WALLET_PIN_KDF_ITERATIONS);
    wallet_pin_kdf(pin, WALLET_PIN_LEN, salt, sizeof(salt),
                   WALLET_PIN_KDF_ITERATIONS, key);

    /* 2. Seal the mnemonic. AAD = "zcash-hw mnemonic v1" so a future
     * version bump that changes the layout fails to unseal old blobs. */
    size_t mn_len = strlen(mnemonic);
    if (mn_len == 0 || mn_len >= WALLET_PIN_MAX_MNEMONIC) {
        memzero(key, sizeof(key));
        return WALLET_ERR_INVALID_MNEMONIC;
    }
    static uint8_t ct[WALLET_PIN_MAX_MNEMONIC];
    uint8_t tag[AEAD_TAG_SIZE];
    static const uint8_t AAD[] = "zcash-hw mnemonic v1";

    aead_aes256_ctr_hmac_seal(key, nonce,
                               AAD, sizeof(AAD) - 1,
                               (const uint8_t*)mnemonic, mn_len,
                               ct, tag);

    /* 3. Persist all parts to NVS in a single transaction. */
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err  = nvs_set_blob(h, NVS_KEY_PIN_SALT,   salt,  sizeof(salt));
        err |= nvs_set_blob(h, NVS_KEY_PIN_NONCE,  nonce, sizeof(nonce));
        err |= nvs_set_blob(h, NVS_KEY_PIN_TAG,    tag,   sizeof(tag));
        err |= nvs_set_blob(h, NVS_KEY_PIN_SEALED, ct,    mn_len);
        err |= nvs_set_u8 (h, NVS_KEY_BACKED_UP, 0);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }

    /* 4. Reset lockout state. */
    wallet_lockout_state_t lo;
    wallet_lockout_init(&lo);
    lockout_save(&lo);

    /* 5. Cache the unsealed mnemonic + passphrase in RAM so the user
     * can sign immediately after provisioning without re-entering PIN. */
    if (err == ESP_OK) {
        g_unlocked.unlocked = true;
        g_unlocked.mnemonic_len = mn_len;
        memcpy(g_unlocked.mnemonic, mnemonic, mn_len);
        g_unlocked.mnemonic[mn_len] = 0;
        size_t pp_len = passphrase ? strlen(passphrase) : 0;
        if (pp_len >= sizeof(g_unlocked.passphrase)) {
            pp_len = sizeof(g_unlocked.passphrase) - 1;
        }
        memcpy(g_unlocked.passphrase, passphrase ? passphrase : "", pp_len);
        g_unlocked.passphrase[pp_len] = 0;
    }

    memzero(salt, sizeof(salt));
    memzero(nonce, sizeof(nonce));
    memzero(key, sizeof(key));
    memzero(ct, sizeof(ct));
    memzero(tag, sizeof(tag));

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wallet_pin_provision: NVS write failed");
        return WALLET_ERR_NVS;
    }
    ESP_LOGI(TAG, "Wallet provisioned (PIN-sealed mnemonic stored)");
    return WALLET_OK;
}

WalletError wallet_pin_unlock(const uint8_t pin[WALLET_PIN_LEN]) {
    /* Lockout pre-check. */
    wallet_lockout_state_t lo;
    lockout_load(&lo);
    if (wallet_lockout_should_wipe(&lo, WALLET_PIN_LOCKOUT_MAX)) {
        return WALLET_ERR_LOCKED_OUT;
    }
    if (!wallet_is_initialized()) return WALLET_ERR_PIN_NOT_SET;

    /* Load sealed blob from NVS. */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return WALLET_ERR_NVS;
    }
    uint8_t salt[16], nonce[AEAD_NONCE_SIZE], tag[AEAD_TAG_SIZE];
    static uint8_t ct[WALLET_PIN_MAX_MNEMONIC];
    size_t salt_len = sizeof(salt), nonce_len = sizeof(nonce);
    size_t tag_len  = sizeof(tag),  ct_len    = sizeof(ct);
    esp_err_t err  = nvs_get_blob(h, NVS_KEY_PIN_SALT,   salt,  &salt_len);
    err           |= nvs_get_blob(h, NVS_KEY_PIN_NONCE,  nonce, &nonce_len);
    err           |= nvs_get_blob(h, NVS_KEY_PIN_TAG,    tag,   &tag_len);
    err           |= nvs_get_blob(h, NVS_KEY_PIN_SEALED, ct,    &ct_len);
    nvs_close(h);
    if (err != ESP_OK ||
        salt_len != sizeof(salt) ||
        nonce_len != sizeof(nonce) ||
        tag_len != sizeof(tag) ||
        ct_len == 0) {
        return WALLET_ERR_NVS;
    }

    /* Derive key + attempt unseal. */
    uint8_t key[AEAD_KEY_SIZE];
    wallet_pin_kdf(pin, WALLET_PIN_LEN, salt, sizeof(salt),
                   WALLET_PIN_KDF_ITERATIONS, key);

    static uint8_t pt[WALLET_PIN_MAX_MNEMONIC];
    static const uint8_t AAD[] = "zcash-hw mnemonic v1";
    int rc = aead_aes256_ctr_hmac_unseal(key, nonce,
                                          AAD, sizeof(AAD) - 1,
                                          ct, ct_len, tag, pt);
    memzero(key, sizeof(key));

    if (rc != 0) {
        /* Wrong PIN. Increment lockout, persist. */
        wallet_lockout_record_failure(
            &lo, (uint64_t)esp_timer_get_time() / 1000000ULL);
        lockout_save(&lo);
        memzero(pt, sizeof(pt));
        ESP_LOGW(TAG, "PIN wrong (fail_count=%u of %u)",
                 (unsigned)lo.fail_count, (unsigned)WALLET_PIN_LOCKOUT_MAX);
        if (wallet_lockout_should_wipe(&lo, WALLET_PIN_LOCKOUT_MAX)) {
            return WALLET_ERR_LOCKED_OUT;
        }
        return WALLET_ERR_PIN_WRONG;
    }

    /* Success: cache mnemonic in RAM, reset lockout. */
    g_unlocked.unlocked = true;
    g_unlocked.mnemonic_len = ct_len;
    memcpy(g_unlocked.mnemonic, pt, ct_len);
    if (ct_len < sizeof(g_unlocked.mnemonic)) {
        g_unlocked.mnemonic[ct_len] = 0;
    }
    g_unlocked.passphrase[0] = 0;  /* set later via separate flow */
    memzero(pt, sizeof(pt));

    wallet_lockout_record_success(&lo);
    lockout_save(&lo);
    ESP_LOGI(TAG, "Wallet unlocked (lifetime attempts: %u)",
             (unsigned)lo.total_attempts);
    return WALLET_OK;
}

void wallet_pin_lock(void) {
    memzero(&g_unlocked, sizeof(g_unlocked));
}

WalletError wallet_attest(const uint8_t challenge[32],
                          uint8_t sig_out[64],
                          uint8_t rk_out[32])
{
    uint8_t device_sk[32];
    WalletError werr = load_or_create_device_sk(device_sk);
    if (werr != WALLET_OK) return werr;

    /* The actual digest + RedPallas signing lives in the library so it
     * can be reused by any other firmware (Ledger, STM32, future HW)
     * without re-implementing the BLAKE2b-then-sign pattern. The HWP
     * personalization tag is a protocol-level constant defined in hwp.h. */
    int ret = orchard_sign_with_personal(
        device_sk,
        (const uint8_t*)HWP_ATTEST_PERSONAL,
        challenge,
        sig_out,
        rk_out);

    memzero(device_sk, sizeof(device_sk));
    return (ret == 0) ? WALLET_OK : WALLET_ERR_SIGN_FAILED;
}
