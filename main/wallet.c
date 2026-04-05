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
#include "redpallas.h"
#include "memzero.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "wallet";
static const char *NVS_NAMESPACE    = "zcash_wallet";
static const char *NVS_KEY_MNEMONIC = "mnemonic";
static const char *NVS_KEY_FVK      = "fvk";
static const char *NVS_KEY_UA       = "ua";
static const char *NVS_KEY_BACKED_UP = "backed_up";

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
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    size_t len = 0;
    esp_err_t err = nvs_get_str(h, NVS_KEY_MNEMONIC, NULL, &len);
    nvs_close(h);
    return (err == ESP_OK && len > 0);
}

WalletError wallet_create(char *mnemonic_out, size_t mnemonic_len)
{
    if (wallet_is_initialized()) {
        return WALLET_ERR_ALREADY_INITIALIZED;
    }

    /* Generate 256-bit entropy → 24 words */
    const char *mnemonic = mnemonic_generate(256);
    if (!mnemonic || !mnemonic_check(mnemonic)) {
        return WALLET_ERR_INVALID_MNEMONIC;
    }

    /* Store in NVS */
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return WALLET_ERR_NVS;
    }
    err = nvs_set_str(h, NVS_KEY_MNEMONIC, mnemonic);
    if (err == ESP_OK) {
        /* New wallet — not yet backed up */
        nvs_set_u8(h, NVS_KEY_BACKED_UP, 0);
        err = nvs_commit(h);
    }
    nvs_close(h);

    if (err != ESP_OK) {
        return WALLET_ERR_NVS;
    }

    if (mnemonic_out && mnemonic_len > 0) {
        strncpy(mnemonic_out, mnemonic, mnemonic_len - 1);
        mnemonic_out[mnemonic_len - 1] = '\0';
    }

    ESP_LOGI(TAG, "Wallet created (24-word mnemonic stored in NVS)");
    return WALLET_OK;
}

WalletError wallet_import(const char *mnemonic)
{
    if (wallet_is_initialized()) {
        return WALLET_ERR_ALREADY_INITIALIZED;
    }

    if (!mnemonic_check(mnemonic)) {
        return WALLET_ERR_INVALID_MNEMONIC;
    }

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return WALLET_ERR_NVS;
    }

    /* Clear any cached derived keys — new mnemonic means new keys */
    nvs_erase_key(h, NVS_KEY_FVK);
    nvs_erase_key(h, NVS_KEY_UA);

    err = nvs_set_str(h, NVS_KEY_MNEMONIC, mnemonic);
    if (err == ESP_OK) {
        /* Imported = user already has the words */
        nvs_set_u8(h, NVS_KEY_BACKED_UP, 1);
        err = nvs_commit(h);
    }
    nvs_close(h);

    return (err == ESP_OK) ? WALLET_OK : WALLET_ERR_NVS;
}

/**
 * Export the mnemonic for backup.
 * Sets the backed_up flag after successful export.
 */
WalletError wallet_export_mnemonic(char *mnemonic_out, size_t mnemonic_len)
{
    if (!wallet_is_initialized()) {
        return WALLET_ERR_NOT_INITIALIZED;
    }

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return WALLET_ERR_NVS;
    }

    size_t len = mnemonic_len;
    err = nvs_get_str(h, NVS_KEY_MNEMONIC, mnemonic_out, &len);
    if (err != ESP_OK) {
        nvs_close(h);
        return WALLET_ERR_NVS;
    }

    /* Mark as backed up */
    nvs_set_u8(h, NVS_KEY_BACKED_UP, 1);
    nvs_commit(h);
    nvs_close(h);

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
static WalletError derive_seed(uint8_t seed[64])
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "derive_seed: NVS open failed");
        return WALLET_ERR_NVS;
    }

    char mnemonic[256];
    size_t len = sizeof(mnemonic);
    err = nvs_get_str(h, NVS_KEY_MNEMONIC, mnemonic, &len);
    nvs_close(h);

    if (err != ESP_OK || len == 0) {
        ESP_LOGE(TAG, "derive_seed: no mnemonic in NVS");
        return WALLET_ERR_NOT_INITIALIZED;
    }

    /* BIP39: mnemonic → seed (PBKDF2, 2048 rounds) */
    mnemonic_to_seed(mnemonic, "", seed, NULL);
    memzero(mnemonic, sizeof(mnemonic));
    return WALLET_OK;
}

WalletError wallet_get_fvk(uint8_t fvk_out[96])
{
    /* Try NVS cache first */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        size_t len = 96;
        if (nvs_get_blob(h, NVS_KEY_FVK, fvk_out, &len) == ESP_OK && len == 96) {
            nvs_close(h);
            ESP_LOGI(TAG, "FVK loaded from NVS cache");
            return WALLET_OK;
        }
        nvs_close(h);
    }

    /* Derive from scratch */
    ESP_LOGI(TAG, "Deriving FVK (first time, may take seconds)...");
    uint8_t seed[64];
    WalletError werr = derive_seed(seed);
    if (werr != WALLET_OK) return werr;

    /* Derive account spending key */
    uint8_t sk[32];
    orchard_derive_account_sk(seed, ZCASH_COIN_TYPE, ZCASH_ACCOUNT, sk);
    memzero(seed, sizeof(seed));

    /* Derive ask, nk, rivk */
    uint8_t ask[32], nk[32], rivk[32];
    orchard_derive_keys(sk, ask, nk, rivk);
    memzero(sk, sizeof(sk));

    /* FVK = ak || nk || rivk */
    uint8_t ak[32];
    redpallas_derive_ak(ask, ak);
    memzero(ask, sizeof(ask));

    memcpy(fvk_out,      ak,   32);
    memcpy(fvk_out + 32, nk,   32);
    memcpy(fvk_out + 64, rivk, 32);

    memzero(ak, sizeof(ak));
    memzero(nk, sizeof(nk));
    memzero(rivk, sizeof(rivk));

    /* Cache in NVS */
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_blob(h, NVS_KEY_FVK, fvk_out, 96);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "FVK cached in NVS");
    }

    return WALLET_OK;
}

WalletError wallet_get_address(char *ua_out, size_t ua_len)
{
    /* Try NVS cache first */
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        size_t len = ua_len;
        if (nvs_get_str(h, NVS_KEY_UA, ua_out, &len) == ESP_OK && len > 1) {
            nvs_close(h);
            ESP_LOGI(TAG, "UA loaded from NVS cache");
            return WALLET_OK;
        }
        nvs_close(h);
    }

    /* Derive from scratch */
    ESP_LOGI(TAG, "Deriving unified address (first time, may take seconds)...");
    uint8_t seed[64];
    WalletError werr = derive_seed(seed);
    if (werr != WALLET_OK) return werr;

    uint8_t d[11], pk_d[32];
    int ret = orchard_derive_unified_address(
        seed, ZCASH_COIN_TYPE, ZCASH_ACCOUNT,
        ZCASH_UA_HRP, ua_out, ua_len, d, pk_d);
    memzero(seed, sizeof(seed));

    if (ret <= 0) {
        return WALLET_ERR_SIGN_FAILED;
    }

    /* Cache in NVS */
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, NVS_KEY_UA, ua_out);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "UA cached in NVS");
    }

    return WALLET_OK;
}

WalletError wallet_sign(const uint8_t sighash[32], const uint8_t alpha[32],
                        uint8_t sig_out[64], uint8_t rk_out[32])
{
    uint8_t seed[64];
    WalletError werr = derive_seed(seed);
    if (werr != WALLET_OK) return werr;

    uint8_t sk[32];
    orchard_derive_account_sk(seed, ZCASH_COIN_TYPE, ZCASH_ACCOUNT, sk);
    memzero(seed, sizeof(seed));

    uint8_t ask[32], nk_discard[32], rivk_discard[32];
    orchard_derive_keys(sk, ask, nk_discard, rivk_discard);
    memzero(sk, sizeof(sk));
    memzero(nk_discard, sizeof(nk_discard));
    memzero(rivk_discard, sizeof(rivk_discard));

    int ret = redpallas_sign(ask, alpha, sighash, sig_out, rk_out);
    memzero(ask, sizeof(ask));

    return (ret == 0) ? WALLET_OK : WALLET_ERR_SIGN_FAILED;
}

WalletError wallet_wipe(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return WALLET_ERR_NVS;
    }
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);

    ESP_LOGW(TAG, "Wallet wiped (mnemonic + cached keys)!");
    return WALLET_OK;
}
