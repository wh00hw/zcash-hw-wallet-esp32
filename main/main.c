/**
 * Zcash Orchard/Ironwood signer — ESP32-S2 reference firmware
 *
 * Implements the device side of HWP over USB CDC, on top of the
 * libzcash-ironwood-c signer (orchard_signer.h, November 2026 API).
 *
 * READ THIS FIRST: the board has no display. Everything this firmware
 * "shows" for review — addresses, amounts, memos, totals — is written with
 * ESP_LOG* to USB CDC 1 (ACM1), i.e. to the same computer that runs the
 * companion. The BOOT-button confirmation therefore proves that a button
 * was pressed, not that the user saw anything a compromised host did not
 * rewrite. See README.md, "What this is not".
 */
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "bootloader_random.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "freertos/ringbuf.h"
#include "usb_transport.h"
#include "pallas.h"
#include "hwp.h"
#include "wallet.h"
#include "orchard.h"
#include "redpallas.h"
#include "zip244.h"
#include "orchard_signer.h"
#include "base58.h"
#include "bip39.h"
#include "memzero.h"
#include "aes_ct.h"
#include "mbedtls/aes.h"
#include "led_status.h"
#include "user_input.h"

static const char *TAG = "hwp";

static uint8_t tx_buf[HWP_MAX_FRAME];
static HwpParser rx_parser;

/* Device state — HWP commands are rejected until READY */
static volatile bool device_ready = false;

/* Cached unified address (derived once at boot) */
static char cached_ua[256];

/* Signing context. The library's state machine orders the steps (review
 * before verify, verify before sign); whether the user really saw the
 * review is this firmware's responsibility, and on this board it cannot be
 * guaranteed (see the note at the top of the file). */
static OrchardSignerCtx signer_ctx;

/* Signatures given for the transaction currently VERIFIED: at most one per
 * action, then the session ends. */
static uint16_t sigs_given;

/* The device's network. Fixed at build time; never taken from the host. */
#define DEVICE_COIN_TYPE  ((uint32_t)ZCASH_DEVICE_COIN_TYPE)
#define DEVICE_IS_TESTNET (DEVICE_COIN_TYPE != ORCHARD_SIGNER_COIN_MAINNET)

static void session_reset(void)
{
    orchard_signer_reset(&signer_ctx);   /* also wipes the session's viewing keys */
    sigs_given = 0;
}

/* Wait CDC1 long enough for any in-flight log lines to flush before we
 * change state. Otherwise the user may see "approve?" before the recipient
 * line has finished printing on the host's terminal. */
static void log_drain_delay(void)
{
    vTaskDelay(pdMS_TO_TICKS(80));
}

/* "<whole>.<8 decimals> ZEC|TAZ (<n> zatoshis)" */
static void log_amount(const char *label, uint64_t zat)
{
    ESP_LOGW(TAG, "    %s %llu.%08llu %s (%llu zatoshis)", label,
             (unsigned long long)(zat / 100000000ULL),
             (unsigned long long)(zat % 100000000ULL),
             DEVICE_IS_TESTNET ? "TAZ" : "ZEC",
             (unsigned long long)zat);
}

/* 21 million coins. A larger amount cannot exist on chain: one that reaches
 * the review is not shown, the session is aborted. */
#define MAX_MONEY_ZAT 2100000000000000ULL

typedef enum {
    REVIEW_OK = 0,
    REVIEW_CANCELLED,     /* long press or timeout */
    REVIEW_SIGNER_ERROR,  /* *serr holds the signer's error (session reset by the library) */
    REVIEW_UNRENDERABLE,  /* an output could not be turned into an address */
} ReviewResult;

/* One prompt: wait for the BOOT button. Short press = approve. */
static bool wait_approve(void)
{
    ESP_LOGW(TAG, "  -> short-press BOOT to approve, hold >2s to cancel");
    log_drain_delay();
    UserInputResult r = user_input_wait(120000);  /* 2 minutes per prompt */
    if (r == USER_INPUT_CONFIRM) {
        ESP_LOGI(TAG, "    approved");
        return true;
    }
    ESP_LOGW(TAG, "    %s", r == USER_INPUT_CANCEL ? "CANCELLED by user"
                                                    : "TIMEOUT - no confirmation received");
    return false;
}

/* Print a verified memo in full. Text (lead byte 0x00..0xF4): printable
 * ASCII as is, every other byte as '?'. Anything else: hex, lead byte
 * included. Trailing zero padding is not printed. */
static void log_memo(const uint8_t memo[512])
{
    size_t n = 512;
    while (n > 1 && memo[n - 1] == 0x00) n--;
    const bool text = (memo[0] <= 0xF4);
    ESP_LOGW(TAG, "    Memo (%s, %u bytes):", text ? "text" : "NOT text, hex", (unsigned)n);
    char line[100];
    const size_t per_line = text ? 64 : 32;
    for (size_t off = 0; off < n; off += per_line) {
        size_t lp = 0;
        for (size_t k = off; k < off + per_line && k < n; k++) {
            uint8_t b = memo[k];
            if (text) {
                line[lp++] = (b >= 0x20 && b <= 0x7E) ? (char)b : '?';
            } else {
                static const char H[] = "0123456789abcdef";
                line[lp++] = H[b >> 4];
                line[lp++] = H[b & 0x0F];
            }
        }
        line[lp] = '\0';
        ESP_LOGW(TAG, "      |%s|", line);
    }
}

/**
 * The review, driven after the host's sighash sentinel:
 *
 *   0. orchard_signer_get_totals() first — it fails unless every action is
 *      in and the sums are in range, before the user is asked anything;
 *   1. every transparent output, as a t-address: a payment that leaves;
 *   2. every shielded output that needs review (value != 0, or a memo),
 *      labelled from the signer's OWN classification — change, own
 *      address, or payment to someone else. Zero-value padding with no
 *      memo is not shown (review_required == false; the library has
 *      already confirmed it and counts it in totals.n_zero_value);
 *   3. the totals: what leaves the wallet, and the fee.
 *
 * Each step needs a BOOT press. orchard_signer_verify() refuses unless
 * every reviewed output and the totals were confirmed.
 *
 * Nothing the host says about an output is used for its label, and the
 * amount / fee / recipient fields of SIGN_REQ are never printed.
 */
static ReviewResult run_review(OrchardSignerError *serr)
{
    OrchardSignerTotals totals;
    *serr = orchard_signer_get_totals(&signer_ctx, &totals);
    if (*serr != SIGNER_OK) return REVIEW_SIGNER_ERROR;

    if (totals.total_leaving > MAX_MONEY_ZAT || totals.fee > MAX_MONEY_ZAT ||
        totals.own_internal > MAX_MONEY_ZAT || totals.own_external > MAX_MONEY_ZAT ||
        totals.external_shielded > MAX_MONEY_ZAT || totals.transparent_out > MAX_MONEY_ZAT) {
        ESP_LOGE(TAG, "REFUSED: an amount above 21 million coins");
        return REVIEW_UNRENDERABLE;
    }

    const char *hrp = wallet_hrp_for_coin_type(DEVICE_COIN_TYPE);

    unsigned n_shown = totals.n_transparent_out;
    for (uint16_t i = 0; i < signer_ctx.actions_received; i++) {
        OrchardOutputInfo info;
        if (orchard_signer_get_output(&signer_ctx, i, &info) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
        if (info.review_required) n_shown++;
    }
    unsigned shown = 0;

    led_status_set(LED_STATE_AWAITING_CONFIRM);
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "==================================================");
    ESP_LOGW(TAG, "  REVIEW BEFORE SIGNING: %u output(s), then the totals", n_shown);
    ESP_LOGW(TAG, "  (this text is on the HOST's screen, not on a device display)");
    ESP_LOGW(TAG, "==================================================");

    /* 1. Transparent outputs. Always leaving: the device does not
     *    recognise its own t-address. */
    for (uint16_t i = 0; i < totals.n_transparent_out; i++) {
        uint8_t script[25];
        size_t script_len = 0;
        uint64_t value = 0;
        char taddr[64];
        if (orchard_signer_get_transparent_output_display(
                &signer_ctx, i, &value, script, sizeof(script), &script_len) != SIGNER_OK ||
            script_to_taddr(script, script_len, DEVICE_IS_TESTNET, taddr, sizeof(taddr)) == 0) {
            ESP_LOGE(TAG, "transparent output %u cannot be displayed", (unsigned)i);
            return REVIEW_UNRENDERABLE;
        }
        if (value > MAX_MONEY_ZAT) {
            ESP_LOGE(TAG, "REFUSED: an amount above 21 million coins");
            return REVIEW_UNRENDERABLE;
        }
        shown++;
        ESP_LOGW(TAG, "");
        ESP_LOGW(TAG, "  [%u/%u] t-address PAYMENT - LEAVES THE WALLET", shown, n_shown);
        log_amount("Value:", value);
        ESP_LOGW(TAG, "    To:    %s", taddr);
        ESP_LOGW(TAG, "    (transparent: public on chain, no memo)");
        if (!wait_approve()) return REVIEW_CANCELLED;
    }

    /* 2. Shielded outputs. */
    for (uint16_t i = 0; i < signer_ctx.actions_received; i++) {
        OrchardOutputInfo info;
        if (orchard_signer_get_output(&signer_ctx, i, &info) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
        if (!info.review_required) continue;   /* verified zero-value padding, no memo */
        if (info.value > MAX_MONEY_ZAT) {
            ESP_LOGE(TAG, "REFUSED: an amount above 21 million coins");
            return REVIEW_UNRENDERABLE;
        }

        char ua[256] = {0};
        if (orchard_encode_ua_raw(info.recipient, info.recipient + 11, hrp, ua, sizeof(ua)) <= 0) {
            ESP_LOGE(TAG, "orchard_encode_ua_raw failed for action %u", (unsigned)i);
            return REVIEW_UNRENDERABLE;
        }

        shown++;
        ESP_LOGW(TAG, "");
        switch (info.ownership) {
        case ORCHARD_OUTPUT_OWN_INTERNAL:
            ESP_LOGW(TAG, "  [%u/%u] CHANGE (your wallet)", shown, n_shown);
            log_amount("Value:", info.value);
            ESP_LOGW(TAG, "    returns to this wallet (decided on-device from its keys)");
            break;
        case ORCHARD_OUTPUT_OWN_EXTERNAL:
            ESP_LOGW(TAG, "  [%u/%u] YOUR ADDRESS (one of this wallet's own receiving addresses)",
                     shown, n_shown);
            log_amount("Value:", info.value);
            ESP_LOGW(TAG, "    address: %s", ua);
            break;
        case ORCHARD_OUTPUT_EXTERNAL:
            if (info.value != 0) {
                ESP_LOGW(TAG, "  [%u/%u] PAYMENT - LEAVES THE WALLET", shown, n_shown);
            } else {
                ESP_LOGW(TAG, "  [%u/%u] MESSAGE (memo only, carries no funds) to an address "
                              "that is not this wallet's", shown, n_shown);
            }
            log_amount("Value:", info.value);
            ESP_LOGW(TAG, "    To:    %s", ua);
            ESP_LOGW(TAG, "    CHECK THIS ADDRESS: it is not one of this wallet's.");
            break;
        default:
            /* Unclassified: never label, never approve. */
            ESP_LOGE(TAG, "action %u has no ownership classification", (unsigned)i);
            return REVIEW_UNRENDERABLE;
        }

        if (info.memo == ORCHARD_MEMO_PRESENT) {
            static uint8_t memo_buf[512];
            bool present = false;
            OrchardSignerError merr =
                orchard_signer_get_action_memo(&signer_ctx, i, memo_buf, &present);
            if (merr != SIGNER_OK || !present) {
                memzero(memo_buf, sizeof(memo_buf));
                return REVIEW_UNRENDERABLE;
            }
            log_memo(memo_buf);
            memzero(memo_buf, sizeof(memo_buf));
        } else if (info.memo == ORCHARD_MEMO_NONE) {
            ESP_LOGW(TAG, "    Memo:  none");
        } else {
            return REVIEW_UNRENDERABLE;
        }

        if (!wait_approve()) return REVIEW_CANCELLED;
        if (orchard_signer_confirm_action(&signer_ctx, i) != SIGNER_OK) {
            return REVIEW_UNRENDERABLE;
        }
    }

    /* 3. Totals. */
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "  TOTALS (computed on the device)");
    log_amount("TOTAL LEAVING THE WALLET:", totals.total_leaving);
    log_amount("  of which fee:          ", totals.fee);
    ESP_LOGW(TAG, "    payments to others: %u shielded, %u transparent",
             (unsigned)totals.n_external, (unsigned)totals.n_transparent_out);
    log_amount("change returning:        ", totals.own_internal);
    if (totals.own_external != 0) {
        log_amount("to own receiving addrs:  ", totals.own_external);
    }
    ESP_LOGW(TAG, "    zero-value padding outputs (not shown): %u",
             (unsigned)totals.n_zero_value);
    ESP_LOGW(TAG, "  Approving this authorises the signatures for this transaction.");
    if (!wait_approve()) return REVIEW_CANCELLED;

    *serr = orchard_signer_confirm_totals(&signer_ctx);
    if (*serr != SIGNER_OK) return REVIEW_SIGNER_ERROR;

    ESP_LOGW(TAG, "  REVIEW COMPLETE");
    ESP_LOGW(TAG, "==================================================");
    return REVIEW_OK;
}

/* Embedded Sinsemilla S-table (1024 points, 64 bytes each = 64KB) */
extern const uint8_t sinsemilla_s_bin_start[] asm("_binary_sinsemilla_s_bin_start");
extern const uint8_t sinsemilla_s_bin_end[]   asm("_binary_sinsemilla_s_bin_end");

/* The Sinsemilla S-table integrity check is performed by the library
 * function `pallas_verify_sinsemilla_table()` (see audit M-5). It walks
 * the registered lookup callback for every index and compares the
 * BLAKE2b-256 of the returned data against the canonical fingerprint
 * baked into the library. Keeping the check in the library means every
 * firmware (regardless of how the table is embedded — objcopy on
 * ESP-IDF, BOLOS resource on Ledger, raw flash region on STM32 — gets
 * the same canonical defence). This file just registers the callback. */

static bool sinsemilla_lookup(uint32_t index, uint8_t buf_out[64], void *ctx)
{
    if (index >= 1024) return false;
    memcpy(buf_out, sinsemilla_s_bin_start + index * 64, 64);
    return true;
}

/* ============================================================================
 * Hardware-AES backend for libzcash-orchard-c (audit H-3).
 *
 * The C library ships with a constant-time software AES-256 (aes_ct.c) used
 * by FF1 for diversifier derivation. ESP32-S2 has a hardware AES peripheral
 * which is constant-time by construction and significantly faster than the
 * software fallback. We register an override that routes every AES-256 ECB
 * call through ESP-IDF's mbedtls — which on this target dispatches to the
 * hardware accelerator when CONFIG_MBEDTLS_HARDWARE_AES is enabled (it is
 * by default in ESP-IDF).
 *
 * The override signature takes the master key directly (32 bytes), so each
 * call re-schedules. mbedTLS's HW path makes this essentially free; the
 * software path would re-schedule too.
 * ============================================================================ */
static void hw_aes256_override(void *ctx_user,
                               const uint8_t key[32],
                               const uint8_t in[16],
                               uint8_t out[16])
{
    (void)ctx_user;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    /* setkey_enc returns non-zero only on invalid key sizes — 256 is always
     * valid; we ignore the return rather than introduce an error path that
     * the C library's interface does not have. */
    (void)mbedtls_aes_setkey_enc(&aes, key, 256);
    (void)mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&aes);
}

/* Yield callback — feeds watchdog during long Sinsemilla computations */
static void yield_cb(void *ctx)
{
    esp_task_wdt_reset();
    vTaskDelay(1); /* let other tasks run */
}

/* Every Error frame ends the signing session (same rule as the library's
 * dispatcher): the signer is reset — viewing keys, hashes, approvals — before
 * the frame goes out, so a host cannot provoke an error and carry on with
 * the approvals it had. */
static void send_error(uint8_t seq, HwpErrorCode code, const char *msg)
{
    session_reset();
    ESP_LOGW(TAG, "ERR 0x%02x: %s", code, msg ? msg : "");
    led_status_set(LED_STATE_ERROR);
    size_t len = hwp_encode_error(tx_buf, seq, code, msg);
    usb_transport_send(tx_buf, len);
}

static void send_pong(uint8_t seq)
{
    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_PONG, NULL, 0);
    usb_transport_send(tx_buf, len);
    ESP_LOGI(TAG, "PING/PONG seq=%d", seq);
}

/* Report a signer error to the host. One mapping for every handler.
 * send_error() resets the session. */
static void fail_signer(uint8_t seq, OrchardSignerError serr)
{
    HwpErrorCode code = HWP_ERR_BAD_FRAME;
    const char *msg = "bad transaction data";
    switch (serr) {
    case SIGNER_ERR_SAPLING_NOT_EMPTY:
        code = HWP_ERR_SAPLING_NOT_EMPTY; msg = "sapling components not allowed"; break;
    case SIGNER_ERR_BRANCH_NOT_ALLOWED:
        code = HWP_ERR_BRANCH_NOT_ALLOWED; msg = "consensus branch not supported by this firmware"; break;
    case SIGNER_ERR_BAD_FVK:
        code = HWP_ERR_INVALID_STATE; msg = "device viewing key unavailable"; break;
    case SIGNER_ERR_TOO_MANY_ACTIONS:
        code = HWP_ERR_LIMIT_EXCEEDED; msg = "more outputs than the device can review"; break;
    case SIGNER_ERR_TOO_MANY_MEMOS:
        code = HWP_ERR_LIMIT_EXCEEDED; msg = "more memos than the device can review"; break;
    case SIGNER_ERR_NOTE_COMMITMENT_MISMATCH:
        code = HWP_ERR_NOTE_COMMITMENT_MISMATCH; msg = "action cmx does not commit to claimed note"; break;
    case SIGNER_ERR_MEMO_MISMATCH:
        code = HWP_ERR_MEMO_MISMATCH; msg = "enc_ciphertext does not match recomputed note/memo"; break;
    case SIGNER_ERR_NETWORK_MISMATCH:
    case SIGNER_ERR_NETWORK_UNSET:
        code = HWP_ERR_NETWORK_MISMATCH; msg = "TxMeta coin_type is not the device's network"; break;
    case SIGNER_ERR_NO_ACTIONS:
        msg = "transaction has no shielded actions"; break;
    case SIGNER_ERR_EMPTY_POOL_BALANCE:
        code = HWP_ERR_EMPTY_POOL_BALANCE; msg = "non-zero value balance for a pool without actions"; break;
    case SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED:
        code = HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED; msg = "transparent inputs are not supported"; break;
    case SIGNER_ERR_TRANSPARENT_MISMATCH:
        code = HWP_ERR_TRANSPARENT_DIGEST_MISMATCH; msg = "transparent digest mismatch"; break;
    case SIGNER_ERR_TRANSPARENT_BAD_OUTPUT:
        msg = "bad transparent output (P2PKH / P2SH only)"; break;
    case SIGNER_ERR_BAD_PK_D:
        code = HWP_ERR_BAD_PK_D; msg = "pk_d does not decode to a valid Pallas point"; break;
    case SIGNER_ERR_FEE_OVERFLOW:
        code = HWP_ERR_FEE_OVERFLOW; msg = "fee arithmetic overflow"; break;
    case SIGNER_ERR_FEE_NEGATIVE:
        code = HWP_ERR_FEE_NEGATIVE; msg = "negative fee (unbalanced transaction)"; break;
    case SIGNER_ERR_VALUE_OVERFLOW:
        code = HWP_ERR_VALUE_OVERFLOW; msg = "output values overflow"; break;
    case SIGNER_ERR_SIGHASH_MISMATCH:
        code = HWP_ERR_SIGHASH_MISMATCH; msg = "device sighash != companion sighash"; break;
    case SIGNER_ERR_BAD_STATE:
    case SIGNER_ERR_ACTION_NOT_CONFIRMED:
    case SIGNER_ERR_FEE_NOT_CONFIRMED:
    case SIGNER_ERR_TRANSPARENT_NOT_EMPTY:
        code = HWP_ERR_INVALID_STATE; msg = "unexpected message for the current signing state"; break;
    case SIGNER_ERR_BAD_META:
        msg = "bad tx metadata"; break;
    default:
        break;
    }
    ESP_LOGE(TAG, "signer error %d", (int)serr);
    send_error(seq, code, msg);
}

static void send_ack(uint8_t seq)
{
    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
    usb_transport_send(tx_buf, len);
}

static void handle_fvk_req(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    /* The host may say which network it expects (4 bytes LE). It cannot set
     * the device's: a request naming the other network is refused. A
     * request naming none (no payload, or 0) is answered. */
    if (payload_len >= HWP_FVK_REQ_SIZE) {
        uint32_t req_coin = (uint32_t)payload[0]
                          | ((uint32_t)payload[1] << 8)
                          | ((uint32_t)payload[2] << 16)
                          | ((uint32_t)payload[3] << 24);
        if (req_coin != 0 && req_coin != DEVICE_COIN_TYPE) {
            ESP_LOGE(TAG, "FVK_REQ for coin_type=%u, device is on %u",
                     (unsigned)req_coin, (unsigned)DEVICE_COIN_TYPE);
            send_error(seq, HWP_ERR_NETWORK_MISMATCH,
                       DEVICE_IS_TESTNET ? "device is on testnet" : "device is on mainnet");
            return;
        }
    }

    ESP_LOGI(TAG, "FVK_REQ received (seq=%d), coin_type=%u", seq, (unsigned)DEVICE_COIN_TYPE);
    led_status_set(LED_STATE_BUSY_KEY);

    uint8_t fvk[96];
    WalletError err = wallet_get_fvk(fvk, DEVICE_COIN_TYPE);
    if (err != WALLET_OK) {
        ESP_LOGE(TAG, "FVK derivation FAILED (err=%d)", err);
        send_error(seq, HWP_ERR_SIGN_FAILED, "key derivation failed");
        return;
    }
    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_FVK_RSP, fvk, 96);
    usb_transport_send(tx_buf, len);
    led_status_set(LED_STATE_SUCCESS);
    ESP_LOGI(TAG, "FVK_RSP sent (96 bytes, seq=%d)", seq);
}

static void handle_tx_output(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    HwpTxOutput out;
    if (!hwp_parse_tx_output(payload, payload_len, &out)) {
        send_error(seq, HWP_ERR_BAD_FRAME, "invalid tx_output payload");
        return;
    }

    OrchardSignerError serr;

    /* --- Metadata message (output_index == 0xFFFF) --- */
    if (out.output_index == HWP_TX_META_INDEX) {
        /* A TxMeta always starts a new transaction from nothing. */
        session_reset();

        /* The full viewing key every output will be classified against
         * (own change / own address / someone else's). Derived here from
         * the PIN-unsealed mnemonic in RAM — NOT read from the NVS cache,
         * which is neither encrypted nor authenticated: whoever can rewrite
         * that cache must not get to decide what "own" means. */
        uint8_t fvk_bytes[96];
        if (wallet_derive_fvk(fvk_bytes, DEVICE_COIN_TYPE) != WALLET_OK) {
            memzero(fvk_bytes, sizeof(fvk_bytes));
            fail_signer(seq, SIGNER_ERR_BAD_FVK);
            return;
        }
        OrchardSignerFvk fvk = {
            .ak = fvk_bytes, .nk = fvk_bytes + 32, .rivk = fvk_bytes + 64 };
        serr = orchard_signer_feed_meta(&signer_ctx, &fvk, out.output_data,
                                         out.output_data_len, out.total_outputs);
        memzero(fvk_bytes, sizeof(fvk_bytes));
        if (serr != SIGNER_OK) {
            fail_signer(seq, serr);
            return;
        }
        led_status_set(LED_STATE_TX_PROGRESS);
        ESP_LOGI(TAG, "TX metadata accepted, expecting %d actions", out.total_outputs);
        send_ack(seq);
        return;
    }

    /* --- Sentinel (output_index == total_outputs): expected sighash --- */
    if (out.output_index == out.total_outputs) {
        if (out.output_data_len != 32) {
            send_error(seq, HWP_ERR_BAD_SIGHASH, "sentinel must be 32 bytes");
            return;
        }

        /* Review: every output that carries value or a memo, then the
         * totals. verify() below refuses unless all of it was confirmed. */
        ReviewResult rr = run_review(&serr);
        if (rr == REVIEW_SIGNER_ERROR) {
            fail_signer(seq, serr);
            return;
        }
        if (rr == REVIEW_UNRENDERABLE) {
            send_error(seq, HWP_ERR_INVALID_STATE,
                       "output cannot be displayed (or amount out of range)");
            return;
        }
        if (rr != REVIEW_OK) {
            send_error(seq, HWP_ERR_USER_CANCELLED,
                       "user cancelled or timed out during the review");
            return;
        }
        led_status_set(LED_STATE_TX_PROGRESS);

        serr = orchard_signer_verify(&signer_ctx, out.output_data);
        if (serr != SIGNER_OK) {
            ESP_LOGE(TAG, "Sighash verify failed (err=%d)", serr);
            fail_signer(seq, serr);
            return;
        }
        sigs_given = 0;

        ESP_LOGI(TAG, "ZIP-244 sighash verified - signing authorized");
        send_ack(seq);
        return;
    }

    /* --- Action data (output_index 0..N-1) ---
     *
     * v6 wire tier only: 1-byte pool tag (0x00 sealed Orchard, 0x01
     * Ironwood) followed by the memo-carrying body, 1416 bytes:
     *   action[820] || recipient[43] || value[8 LE] || rseed[32] || memo[512]
     * The device recomputes the note commitment AND the ciphertext of every
     * action from it. The compact (no-memo, 904 B) body no longer has an
     * entry point in the library and is refused, as is anything else. */
    if (out.output_data_len == HWP_ACTION_DATA_SIZE_V6_COMPACT) {
        send_error(seq, HWP_ERR_MEMO_REQUIRED,
                   "compact action body refused: send the memo-carrying body");
        return;
    }
    if (out.output_data_len != HWP_ACTION_DATA_SIZE_V6) {
        ESP_LOGE(TAG, "Action payload is %u bytes, expected %d (v6 pool-tagged, with memo)",
                 (unsigned)out.output_data_len, HWP_ACTION_DATA_SIZE_V6);
        send_error(seq, HWP_ERR_BAD_FRAME,
                   "action payload must be v6 pool-tagged with memo (1416 bytes)");
        return;
    }
    if (out.output_data[0] > ZIP244_POOL_IRONWOOD) {
        send_error(seq, HWP_ERR_BAD_FRAME, "bad v6 action pool tag");
        return;
    }
    /* The index must be the next one, and the announced total must not
     * change: an action cannot be replayed, skipped or re-ordered. */
    if (out.output_index != signer_ctx.actions_received ||
        out.total_outputs != signer_ctx.actions_expected) {
        send_error(seq, HWP_ERR_INVALID_STATE, "action out of sequence");
        return;
    }
    Zip244Pool pool = (Zip244Pool)out.output_data[0];
    const uint8_t *adata = out.output_data + HWP_POOL_TAG_SIZE;
    size_t alen = (size_t)out.output_data_len - HWP_POOL_TAG_SIZE;

    HwpActionV5 av5;
    if (!hwp_parse_action_v5(adata, (uint16_t)alen, &av5)) {
        send_error(seq, HWP_ERR_BAD_FRAME, "action memo-body size mismatch");
        return;
    }
    serr = orchard_signer_feed_action_with_note_and_memo(
        &signer_ctx, pool, av5.action, HWP_ACTION_DATA_SIZE,
        av5.recipient, av5.value, av5.rseed, av5.memo);
    if (serr != SIGNER_OK) {
        ESP_LOGE(TAG, "Action %d/%d rejected", out.output_index + 1, out.total_outputs);
        fail_signer(seq, serr);
        return;
    }

    ESP_LOGI(TAG, "Action %d/%d: cmx + ciphertext verified, classified, hashed",
             out.output_index + 1, out.total_outputs);
    send_ack(seq);
}

/* SIGN_REQ. Two fields are used: the sighash, which must be the one the
 * device computed and verified, and alpha. amount, fee and recipient are
 * the host's words about a transaction the device has already examined
 * itself: parsed for framing, otherwise ignored — not checked, not printed.
 *
 * At most one signature per action for a verified transaction; when the
 * count is reached the session ends. */
static void handle_sign_req(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    ESP_LOGI(TAG, "SIGN_REQ received (seq=%d, %d bytes)", seq, payload_len);

    static HwpSignReq req;
    if (!hwp_parse_sign_req(payload, payload_len, &req)) {
        send_error(seq, HWP_ERR_BAD_SIGHASH, "invalid sign_req payload");
        return;
    }

    OrchardSignerError chk = orchard_signer_check(&signer_ctx, req.sighash);
    if (chk == SIGNER_ERR_NOT_VERIFIED) {
        ESP_LOGE(TAG, "SIGN_REQ rejected: transaction not reviewed and verified");
        send_error(seq, HWP_ERR_INVALID_STATE, "sighash not verified");
        return;
    }
    if (chk != SIGNER_OK) {
        ESP_LOGE(TAG, "SIGN_REQ sighash does not match verified sighash");
        send_error(seq, HWP_ERR_SIGHASH_MISMATCH, "SignReq sighash mismatch");
        return;
    }
    if (sigs_given >= signer_ctx.actions_received) {
        send_error(seq, HWP_ERR_INVALID_STATE, "signature limit reached");
        return;
    }

    led_status_set(LED_STATE_BUSY_SIGN);
    ESP_LOGI(TAG, "Signing (%u/%u)...", (unsigned)(sigs_given + 1),
             (unsigned)signer_ctx.actions_received);

    uint8_t sig[64], rk[32];
    WalletError err = wallet_sign_via_ctx(&signer_ctx, req.sighash, req.alpha, sig, rk,
                                          DEVICE_COIN_TYPE);
    memzero(&req, sizeof(req));
    if (err != WALLET_OK) {
        ESP_LOGE(TAG, "Signing FAILED (err=%d)", err);
        memzero(sig, sizeof(sig));
        send_error(seq, HWP_ERR_SIGN_FAILED, "signing failed");
        return;
    }

    uint8_t rsp[96];
    memcpy(rsp, sig, 64);
    memcpy(rsp + 64, rk, 32);

    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_SIGN_RSP, rsp, 96);
    usb_transport_send(tx_buf, len);
    led_status_set(LED_STATE_SUCCESS);
    ESP_LOGI(TAG, "SIGN_RSP sent (sig[64] + rk[32], seq=%d)", seq);

    sigs_given++;
    if (sigs_given >= signer_ctx.actions_received) {
        ESP_LOGI(TAG, "One signature per action given - transaction done, session reset");
        session_reset();
    }
}

/* ------------------------------------------------------------------ */
/*  Transparent messages                                              */
/*                                                                    */
/*  Transparent OUTPUTS (shielded -> t-address payments) are          */
/*  supported: hashed into the transparent digest, shown in the       */
/*  review as t-addresses, counted as leaving the wallet.             */
/*                                                                    */
/*  Transparent INPUTS and transparent SIGNING are not supported      */
/*  (libzcash-ironwood-c refuses them). No transparent key is derived */
/*  and no transparent public key is ever sent.                       */
/* ------------------------------------------------------------------ */

/* TX_TRANSPARENT_INPUT. The only frame of this type that is accepted is
 * the one that carries no input: index == total == 0 with the 32-byte
 * transparent digest — the sentinel that closes the transparent-output
 * stream. Anything announcing an input is handed to the library, which
 * refuses it (SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED) and resets. */
static void handle_transparent_input(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len < HWP_TX_OUTPUT_HEADER) {
        send_error(seq, HWP_ERR_BAD_FRAME, "transparent input too short");
        return;
    }

    uint16_t input_index  = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
    uint16_t total_inputs = (uint16_t)payload[2] | ((uint16_t)payload[3] << 8);
    const uint8_t *data   = payload + HWP_TX_OUTPUT_HEADER;
    uint16_t data_len     = payload_len - HWP_TX_OUTPUT_HEADER;

    OrchardSignerError serr;

    if (total_inputs != 0 || input_index != 0) {
        serr = orchard_signer_feed_transparent_input(&signer_ctx, data, data_len);
        ESP_LOGE(TAG, "Transparent input refused: spending from a t-address is not supported");
        fail_signer(seq, serr != SIGNER_OK ? serr : SIGNER_ERR_TRANSPARENT_INPUTS_UNSUPPORTED);
        return;
    }
    if (data_len != 32) {
        send_error(seq, HWP_ERR_BAD_FRAME, "transparent sentinel must be 32 bytes");
        return;
    }
    /* A host may close an empty transparent stream too (no outputs): the
     * digest is then the empty-bundle constant. */
    if (signer_ctx.state == SIGNER_RECEIVING_ACTIONS && !signer_ctx.transparent_begun) {
        serr = orchard_signer_begin_transparent(&signer_ctx, 0, 0);
        if (serr != SIGNER_OK) {
            fail_signer(seq, serr);
            return;
        }
    }
    serr = orchard_signer_verify_transparent(&signer_ctx, data);
    if (serr != SIGNER_OK) {
        ESP_LOGE(TAG, "Transparent digest verification failed (err=%d)", serr);
        fail_signer(seq, serr);
        return;
    }

    ESP_LOGI(TAG, "Transparent outputs digest verified - matches TxMeta");
    send_ack(seq);
}

static void handle_transparent_output(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len < HWP_TX_OUTPUT_HEADER) {
        send_error(seq, HWP_ERR_BAD_FRAME, "transparent output too short");
        return;
    }

    uint16_t output_index  = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
    uint16_t total_outputs = (uint16_t)payload[2] | ((uint16_t)payload[3] << 8);
    const uint8_t *data    = payload + HWP_TX_OUTPUT_HEADER;
    uint16_t data_len      = payload_len - HWP_TX_OUTPUT_HEADER;

    OrchardSignerError serr;

    /* The first output opens the transparent pass — with zero inputs. More
     * outputs than the device can show are refused here, before any is
     * hashed. */
    if (output_index == 0 && signer_ctx.state == SIGNER_RECEIVING_ACTIONS) {
        serr = orchard_signer_begin_transparent(&signer_ctx, 0, total_outputs);
        if (serr != SIGNER_OK) {
            fail_signer(seq, serr);
            return;
        }
        ESP_LOGI(TAG, "Expecting %d transparent outputs", total_outputs);
    }
    /* Like actions: the next index, an unchanged total. */
    if (signer_ctx.state != SIGNER_RECEIVING_TRANSPARENT ||
        output_index != signer_ctx.transparent_state.outputs_received ||
        total_outputs != signer_ctx.transparent_outputs_expected) {
        send_error(seq, HWP_ERR_INVALID_STATE, "transparent output out of sequence");
        return;
    }

    serr = orchard_signer_feed_transparent_output(&signer_ctx, data, data_len);
    if (serr != SIGNER_OK) {
        fail_signer(seq, serr);
        return;
    }

    ESP_LOGI(TAG, "Transparent output %d/%d hashed (%d bytes)",
             output_index + 1, total_outputs, data_len);
    send_ack(seq);
}

/* TRANSPARENT_SIGN_REQ: refused, always. There is no transparent key in
 * this firmware to sign with. */
static void handle_transparent_sign_req(uint8_t seq)
{
    ESP_LOGE(TAG, "TRANSPARENT_SIGN_REQ refused: transparent signing is not supported");
    send_error(seq, HWP_ERR_TRANSPARENT_INPUTS_UNSUPPORTED,
               "transparent signing is not supported");
}

static void handle_abort(uint8_t seq)
{
    if (signer_ctx.state != SIGNER_IDLE) {
        ESP_LOGW(TAG, "Session aborted");
        session_reset();
    } else {
        ESP_LOGD(TAG, "ABORT (no active session)");
    }
    led_status_set(LED_STATE_CONNECTED);
}

/* ------------------------------------------------------------------ */
/*  Device attestation handlers (audit M1)                            */
/* ------------------------------------------------------------------ */

static void handle_identity_req(uint8_t seq)
{
    ESP_LOGI(TAG, "IDENTITY_REQ received (seq=%d)", seq);

    uint8_t device_pk[HWP_DEVICE_PUBKEY_SIZE];
    WalletError werr = wallet_get_or_create_device_identity(device_pk);
    if (werr != WALLET_OK) {
        ESP_LOGE(TAG, "device identity load/create failed (err=%d)", werr);
        send_error(seq, HWP_ERR_SIGN_FAILED, "device identity unavailable");
        return;
    }

    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_IDENTITY_RSP,
                            device_pk, HWP_DEVICE_PUBKEY_SIZE);
    usb_transport_send(tx_buf, len);
    /* device_pk is public — no memzero needed. */
    ESP_LOGI(TAG, "IDENTITY_RSP sent (32 bytes, seq=%d)", seq);
}

static void handle_attest_req(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != HWP_ATTEST_CHALLENGE_SIZE) {
        ESP_LOGE(TAG, "ATTEST_REQ bad payload length (%d != %d)",
                 payload_len, HWP_ATTEST_CHALLENGE_SIZE);
        send_error(seq, HWP_ERR_BAD_FRAME, "attest challenge must be 32 bytes");
        return;
    }
    ESP_LOGI(TAG, "ATTEST_REQ received (seq=%d)", seq);

    uint8_t sig[HWP_ATTEST_SIG_SIZE];
    uint8_t rk[HWP_DEVICE_PUBKEY_SIZE];
    WalletError werr = wallet_attest(payload, sig, rk);
    if (werr != WALLET_OK) {
        ESP_LOGE(TAG, "attestation failed (err=%d)", werr);
        send_error(seq, HWP_ERR_SIGN_FAILED, "attestation failed");
        memzero(sig, sizeof(sig));
        memzero(rk, sizeof(rk));
        return;
    }

    /* Response = sig[64] || rk[32] (rk == device_pk because alpha was 0) */
    uint8_t rsp[HWP_ATTEST_RSP_SIZE];
    memcpy(rsp,                     sig, HWP_ATTEST_SIG_SIZE);
    memcpy(rsp + HWP_ATTEST_SIG_SIZE, rk,  HWP_DEVICE_PUBKEY_SIZE);

    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_ATTEST_RSP, rsp, sizeof(rsp));
    usb_transport_send(tx_buf, len);

    memzero(sig, sizeof(sig));
    memzero(rk, sizeof(rk));
    memzero(rsp, sizeof(rsp));
    ESP_LOGI(TAG, "ATTEST_RSP sent (sig+rk = %d bytes, seq=%d)",
             HWP_ATTEST_RSP_SIZE, seq);
}

static void send_ping(void)
{
    uint8_t seq = 0x01;
    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_PING, NULL, 0);
    usb_transport_send(tx_buf, len);
    ESP_LOGI(TAG, "Handshake PING sent (seq=%d)", seq);
}

static void hwp_task(void *arg)
{
    /* Wait until device initialization is complete */
    while (!device_ready) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGI(TAG, "HWP listener started");

    for (;;) {
        HwpFeedResult res = usb_transport_recv_frame(&rx_parser, 0);
        if (res == HWP_FEED_CRC_ERROR) {
            send_error(rx_parser.frame.seq, HWP_ERR_BAD_FRAME, "CRC mismatch");
            continue;
        }
        if (res != HWP_FEED_FRAME_READY) continue;

        HwpFrame *f = &rx_parser.frame;
        ESP_LOGI(TAG, "Frame received: type=0x%02x seq=%d payload_len=%d", f->type, f->seq, f->payload_len);

        switch (f->type) {
        case HWP_MSG_PING:
            /* PING = new-session signal: nothing of a previous session
             * (viewing keys, approvals) survives it. */
            session_reset();
            send_pong(f->seq);
            break;
        case HWP_MSG_PONG:
            ESP_LOGI(TAG, "PONG received (seq=%d) — handshake complete", f->seq);
            break;
        case HWP_MSG_FVK_REQ:
            handle_fvk_req(f->seq, f->payload, f->payload_len);
            break;
        case HWP_MSG_TX_OUTPUT:
            handle_tx_output(f->seq, f->payload, f->payload_len);
            break;
        case HWP_MSG_SIGN_REQ:
            handle_sign_req(f->seq, f->payload, f->payload_len);
            break;
        case HWP_MSG_ABORT:
            handle_abort(f->seq);
            break;
        case HWP_MSG_TX_TRANSPARENT_INPUT:
            handle_transparent_input(f->seq, f->payload, f->payload_len);
            break;
        case HWP_MSG_TX_TRANSPARENT_OUTPUT:
            handle_transparent_output(f->seq, f->payload, f->payload_len);
            break;
        case HWP_MSG_TRANSPARENT_SIGN_REQ:
            handle_transparent_sign_req(f->seq);
            break;
        case HWP_MSG_IDENTITY_REQ:
            handle_identity_req(f->seq);
            break;
        case HWP_MSG_ATTEST_REQ:
            handle_attest_req(f->seq, f->payload, f->payload_len);
            break;
        default:
            send_error(f->seq, HWP_ERR_UNKNOWN, "unsupported msg type");
            break;
        }
    }
}

/* Monitor USB connection state and update LED accordingly */
static void usb_monitor_task(void *arg)
{
    bool was_connected = false;
    for (;;) {
        bool connected = usb_transport_host_connected();
        if (connected && !was_connected) {
            if (device_ready) {
                led_status_set(LED_STATE_CONNECTED);
                ESP_LOGI(TAG, "========================================");
                ESP_LOGI(TAG, " Zcash Orchard/Ironwood Hardware Wallet");
                ESP_LOGI(TAG, " HWP v%d | Target: ESP32-S2", HWP_VERSION);
                ESP_LOGI(TAG, " Wallet: READY%s",
                         wallet_is_backed_up() ? "" : " [NOT BACKED UP]");
                if (cached_ua[0]) {
                    ESP_LOGI(TAG, " UA: %s", cached_ua);
                }
                ESP_LOGI(TAG, " ACM0: HWP protocol | ACM1: logs");
                ESP_LOGI(TAG, "========================================");
                /* Send handshake PING — companion expects device to initiate */
                vTaskDelay(pdMS_TO_TICKS(300));
                send_ping();
            } else {
                ESP_LOGW(TAG, "Host connected but device still initializing...");
            }
        } else if (!connected && was_connected) {
            session_reset();
            if (device_ready) {
                led_status_set(LED_STATE_READY);
            }
            ESP_LOGI(TAG, "Host disconnected");
        }
        was_connected = connected;
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

static void fatal_halt(const char *reason)
{
    led_status_set(LED_STATE_ERROR);
    for (;;) {
        ESP_LOGE(TAG, "FATAL: %s — device halted", reason);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, " Zcash Orchard/Ironwood Hardware Wallet");
    ESP_LOGI(TAG, " HWP v%d | Target: ESP32-S2", HWP_VERSION);
    ESP_LOGI(TAG, "========================================");

    /* On ESP32-S2, esp_random() / esp_fill_random() return cryptographically
     * strong entropy only when WiFi/BT is started or the SAR/RC oscillator
     * chaos-mode source has been explicitly enabled. WiFi/BT are intentionally
     * disabled on this device, so we enable the bootloader RNG source here and
     * leave it on for the lifetime of the firmware: mnemonic generation at
     * first boot, FVK derivation, and per-signature RedPallas nonce hedging
     * all rely on a CSPRNG. No other code path on this board uses the SAR-ADC,
     * which is the precondition Espressif documents for keeping the source
     * enabled at runtime. (Audit: docs/security-audit/03-firmware-esp32.md C-4)
     */
    bootloader_random_enable();

    /* Init signing context and fix the device's network (build-time). */
    orchard_signer_init(&signer_ctx, DEVICE_COIN_TYPE);

    /* [1/5] LED + BOOT button — visual + tactile feedback */
    ESP_LOGI(TAG, "[1/5] Initializing LED + user input...");
    led_status_init();
    led_status_set(LED_STATE_INITIALIZING);
    user_input_init();

    /* [2/5] USB CDC (dual) — enables log output on ACM1 */
    ESP_LOGI(TAG, "[2/5] Initializing USB CDC transport (dual CDC)...");
    if (usb_transport_init() != 0) {
        fatal_halt("USB transport init failed");
    }
    usb_transport_log_redirect();

    /* Start tasks early so USB stack stays responsive during init.
     * HWP task will block on device_ready before processing commands. */
    xTaskCreate(hwp_task, "hwp_task", 8192, NULL, 5, NULL);
    xTaskCreate(usb_monitor_task, "usb_mon", 2048, NULL, 3, NULL);

    /* [3/5] NVS */
    ESP_LOGI(TAG, "[3/5] Initializing NVS (wallet storage)...");
    if (wallet_init() != WALLET_OK) {
        fatal_halt("NVS init failed");
    }

    /* [4/5] Crypto callbacks + integrity self-tests */
    ESP_LOGI(TAG, "[4/5] Registering Pallas/Sinsemilla crypto callbacks...");

    /* Register both callbacks BEFORE the integrity check, because
     * pallas_verify_sinsemilla_table walks the lookup callback and uses
     * pallas_yield to feed the watchdog during the 1024 iterations. */
    pallas_set_yield_cb(yield_cb, NULL);
    pallas_set_sinsemilla_lookup(sinsemilla_lookup, NULL);

    /* Verify the loaded S-table against the library's canonical
     * BLAKE2b-256 fingerprint. A mismatch means the table on flash has
     * been altered (supply-chain or fault attack) and we cannot trust
     * any subsequent Sinsemilla output. Halt the device — refusing to
     * operate is safer than producing signatures against a tampered
     * note-commitment scheme. (audit M-5) */
    if (!pallas_verify_sinsemilla_table()) {
        fatal_halt("Sinsemilla S-table integrity check failed");
    }
    ESP_LOGI(TAG, "  Sinsemilla S-table: integrity verified (%u bytes)",
             (unsigned)(sinsemilla_s_bin_end - sinsemilla_s_bin_start));

    /* Verify the constant-time software AES-256 against the FIPS-197 §C.3
     * known-answer vector. This validates the SOFTWARE fallback used if
     * the HW override is ever bypassed (e.g. mbedtls misconfiguration);
     * a self-test failure here means a build broken in a way that would
     * silently produce wrong diversifiers, so we halt rather than
     * proceed. (audit H-3) */
    if (!aes_ct_256_self_test()) {
        fatal_halt("AES-256 constant-time self-test failed");
    }
    ESP_LOGI(TAG, "  AES-256 CT self-test: PASS");

    /* Register the hardware-AES backend. After this call, every FF1 inner
     * AES op dispatches through the ESP32-S2 AES peripheral (via mbedTLS)
     * instead of the software fallback. The backend is constant-time by
     * construction and ~10× faster than the software scan. */
    aes_ct_256_set_override(hw_aes256_override, NULL);
    ESP_LOGI(TAG, "  AES-256 backend: HW (mbedTLS via ESP32-S2 AES peripheral)");

    /* [5/5] Wallet — create or verify, derive keys */
    ESP_LOGI(TAG, "[5/5] Checking wallet state...");
    if (!wallet_is_initialized()) {
        ESP_LOGW(TAG, "  No wallet found in NVS — FIRST BOOT");
        ESP_LOGI(TAG, "  Generating 24-word BIP39 mnemonic...");

        char mnemonic[256];
        WalletError werr = wallet_create(mnemonic, sizeof(mnemonic));
        if (werr != WALLET_OK) {
            fatal_halt("wallet_create() failed");
        }
        ESP_LOGW(TAG, "========================================");
        ESP_LOGW(TAG, " BACKUP YOUR MNEMONIC NOW!");
        ESP_LOGW(TAG, " %s", mnemonic);
        ESP_LOGW(TAG, "========================================");

        /* H-5: collect a 5-digit PIN via tap-count, then seal the
         * mnemonic under a PIN-derived key. Until the user completes
         * this step, the wallet is NOT initialized in NVS. The mnemonic
         * exists ONLY in this stack-local buffer (cleared on every
         * exit path below). */
        ESP_LOGW(TAG, "Now enter a 5-digit PIN via the BOOT button:");
        ESP_LOGW(TAG, "  - tap the button N times for digit N (10 taps = 0)");
        ESP_LOGW(TAG, "  - wait ~1.5s without tapping to confirm each digit");
        ESP_LOGW(TAG, "  - hold >3s to cancel");
        uint8_t pin[WALLET_PIN_LEN];
        PinEntryResult pin_rc = user_input_collect_pin(pin);
        if (pin_rc != PIN_ENTRY_OK) {
            memzero(mnemonic, sizeof(mnemonic));
            memzero(pin, sizeof(pin));
            fatal_halt("PIN entry cancelled or timed out at provisioning");
        }
        werr = wallet_pin_provision(mnemonic, pin, "" /* no passphrase v1 */);
        memzero(pin, sizeof(pin));
        memzero(mnemonic, sizeof(mnemonic));
        if (werr != WALLET_OK) {
            fatal_halt("wallet_pin_provision() failed");
        }
        ESP_LOGI(TAG, "  PIN provisioned, mnemonic sealed in NVS");

        /* Display the device identity pubkey fingerprint at first boot.
         * This is the trust window in which a user — or the standalone
         * pairing CLI — captures the canonical pubkey for future
         * attestation. After this boot, the same pubkey is returned
         * via HWP IDENTITY_REQ but a hostile companion could lie about
         * the displayed value; the fingerprint shown here on the trusted
         * first-boot host is the authoritative reference. */
        {
            uint8_t device_pk[32];
            if (wallet_get_or_create_device_identity(device_pk) == WALLET_OK) {
                char hex[65];
                for (int i = 0; i < 32; i++) {
                    static const char H[] = "0123456789abcdef";
                    hex[2*i]   = H[(device_pk[i] >> 4) & 0xF];
                    hex[2*i+1] = H[device_pk[i] & 0xF];
                }
                hex[64] = 0;
                ESP_LOGW(TAG, "========================================");
                ESP_LOGW(TAG, " DEVICE IDENTITY PUBKEY (record this!):");
                ESP_LOGW(TAG, " %s", hex);
                ESP_LOGW(TAG, " Pin this in your pairing tool. Future");
                ESP_LOGW(TAG, " attestations must return the same value.");
                ESP_LOGW(TAG, "========================================");
            }
        }

        ESP_LOGI(TAG, "  Pre-deriving FVK (warms up Pallas curve, may take seconds)...");
        uint8_t fvk[96];
        werr = wallet_get_fvk(fvk, ZCASH_DEFAULT_COIN_TYPE);
        memzero(fvk, sizeof(fvk));
        if (werr != WALLET_OK) {
            fatal_halt("FVK pre-derivation failed");
        }
        ESP_LOGI(TAG, "  FVK pre-derivation complete — crypto ready");
    } else {
        ESP_LOGI(TAG, "  Wallet found in NVS — PIN unlock required");

        /* H-5: every subsequent boot prompts for PIN. The user has up to
         * WALLET_PIN_LOCKOUT_MAX consecutive wrong-PIN attempts before
         * the device wipes itself. Each wrong attempt re-prompts. */
        for (;;) {
            WalletPinStatus st = wallet_pin_status();
            if (st == WALLET_PIN_LOCKED_OUT) {
                ESP_LOGE(TAG, "Lockout threshold reached — wiping wallet!");
                wallet_wipe();
                fatal_halt("Lockout: wallet wiped, halt for re-provisioning");
            }
            ESP_LOGW(TAG, "Enter your 5-digit PIN via BOOT button:");
            uint8_t pin[WALLET_PIN_LEN];
            PinEntryResult pin_rc = user_input_collect_pin(pin);
            if (pin_rc != PIN_ENTRY_OK) {
                memzero(pin, sizeof(pin));
                ESP_LOGW(TAG, "PIN entry cancelled — try again");
                continue;
            }
            WalletError werr = wallet_pin_unlock(pin);
            memzero(pin, sizeof(pin));
            if (werr == WALLET_OK) {
                ESP_LOGI(TAG, "  Wallet unlocked");
                break;
            }
            if (werr == WALLET_ERR_LOCKED_OUT) {
                ESP_LOGE(TAG, "Lockout threshold reached — wiping wallet!");
                wallet_wipe();
                fatal_halt("Lockout: wallet wiped, halt for re-provisioning");
            }
            /* WALLET_ERR_PIN_WRONG: loop and try again. */
        }
    }

    /* Get UA (cached in NVS by wallet.c, instant on subsequent boots) */
    if (wallet_get_address(cached_ua, sizeof(cached_ua), ZCASH_DEFAULT_COIN_TYPE) == WALLET_OK) {
        ESP_LOGI(TAG, "UA: %s", cached_ua);
    } else {
        ESP_LOGW(TAG, "UA derivation failed");
        cached_ua[0] = '\0';
    }

    /* --- Device fully initialized — allow HWP traffic --- */
    device_ready = true;

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, " READY — HWP protocol active");
    ESP_LOGI(TAG, " ACM0: HWP binary frames");
    ESP_LOGI(TAG, " ACM1: debug logs (this output)");
    ESP_LOGI(TAG, " Waiting for companion app...");
    ESP_LOGI(TAG, "========================================");

    led_status_set(LED_STATE_READY);
}
