/**
 * Zcash Orchard Hardware Wallet — ESP32-S2 Firmware
 *
 * Implements HWP v2 protocol over USB CDC.
 * Debug logging goes to USB CDC 1 (ACM1) via ESP_LOG*.
 */
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "freertos/ringbuf.h"
#include "usb_transport.h"
#include "pallas.h"
#include "hwp.h"
#include "wallet.h"
#include "orchard.h"
#include "redpallas.h"
#include "blake2b.h"
#include "zip244.h"
#include "orchard_signer.h"
#include "bip39.h"
#include "memzero.h"
#include "led_status.h"

static const char *TAG = "hwp";

static uint8_t tx_buf[HWP_MAX_FRAME];
static HwpParser rx_parser;

/* Device state — HWP commands are rejected until READY */
static volatile bool device_ready = false;

/* Cached unified address (derived once at boot) */
static char cached_ua[256];

/* Signing context — enforces ZIP-244 verification before signing (in libzcash) */
static OrchardSignerCtx signer_ctx;

static void session_reset(void)
{
    orchard_signer_reset(&signer_ctx);
}

/* Embedded Sinsemilla S-table (1024 points, 64 bytes each = 64KB) */
extern const uint8_t sinsemilla_s_bin_start[] asm("_binary_sinsemilla_s_bin_start");
extern const uint8_t sinsemilla_s_bin_end[]   asm("_binary_sinsemilla_s_bin_end");

static bool sinsemilla_lookup(uint32_t index, uint8_t buf_out[64], void *ctx)
{
    if (index >= 1024) return false;
    memcpy(buf_out, sinsemilla_s_bin_start + index * 64, 64);
    return true;
}

/* Yield callback — feeds watchdog during long Sinsemilla computations */
static void yield_cb(void *ctx)
{
    esp_task_wdt_reset();
    vTaskDelay(1); /* let other tasks run */
}

static void send_error(uint8_t seq, HwpErrorCode code, const char *msg)
{
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

static void handle_fvk_req(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    /* Parse coin_type from payload (4 bytes LE), or use default for backward compat */
    uint32_t coin_type = ZCASH_DEFAULT_COIN_TYPE;
    if (payload_len >= HWP_FVK_REQ_SIZE) {
        coin_type = (uint32_t)payload[0]
                  | ((uint32_t)payload[1] << 8)
                  | ((uint32_t)payload[2] << 16)
                  | ((uint32_t)payload[3] << 24);
    }

    ESP_LOGI(TAG, "FVK_REQ received (seq=%d, coin_type=%u), deriving full viewing key...",
             seq, (unsigned)coin_type);
    led_status_set(LED_STATE_BUSY_KEY);

    /* Store coin_type in signer context for session consistency */
    signer_ctx.coin_type = coin_type;

    uint8_t fvk[96];
    WalletError err = wallet_get_fvk(fvk, coin_type);
    if (err != WALLET_OK) {
        ESP_LOGE(TAG, "FVK derivation FAILED (err=%d)", err);
        send_error(seq, HWP_ERR_SIGN_FAILED, "key derivation failed");
        return;
    }
    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_FVK_RSP, fvk, 96);
    usb_transport_send(tx_buf, len);
    led_status_set(LED_STATE_SUCCESS);
    ESP_LOGI(TAG, "FVK_RSP sent (96 bytes, seq=%d, coin_type=%u)", seq, (unsigned)coin_type);
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
        serr = orchard_signer_feed_meta(&signer_ctx, out.output_data,
                                         out.output_data_len, out.total_outputs);
        if (serr == SIGNER_ERR_NETWORK_MISMATCH) {
            ESP_LOGE(TAG, "Network mismatch: FvkReq coin_type=%u vs TxMeta coin_type=%u",
                     (unsigned)signer_ctx.coin_type, (unsigned)signer_ctx.tx_meta.coin_type);
            send_error(seq, HWP_ERR_NETWORK_MISMATCH, "coin_type mismatch between FvkReq and TxMeta");
            session_reset();
            return;
        }
        if (serr != SIGNER_OK) {
            send_error(seq, HWP_ERR_BAD_FRAME, "invalid tx metadata");
            session_reset();
            return;
        }
        led_status_set(LED_STATE_TX_PROGRESS);
        ESP_LOGI(TAG, "TX metadata received, expecting %d actions", out.total_outputs);

        size_t len = hwp_encode(tx_buf, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
        usb_transport_send(tx_buf, len);
        return;
    }

    /* --- Sentinel (output_index == total_outputs): expected sighash --- */
    if (out.output_index == out.total_outputs) {
        if (out.output_data_len != 32) {
            send_error(seq, HWP_ERR_BAD_FRAME, "sentinel must be 32 bytes");
            session_reset();
            return;
        }

        /* Log all intermediate digests for debug */
        {
            uint8_t hdr[32], orch[32], dbg_sighash[32];
            Zip244ActionsState dbg_actions = signer_ctx.actions_state;

            zip244_header_digest(&signer_ctx.tx_meta, hdr);
            ESP_LOGI(TAG, "header_digest:");
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, hdr, 32, ESP_LOG_INFO);
            ESP_LOGI(TAG, "transparent_sig_digest (from companion):");
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, signer_ctx.tx_meta.transparent_sig_digest, 32, ESP_LOG_INFO);
            ESP_LOGI(TAG, "sapling_digest (from companion):");
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, signer_ctx.tx_meta.sapling_digest, 32, ESP_LOG_INFO);

            zip244_orchard_digest(&dbg_actions, &signer_ctx.tx_meta, orch);
            ESP_LOGI(TAG, "orchard_digest (computed by device):");
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, orch, 32, ESP_LOG_INFO);

            /* Recompute full sighash */
            Zip244ActionsState dbg_actions2 = signer_ctx.actions_state;
            zip244_shielded_sighash(&signer_ctx.tx_meta, &dbg_actions2, dbg_sighash);
            ESP_LOGI(TAG, "Device sighash:");
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, dbg_sighash, 32, ESP_LOG_INFO);
            ESP_LOGI(TAG, "Companion sighash:");
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, out.output_data, 32, ESP_LOG_INFO);
        }

        serr = orchard_signer_verify(&signer_ctx, out.output_data);
        if (serr == SIGNER_ERR_SIGHASH_MISMATCH) {
            ESP_LOGE(TAG, "ZIP-244 sighash MISMATCH");
            send_error(seq, HWP_ERR_SIGHASH_MISMATCH, "ZIP-244 sighash mismatch");
            return;
        }
        if (serr != SIGNER_OK) {
            ESP_LOGE(TAG, "Sighash verify failed (err=%d)", serr);
            send_error(seq, HWP_ERR_INVALID_STATE, "sighash verify failed");
            session_reset();
            return;
        }

        ESP_LOGI(TAG, "ZIP-244 sighash verified — signing authorized");
        size_t len = hwp_encode(tx_buf, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
        usb_transport_send(tx_buf, len);
        return;
    }

    /* --- Normal action data (output_index 0..N-1) --- */
    serr = orchard_signer_feed_action(&signer_ctx, out.output_data, out.output_data_len);
    if (serr != SIGNER_OK) {
        const char *msg = (serr == SIGNER_ERR_BAD_STATE) ? "unexpected action" : "invalid action data";
        send_error(seq, (serr == SIGNER_ERR_BAD_STATE) ? HWP_ERR_INVALID_STATE : HWP_ERR_BAD_FRAME, msg);
        session_reset();
        return;
    }

    ESP_LOGI(TAG, "Action %d/%d hashed (%d bytes)",
             out.output_index + 1, out.total_outputs, out.output_data_len);

    size_t len = hwp_encode(tx_buf, seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
    usb_transport_send(tx_buf, len);
}

static void handle_sign_req(uint8_t seq, const uint8_t *payload, uint16_t payload_len)
{
    ESP_LOGI(TAG, "SIGN_REQ received (seq=%d, %d bytes)", seq, payload_len);

    HwpSignReq req;
    if (!hwp_parse_sign_req(payload, payload_len, &req)) {
        ESP_LOGE(TAG, "SIGN_REQ parse failed (payload_len=%d, need >= %d)", payload_len, HWP_SIGN_REQ_FIXED);
        send_error(seq, HWP_ERR_BAD_FRAME, "invalid sign_req payload");
        return;
    }

    ESP_LOGI(TAG, "SIGN_REQ: amount=%llu fee=%llu recipient='%s'",
             (unsigned long long)req.amount, (unsigned long long)req.fee, req.recipient);

    /* Check ZIP-244 verification via libzcash signer context.
     * orchard_signer_check() enforces the invariant: no signing without
     * prior sighash verification. This is a library-level guarantee. */
    OrchardSignerError chk = orchard_signer_check(&signer_ctx, req.sighash);
    if (chk == SIGNER_ERR_NOT_VERIFIED) {
        ESP_LOGE(TAG, "SIGN_REQ rejected: ZIP-244 sighash not verified (send TX_OUTPUT first)");
        send_error(seq, HWP_ERR_INVALID_STATE, "sighash not verified");
        return;
    }
    if (chk == SIGNER_ERR_WRONG_SIGHASH) {
        ESP_LOGE(TAG, "SIGN_REQ sighash does not match verified sighash");
        send_error(seq, HWP_ERR_SIGHASH_MISMATCH, "SignReq sighash mismatch");
        session_reset();
        return;
    }
    ESP_LOGI(TAG, "ZIP-244 sighash verified — proceeding with signature");

    led_status_set(LED_STATE_BUSY_SIGN);
    ESP_LOGI(TAG, "Signing transaction...");

    uint8_t sig[64], rk[32];
    uint32_t coin_type = signer_ctx.coin_type ? signer_ctx.coin_type : ZCASH_DEFAULT_COIN_TYPE;
    WalletError err = wallet_sign_via_ctx(&signer_ctx, req.sighash, req.alpha, sig, rk, coin_type);
    if (err != WALLET_OK) {
        ESP_LOGE(TAG, "Signing FAILED (err=%d)", err);
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
                ESP_LOGI(TAG, " Zcash Orchard Hardware Wallet");
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
    ESP_LOGI(TAG, " Zcash Orchard Hardware Wallet");
    ESP_LOGI(TAG, " HWP v%d | Target: ESP32-S2", HWP_VERSION);
    ESP_LOGI(TAG, "========================================");

    /* Init signing context */
    orchard_signer_init(&signer_ctx);

    /* [1/5] LED — immediate visual feedback */
    ESP_LOGI(TAG, "[1/5] Initializing LED...");
    led_status_init();
    led_status_set(LED_STATE_INITIALIZING);

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

    /* [4/5] Crypto callbacks */
    ESP_LOGI(TAG, "[4/5] Registering Pallas/Sinsemilla crypto callbacks...");
    pallas_set_yield_cb(yield_cb, NULL);
    pallas_set_sinsemilla_lookup(sinsemilla_lookup, NULL);
    ESP_LOGI(TAG, "  Sinsemilla S-table: %u bytes",
             (unsigned)(sinsemilla_s_bin_end - sinsemilla_s_bin_start));

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
        memzero(mnemonic, sizeof(mnemonic));
        ESP_LOGI(TAG, "  Mnemonic generated and stored in NVS");

        ESP_LOGI(TAG, "  Pre-deriving FVK (warms up Pallas curve, may take seconds)...");
        uint8_t fvk[96];
        werr = wallet_get_fvk(fvk, ZCASH_DEFAULT_COIN_TYPE);
        memzero(fvk, sizeof(fvk));
        if (werr != WALLET_OK) {
            fatal_halt("FVK pre-derivation failed");
        }
        ESP_LOGI(TAG, "  FVK pre-derivation complete — crypto ready");
    } else {
        ESP_LOGI(TAG, "  Wallet found in NVS — skipping creation");
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
