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

/* --- Signing session state (TX_OUTPUT incremental hashing) --- */
typedef enum {
    SESSION_IDLE,
    SESSION_RECEIVING_OUTPUTS,
} SessionState;

static SessionState session_state = SESSION_IDLE;
static BLAKE2B_CTX session_hash_ctx;
static uint16_t session_outputs_received;
static uint16_t session_outputs_total;

static void session_reset(void)
{
    session_state = SESSION_IDLE;
    session_outputs_received = 0;
    session_outputs_total = 0;
    memzero(&session_hash_ctx, sizeof(session_hash_ctx));
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

static void handle_fvk_req(uint8_t seq)
{
    ESP_LOGI(TAG, "FVK_REQ received (seq=%d), deriving full viewing key...", seq);
    led_status_set(LED_STATE_BUSY_KEY);

    uint8_t fvk[96];
    WalletError err = wallet_get_fvk(fvk);
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

    /* First output starts a new session */
    if (out.output_index == 0) {
        session_reset();
        session_state = SESSION_RECEIVING_OUTPUTS;
        session_outputs_total = out.total_outputs;
        blake2b_Init(&session_hash_ctx, 32);
        led_status_set(LED_STATE_TX_PROGRESS);
        ESP_LOGI(TAG, "Signing session started, expecting %d outputs", out.total_outputs);
    }

    if (session_state != SESSION_RECEIVING_OUTPUTS) {
        send_error(seq, HWP_ERR_INVALID_STATE, "no active signing session");
        return;
    }

    if (out.output_index != session_outputs_received) {
        send_error(seq, HWP_ERR_INVALID_STATE, "unexpected output index");
        session_reset();
        return;
    }

    if (out.total_outputs != session_outputs_total) {
        send_error(seq, HWP_ERR_INVALID_STATE, "total_outputs mismatch");
        session_reset();
        return;
    }

    /* Hash this output's data incrementally */
    blake2b_Update(&session_hash_ctx, out.output_data, out.output_data_len);
    session_outputs_received++;

    ESP_LOGI(TAG, "TX_OUTPUT %d/%d hashed (%d bytes)",
             out.output_index + 1, out.total_outputs, out.output_data_len);

    /* Send ACK */
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

    /* If we received outputs, verify sighash matches our incremental hash */
    if (session_state == SESSION_RECEIVING_OUTPUTS) {
        if (session_outputs_received != session_outputs_total) {
            send_error(seq, HWP_ERR_INVALID_STATE, "not all outputs received");
            session_reset();
            return;
        }

        uint8_t computed_hash[32];
        blake2b_Final(&session_hash_ctx, computed_hash, 32);
        session_reset();

        if (memcmp(computed_hash, req.sighash, 32) != 0) {
            memzero(computed_hash, sizeof(computed_hash));
            send_error(seq, HWP_ERR_SIGHASH_MISMATCH, "sighash mismatch");
            return;
        }
        memzero(computed_hash, sizeof(computed_hash));
        ESP_LOGI(TAG, "Sighash verified against outputs");
    }

    led_status_set(LED_STATE_BUSY_SIGN);
    ESP_LOGI(TAG, "Signing transaction...");

    uint8_t sig[64], rk[32];
    WalletError err = wallet_sign(req.sighash, req.alpha, sig, rk);
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
    if (session_state != SESSION_IDLE) {
        ESP_LOGW(TAG, "Session aborted (had %d/%d outputs)",
                 session_outputs_received, session_outputs_total);
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

    bool handshake_sent = false;

    for (;;) {
        /* When host connects, send handshake PING (once per connection) */
        if (usb_transport_host_connected() && !handshake_sent) {
            vTaskDelay(pdMS_TO_TICKS(500));
            send_ping();
            handshake_sent = true;
        }
        if (!usb_transport_host_connected()) {
            handshake_sent = false;
        }

        HwpFeedResult res = usb_transport_recv_frame(&rx_parser, 500);
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
            handle_fvk_req(f->seq);
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
                /* Handshake PING is sent by hwp_task when it sees host_connected */
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
        werr = wallet_get_fvk(fvk);
        memzero(fvk, sizeof(fvk));
        if (werr != WALLET_OK) {
            fatal_halt("FVK pre-derivation failed");
        }
        ESP_LOGI(TAG, "  FVK pre-derivation complete — crypto ready");
    } else {
        ESP_LOGI(TAG, "  Wallet found in NVS — skipping creation");
    }

    /* Get UA (cached in NVS by wallet.c, instant on subsequent boots) */
    if (wallet_get_address(cached_ua, sizeof(cached_ua)) == WALLET_OK) {
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
