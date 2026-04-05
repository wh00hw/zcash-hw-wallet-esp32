/**
 * USB CDC transport layer for HWP protocol on ESP32-S2.
 *
 * Two CDC interfaces:
 *   CDC 0 (ACM0) — binary HWP frames only
 *   CDC 1 (ACM1) — debug/diagnostic log output (ESP_LOG*)
 */
#include "usb_transport.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

static const char *TAG = "usb";

static RingbufHandle_t rx_ringbuf;
#define RX_RINGBUF_SIZE 1024

static volatile bool host_connected = false;

/* --- CDC 0: HWP protocol --- */

static void cdc_rx_callback(int itf, cdcacm_event_t *event)
{
    uint8_t buf[CONFIG_TINYUSB_CDC_RX_BUFSIZE];
    size_t rx_size = 0;

    esp_err_t ret = tinyusb_cdcacm_read(itf, buf, sizeof(buf), &rx_size);
    if (ret == ESP_OK && rx_size > 0) {
        ESP_LOGD(TAG, "RX %u bytes from USB", (unsigned)rx_size);
        xRingbufferSend(rx_ringbuf, buf, rx_size, 0);
    }
}

static void cdc_line_state_callback(int itf, cdcacm_event_t *event)
{
    int dtr = event->line_state_changed_data.dtr;
    int rts = event->line_state_changed_data.rts;
    host_connected = dtr;
    ESP_LOGI(TAG, "USB line state changed: DTR=%d RTS=%d → host %s",
             dtr, rts, dtr ? "CONNECTED" : "DISCONNECTED");
}

/* --- CDC 1: Log output --- */

static vprintf_like_t s_original_vprintf;

static int log_to_uart_and_cdc1(const char *fmt, va_list args)
{
    /* Always send to original UART console */
    va_list args_copy;
    va_copy(args_copy, args);
    if (s_original_vprintf) {
        s_original_vprintf(fmt, args_copy);
    }
    va_end(args_copy);

    /* Mirror to CDC 1 (best-effort) */
    char buf[256];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    if (len <= 0) return len;
    if ((size_t)len >= sizeof(buf)) len = sizeof(buf) - 1;

    tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_1, (const uint8_t *)buf, len);
    tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_1, 0);

    return len;
}

int usb_transport_init(void)
{
    ESP_LOGI(TAG, "Initializing USB CDC transport (dual CDC)...");

    rx_ringbuf = xRingbufferCreate(RX_RINGBUF_SIZE, RINGBUF_TYPE_BYTEBUF);
    if (!rx_ringbuf) {
        ESP_LOGE(TAG, "FATAL: Failed to create RX ring buffer (%d bytes)", RX_RINGBUF_SIZE);
        return -1;
    }

    const tinyusb_config_t tusb_cfg = {
        .string_descriptor = (const char *[]){
            [0] = "",
            [1] = "Zcash",
            [2] = "Orchard HW Wallet",
            [3] = "000001",
            [4] = "HWP Protocol",
            [5] = "Debug Log",
        },
        .string_descriptor_count = 6,
        .external_phy = false,
    };

    esp_err_t err = tinyusb_driver_install(&tusb_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "FATAL: TinyUSB driver install failed: %s", esp_err_to_name(err));
        return -1;
    }
    ESP_LOGI(TAG, "TinyUSB driver installed");

    /* CDC 0: HWP binary protocol */
    tinyusb_config_cdcacm_t acm0_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 256,
        .callback_rx = &cdc_rx_callback,
        .callback_line_state_changed = &cdc_line_state_callback,
    };

    err = tusb_cdc_acm_init(&acm0_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "FATAL: CDC ACM 0 (HWP) init failed: %s", esp_err_to_name(err));
        return -1;
    }
    ESP_LOGI(TAG, "CDC 0 (ACM0) ready — HWP binary protocol");

    /* CDC 1: Debug log output */
    tinyusb_config_cdcacm_t acm1_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_1,
        .rx_unread_buf_sz = 64,
        .callback_rx = NULL,
        .callback_line_state_changed = NULL,
    };

    err = tusb_cdc_acm_init(&acm1_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "FATAL: CDC ACM 1 (log) init failed: %s", esp_err_to_name(err));
        return -1;
    }
    ESP_LOGI(TAG, "CDC 1 (ACM1) ready — debug log output");

    return 0;
}

void usb_transport_log_redirect(void)
{
    s_original_vprintf = esp_log_set_vprintf(log_to_uart_and_cdc1);
}

bool usb_transport_host_connected(void)
{
    return host_connected;
}

int usb_transport_send(const uint8_t *data, size_t len)
{
    if (!host_connected) {
        ESP_LOGW(TAG, "TX dropped (%u bytes): host not connected (DTR low)", (unsigned)len);
        return -1;
    }

    ESP_LOGD(TAG, "TX %u bytes", (unsigned)len);

    size_t sent = 0;
    while (sent < len) {
        size_t chunk = len - sent;
        if (chunk > CONFIG_TINYUSB_CDC_RX_BUFSIZE) {
            chunk = CONFIG_TINYUSB_CDC_RX_BUFSIZE;
        }
        size_t queued = tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,
                                                    data + sent, chunk);
        if (queued == 0) {
            ESP_LOGE(TAG, "TX write_queue returned 0 at offset %u", (unsigned)sent);
            return -1;
        }
        esp_err_t err = tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(100));
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "TX flush failed at offset %u: %s",
                     (unsigned)sent, esp_err_to_name(err));
            return -1;
        }
        sent += queued;
    }
    return (int)sent;
}

HwpFeedResult usb_transport_recv_frame(HwpParser *parser, uint32_t timeout_ms)
{
    TickType_t ticks = (timeout_ms == 0)
        ? portMAX_DELAY
        : pdMS_TO_TICKS(timeout_ms);

    hwp_parser_init(parser);

    for (;;) {
        size_t item_size = 0;
        uint8_t *item = xRingbufferReceiveUpTo(rx_ringbuf, &item_size,
                                                ticks, HWP_MAX_FRAME);
        if (!item || item_size == 0) {
            if (item) vRingbufferReturnItem(rx_ringbuf, item);
            return HWP_FEED_INCOMPLETE;
        }

        for (size_t i = 0; i < item_size; i++) {
            HwpFeedResult res = hwp_parser_feed(parser, item[i]);
            if (res != HWP_FEED_INCOMPLETE) {
                vRingbufferReturnItem(rx_ringbuf, item);
                return res;
            }
        }
        vRingbufferReturnItem(rx_ringbuf, item);
    }
}
