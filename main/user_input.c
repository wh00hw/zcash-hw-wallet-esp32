/**
 * User-input implementation — see user_input.h
 */
#include "user_input.h"
#include "led_status.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "memzero.h"

static const char *TAG = "input";

#define BUTTON_GPIO       0       /* BOOT button on ESP32-S2 dev boards */
#define POLL_MS           20
#define DEBOUNCE_MS       40
#define LONG_PRESS_MS     2000

static bool s_initialized = false;

int user_input_init(void)
{
    if (s_initialized) return 0;

    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << BUTTON_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "gpio_config(BOOT) failed: %s", esp_err_to_name(err));
        return -1;
    }
    s_initialized = true;
    ESP_LOGI(TAG, "BOOT button input ready on GPIO%d (active-low)", BUTTON_GPIO);
    return 0;
}

/* GPIO0 is active-low: pressed => 0, idle => 1 */
static bool button_pressed(void) {
    return gpio_get_level(BUTTON_GPIO) == 0;
}

UserInputResult user_input_wait(uint32_t timeout_ms)
{
    if (!s_initialized) {
        if (user_input_init() != 0) return USER_INPUT_NONE;
    }

    /* Wait for press edge with timeout. Drain any release-state debounce
     * before sampling, so a stale press from a previous call doesn't
     * register here. */
    uint32_t elapsed = 0;
    while (button_pressed()) {
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        elapsed += POLL_MS;
        if (elapsed >= timeout_ms) return USER_INPUT_NONE;
    }

    while (!button_pressed()) {
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        elapsed += POLL_MS;
        if (elapsed >= timeout_ms) return USER_INPUT_NONE;
    }

    /* Debounce: require sustained press for DEBOUNCE_MS. */
    vTaskDelay(pdMS_TO_TICKS(DEBOUNCE_MS));
    if (!button_pressed()) {
        return USER_INPUT_NONE;
    }

    /* Measure how long the user holds the button to distinguish short
     * (confirm) from long (cancel). */
    uint32_t held = DEBOUNCE_MS;
    while (button_pressed()) {
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        held += POLL_MS;
        if (held >= LONG_PRESS_MS) {
            /* Wait for release to swallow the rest of the long press, so
             * the button is left in the released state for the next call. */
            while (button_pressed()) {
                vTaskDelay(pdMS_TO_TICKS(POLL_MS));
            }
            return USER_INPUT_CANCEL;
        }
    }
    return USER_INPUT_CONFIRM;
}

/* ====================================================================== */
/*  PIN entry via tap-count encoding (audit H-5)                          */
/* ====================================================================== */

#define PIN_TAP_DEBOUNCE_MS    30
#define PIN_DIGIT_PAUSE_MS   1500   /* idle time that confirms a digit */
#define PIN_CANCEL_HOLD_MS   3000
#define PIN_DIGIT_TIMEOUT_MS 60000  /* fresh-prompt timeout */
#define PIN_TAPS_MAX            10  /* 10 taps = digit 0 */

/* Wait for a button press OR a `pause_ms` idle window, whichever comes
 * first. Returns:
 *    1  press detected
 *    0  pause elapsed without any press
 *   -1  press detected AND was held >= cancel_hold_ms (cancel signal).
 *       The function consumes the rest of the long press so the button
 *       is in released state on return.
 */
static int wait_press_or_pause(uint32_t pause_ms, uint32_t cancel_hold_ms) {
    uint32_t elapsed = 0;
    while (!button_pressed()) {
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        elapsed += POLL_MS;
        if (elapsed >= pause_ms) return 0;
    }
    /* Press edge — debounce. */
    vTaskDelay(pdMS_TO_TICKS(PIN_TAP_DEBOUNCE_MS));
    if (!button_pressed()) return 0; /* spurious */

    /* Measure hold duration to distinguish tap from cancel. */
    uint32_t held = PIN_TAP_DEBOUNCE_MS;
    while (button_pressed()) {
        vTaskDelay(pdMS_TO_TICKS(POLL_MS));
        held += POLL_MS;
        if (held >= cancel_hold_ms) {
            /* Consume the rest of the long press. */
            while (button_pressed()) {
                vTaskDelay(pdMS_TO_TICKS(POLL_MS));
            }
            return -1;
        }
    }
    return 1;  /* short tap */
}

PinEntryResult user_input_collect_pin(uint8_t pin_out[WALLET_PIN_LEN]) {
    if (!s_initialized) {
        if (user_input_init() != 0) return PIN_ENTRY_TIMEOUT;
    }
    memzero(pin_out, WALLET_PIN_LEN);

    for (int d = 0; d < WALLET_PIN_LEN; d++) {
        led_status_set(LED_STATE_AWAITING_CONFIRM);

        int taps = 0;
        for (;;) {
            uint32_t pause = (taps == 0) ? PIN_DIGIT_TIMEOUT_MS : PIN_DIGIT_PAUSE_MS;
            int rc = wait_press_or_pause(pause, PIN_CANCEL_HOLD_MS);
            if (rc == -1) {
                memzero(pin_out, WALLET_PIN_LEN);
                return PIN_ENTRY_CANCELLED;
            }
            if (rc == 0) {
                if (taps == 0) {
                    memzero(pin_out, WALLET_PIN_LEN);
                    return PIN_ENTRY_TIMEOUT;
                }
                /* Pause elapsed with at least one tap → digit confirmed. */
                break;
            }
            /* rc == 1: short tap. */
            if (taps < PIN_TAPS_MAX) taps++;
        }

        /* Map tap count to digit: 1..9 taps => digit equal to count;
         * 10 taps => digit 0 (i.e. count modulo 10). */
        pin_out[d] = (uint8_t)(taps % 10);

        /* Visual echo: blink the entered count via the BUSY pulse so the
         * user can verify they entered the digit they intended. The
         * firmware can map LED_STATE_BUSY_KEY to a specific colour. */
        led_status_set(LED_STATE_BUSY_KEY);
        for (int b = 0; b < taps; b++) {
            vTaskDelay(pdMS_TO_TICKS(150));
            led_status_set(LED_STATE_READY);
            vTaskDelay(pdMS_TO_TICKS(150));
            led_status_set(LED_STATE_BUSY_KEY);
        }
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    return PIN_ENTRY_OK;
}
