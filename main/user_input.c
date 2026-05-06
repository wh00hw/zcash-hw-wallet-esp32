/**
 * User-input implementation — see user_input.h
 */
#include "user_input.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

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
