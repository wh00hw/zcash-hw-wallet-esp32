/**
 * LED status indicator — RGB LED (R=GPIO6, G=GPIO5, B=GPIO4, active-low).
 */
#include "led_status.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>

static const char *TAG = "led";

#define GPIO_RED    6
#define GPIO_GREEN  5
#define GPIO_BLUE   4

#define DUTY_MAX    255
#define TICK_MS     20
#define BREATH_SLOW 3000
#define BREATH_FAST 1000
#define BLINK_MS    150
#define FLASH_MS    600

static volatile LedState current_state = LED_STATE_OFF;
static LedState return_state = LED_STATE_READY;

/* Active-low: duty 255 = OFF, duty 0 = full ON */
static void led_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, DUTY_MAX - r);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_1, DUTY_MAX - g);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_2, DUTY_MAX - b);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_1);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_2);
}

static float breath(uint32_t tick, uint32_t period)
{
    float phase = (float)(tick % period) / (float)period;
    float v = (sinf(phase * 6.2832f - 1.5708f) + 1.0f) / 2.0f;
    return v * v;
}

static void led_task(void *arg)
{
    uint32_t tick = 0;
    LedState flash_state = LED_STATE_OFF;
    uint32_t flash_start = 0;

    for (;;) {
        LedState st = current_state;

        /* Transient states: SUCCESS / ERROR — flash then return */
        if (st == LED_STATE_SUCCESS || st == LED_STATE_ERROR) {
            if (flash_state != st) {
                flash_state = st;
                flash_start = tick;
            }
            uint32_t elapsed = tick - flash_start;
            if (elapsed < FLASH_MS) {
                bool on = (elapsed / 100) % 2 == 0;
                if (st == LED_STATE_SUCCESS)
                    led_rgb(0, on ? 60 : 0, 0);
                else
                    led_rgb(on ? 80 : 0, 0, 0);
            } else {
                flash_state = LED_STATE_OFF;
                current_state = return_state;
            }
            vTaskDelay(pdMS_TO_TICKS(TICK_MS));
            tick += TICK_MS;
            continue;
        }

        /* Remember non-flash state for return */
        return_state = st;
        flash_state = LED_STATE_OFF;

        switch (st) {
        case LED_STATE_OFF:
            led_rgb(0, 0, 0);
            break;

        case LED_STATE_INITIALIZING: {
            /* Blue blinking */
            bool on = (tick / BLINK_MS) % 2 == 0;
            led_rgb(0, 0, on ? 50 : 0);
            break;
        }

        case LED_STATE_READY:
        case LED_STATE_CONNECTED:
            /* Green solid */
            led_rgb(0, 40, 0);
            break;

        case LED_STATE_BUSY_KEY:
        case LED_STATE_BUSY_SIGN: {
            /* Blue blinking */
            bool on = (tick / BLINK_MS) % 2 == 0;
            led_rgb(0, 0, on ? 50 : 0);
            break;
        }

        case LED_STATE_TX_PROGRESS: {
            /* Cyan fast breathing */
            float v = breath(tick, BREATH_FAST);
            led_rgb(0, (uint8_t)(v * 35), (uint8_t)(v * 50));
            break;
        }

        default:
            led_rgb(0, 0, 0);
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(TICK_MS));
        tick += TICK_MS;
    }
}

int led_status_init(void)
{
    ledc_timer_config_t timer_cfg = {
        .speed_mode      = LEDC_LOW_SPEED_MODE,
        .duty_resolution = LEDC_TIMER_8_BIT,
        .timer_num       = LEDC_TIMER_0,
        .freq_hz         = 5000,
        .clk_cfg         = LEDC_AUTO_CLK,
    };
    esp_err_t err = ledc_timer_config(&timer_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "LEDC timer failed: %s", esp_err_to_name(err));
        return -1;
    }

    const int gpios[] = { GPIO_RED, GPIO_GREEN, GPIO_BLUE };
    const int chans[] = { LEDC_CHANNEL_0, LEDC_CHANNEL_1, LEDC_CHANNEL_2 };

    for (int i = 0; i < 3; i++) {
        ledc_channel_config_t ch = {
            .gpio_num   = gpios[i],
            .speed_mode = LEDC_LOW_SPEED_MODE,
            .channel    = chans[i],
            .timer_sel  = LEDC_TIMER_0,
            .duty       = DUTY_MAX, /* start OFF (active-low) */
            .hpoint     = 0,
        };
        err = ledc_channel_config(&ch);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "LEDC ch %d failed: %s", i, esp_err_to_name(err));
            return -1;
        }
    }

    xTaskCreate(led_task, "led", 2048, NULL, 2, NULL);
    ESP_LOGI(TAG, "RGB LED init OK (R=%d G=%d B=%d)", GPIO_RED, GPIO_GREEN, GPIO_BLUE);
    return 0;
}

void led_status_set(LedState state)
{
    current_state = state;
}
