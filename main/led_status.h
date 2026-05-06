/**
 * LED status indicator — RGB LED (R=GPIO6, G=GPIO5, B=GPIO4).
 *
 * States:
 *   INITIALIZING    — blue blinking      (wallet creation + key derivation)
 *   READY           — green solid        (protocol active, waiting for companion)
 *   CONNECTED       — green solid        (companion connected)
 *   BUSY_KEY        — blue blinking      (key derivation during protocol)
 *   BUSY_SIGN       — blue blinking      (signing in progress)
 *   TX_PROGRESS     — cyan fast breath   (receiving TX outputs)
 *   AWAITING_CONFIRM — magenta blinking  (waiting for BOOT-button confirm
 *                                          on per-output recipient/value)
 *   SUCCESS         — green flash        (operation completed → prev)
 *   ERROR           — red flash          (error → prev)
 */
#pragma once

typedef enum {
    LED_STATE_OFF,
    LED_STATE_INITIALIZING,    /* blue blinking — wallet init / first derivation */
    LED_STATE_READY,           /* green solid — protocol active, no companion */
    LED_STATE_CONNECTED,       /* green solid — companion connected */
    LED_STATE_BUSY_KEY,        /* blue blinking — key derivation */
    LED_STATE_BUSY_SIGN,       /* blue blinking — signing */
    LED_STATE_TX_PROGRESS,     /* cyan fast breathing — receiving outputs */
    LED_STATE_AWAITING_CONFIRM,/* magenta blinking — waiting for user to press
                                  BOOT to confirm per-output recipient/value */
    LED_STATE_SUCCESS,         /* green flash → returns to previous */
    LED_STATE_ERROR,           /* red flash → returns to previous */
} LedState;

int led_status_init(void);
void led_status_set(LedState state);
