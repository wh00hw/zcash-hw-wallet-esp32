/**
 * LED status indicator — RGB LED (R=GPIO6, G=GPIO5, B=GPIO4).
 *
 * States:
 *   INITIALIZING  — blue blinking          (wallet creation + key derivation)
 *   READY         — green solid            (protocol active, waiting for companion)
 *   CONNECTED     — green solid            (companion app connected)
 *   BUSY_KEY      — blue blinking          (key derivation during protocol)
 *   BUSY_SIGN     — blue blinking          (signing in progress)
 *   TX_PROGRESS   — cyan fast breathing    (receiving TX outputs)
 *   SUCCESS       — green flash            (operation completed, returns to prev)
 *   ERROR         — red flash              (error, returns to prev)
 */
#pragma once

typedef enum {
    LED_STATE_OFF,
    LED_STATE_INITIALIZING, /* blue blinking — wallet init / first derivation */
    LED_STATE_READY,        /* green solid — protocol active, no companion */
    LED_STATE_CONNECTED,    /* green solid — companion connected */
    LED_STATE_BUSY_KEY,     /* blue blinking — key derivation */
    LED_STATE_BUSY_SIGN,    /* blue blinking — signing */
    LED_STATE_TX_PROGRESS,  /* cyan fast breathing — receiving outputs */
    LED_STATE_SUCCESS,      /* green flash → returns to previous */
    LED_STATE_ERROR,        /* red flash → returns to previous */
} LedState;

int led_status_init(void);
void led_status_set(LedState state);
