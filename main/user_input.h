/**
 * User-input — single-button confirmation on the ESP32-S2 BOOT pin (GPIO0).
 *
 * The dev board (Flipper WiFi Dev Board v1) exposes GPIO0 as a momentary
 * push-to-ground BOOT button with an internal pull-up. We use it as the
 * only physical input the user has on this reference port: one press
 * confirms the currently displayed prompt, a long press cancels.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    USER_INPUT_NONE = 0,    /* timeout, no press */
    USER_INPUT_CONFIRM,     /* short press */
    USER_INPUT_CANCEL,      /* long press (>= 2 s) */
} UserInputResult;

/**
 * Configure GPIO0 as input with internal pull-up. Idempotent.
 */
int user_input_init(void);

/**
 * Block until the user presses the BOOT button (or until timeout_ms elapses).
 *
 * Returns USER_INPUT_CONFIRM for short presses (< 2 s), USER_INPUT_CANCEL
 * for long presses (>= 2 s), or USER_INPUT_NONE on timeout. Polls every
 * 20 ms with a small debounce window.
 */
UserInputResult user_input_wait(uint32_t timeout_ms);

/* --- PIN entry over tap-count (audit H-5) -------------------------- */

#include "wallet.h"  /* WALLET_PIN_LEN */

typedef enum {
    PIN_ENTRY_OK = 0,
    PIN_ENTRY_CANCELLED,        /* user held button > 3 s */
    PIN_ENTRY_TIMEOUT,          /* no input within 60 s */
} PinEntryResult;

/**
 * Collect a 5-digit PIN via tap-count encoding.
 *
 * Each digit:
 *   - tap N times rapidly (1 <= N <= 10);
 *   - wait ~1.5 s without tapping → digit confirmed (10 taps = digit "0");
 *   - LED status blinks the entered count back as visual confirmation
 *     (the firmware drives this via led_status_set(LED_STATE_PIN_ECHO_*)).
 *
 * Cancel/restart at any point: hold the button > 3 s.
 *
 * Stack budget: < 64 bytes (no large locals).
 *
 * @param pin_out  WALLET_PIN_LEN bytes, each in [0, 9]
 */
PinEntryResult user_input_collect_pin(uint8_t pin_out[WALLET_PIN_LEN]);
