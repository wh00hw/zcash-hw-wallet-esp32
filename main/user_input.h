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
