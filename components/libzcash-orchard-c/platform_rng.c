/**
 * Platform RNG implementation for ESP32-S2.
 *
 * Provides random32() and random_buffer() required by libzcash-orchard-c
 * when USE_PLATFORM_RNG=1. Uses the ESP32 hardware RNG (RF noise-based).
 */
#include <stdint.h>
#include <stddef.h>
#include "esp_random.h"

uint32_t random32(void)
{
    return esp_random();
}

void random_buffer(uint8_t *buf, size_t len)
{
    esp_fill_random(buf, len);
}
