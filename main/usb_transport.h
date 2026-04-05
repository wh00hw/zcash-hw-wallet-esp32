/**
 * USB CDC transport layer for HWP protocol.
 *
 * The ESP32-S2 has native USB OTG. On the Flipper Zero WiFi Dev Board v1,
 * the USB connector is wired directly to the ESP32-S2 USB pins.
 * The device appears as a USB CDC ACM serial port on the host (/dev/ttyACM0).
 *
 * IMPORTANT: This channel carries ONLY binary HWP frames.
 * All debug logging goes to UART0 via ESP_LOG*.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hwp.h"

/**
 * Initialize USB CDC for HWP communication.
 * Returns 0 on success.
 */
int usb_transport_init(void);

/**
 * Send a raw HWP frame over USB CDC.
 * @return Number of bytes written, or -1 on error
 */
int usb_transport_send(const uint8_t *data, size_t len);

/**
 * Check if the USB host has opened the serial port (DTR active).
 */
bool usb_transport_host_connected(void);

/**
 * Redirect ESP_LOG output to USB CDC 1 (ACM1).
 * Call after usb_transport_init().
 */
void usb_transport_log_redirect(void);

/**
 * Blocking read: waits for a complete HWP frame.
 * @param parser      HWP parser (re-initialized each call)
 * @param timeout_ms  Read timeout in milliseconds (0 = forever)
 * @return HWP_FEED_FRAME_READY on success, or error code
 */
HwpFeedResult usb_transport_recv_frame(HwpParser *parser, uint32_t timeout_ms);
