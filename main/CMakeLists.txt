idf_component_register(
    SRCS
        "main.c"
        "wallet.c"
        "usb_transport.c"
        "led_status.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash esp_ringbuf
    PRIV_REQUIRES libzcash-orchard-c esp_tinyusb esp_driver_ledc
)
