set(LIB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/lib")

# IMPORTANT: lib/ is a git submodule of wh00hw/libzcash-orchard-c. After
# updating that repo, run `git submodule update --remote` here and commit
# the new pointer, otherwise the file list below will reference content
# the working tree does not contain. The library API expects the constant-
# time `aes_ct.c` (audit H-3); the legacy Brian-Gladman files
# (aescrypt/aeskey/aes_modes/aestab) are no longer in the build.
#
# H-5 (PIN-protected wallet) is implemented via aead.c + wallet_lockout.c
# from the library. base58.c and hwp_dispatcher.c are also shipped by
# upstream but the ESP32 firmware drives its own dispatch loop in main.c
# and does not encode t-addrs on-device, so they are intentionally
# excluded from the build to save flash.
set(SRCS
    "${LIB_ROOT}/src/orchard.c"
    "${LIB_ROOT}/src/pallas.c"
    "${LIB_ROOT}/src/redpallas.c"
    "${LIB_ROOT}/src/bignum.c"
    "${LIB_ROOT}/src/blake2b.c"
    "${LIB_ROOT}/src/bip39.c"
    "${LIB_ROOT}/src/bip39_english.c"
    "${LIB_ROOT}/src/segwit_addr.c"
    "${LIB_ROOT}/src/memzero.c"
    "${LIB_ROOT}/src/hmac.c"
    "${LIB_ROOT}/src/pbkdf2.c"
    "${LIB_ROOT}/src/sha2.c"
    "${LIB_ROOT}/src/rand.c"
    "${LIB_ROOT}/src/hash_stubs.c"
    "${LIB_ROOT}/src/hwp.c"
    "${LIB_ROOT}/src/zip244.c"
    "${LIB_ROOT}/src/orchard_signer.c"
    "${LIB_ROOT}/src/bip32.c"
    "${LIB_ROOT}/src/secp256k1.c"
    "${LIB_ROOT}/src/aes/aes_ct.c"
    "${LIB_ROOT}/src/aead.c"
    "${LIB_ROOT}/src/wallet_lockout.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/platform_rng.c"
)

idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "${LIB_ROOT}/include"
    PRIV_INCLUDE_DIRS "${LIB_ROOT}/src" "${LIB_ROOT}/src/aes"
    REQUIRES esp_hw_support
    EMBED_FILES "${LIB_ROOT}/src/sinsemilla_s.bin"
)

# Production: use hardware RNG (provided by platform_rng.c in main)
target_compile_definitions(${COMPONENT_LIB} PUBLIC USE_PLATFORM_RNG=1)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-parameter)
