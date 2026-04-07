set(LIB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/lib")

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
    "${LIB_ROOT}/src/aes/aescrypt.c"
    "${LIB_ROOT}/src/aes/aeskey.c"
    "${LIB_ROOT}/src/aes/aes_modes.c"
    "${LIB_ROOT}/src/aes/aestab.c"
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
