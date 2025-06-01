#include "chachacat.h"
#include <stdio.h>

int run_sha256_tests(void) {
    int err = 0;
    struct {
        const char *input;
        const char *expected;
    } tests[] = {
        {
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        {
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        },
        {
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        },
        {
            "The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        }
    };

    printf("Running SHA-256 tests...\n");
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        SHA256_CTX ctx;
        uint8_t hash[32];
        char hex[65];

        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t*)tests[i].input, strlen(tests[i].input));
        sha256_final(&ctx, hash);

        for (int j = 0; j < 32; j++) {
            sprintf(hex + j*2, "%02x", hash[j]);
        }
        hex[64] = 0;

        if (strcmp(hex, tests[i].expected) == 0) {
            printf("  Test %zu: PASSED\n", i+1);
        } else {
            err = 1;
            printf("  Test %zu: FAILED\n", i+1);
            printf("    Input:    '%s'\n", tests[i].input);
            printf("    Expected: %s\n", tests[i].expected);
            printf("    Got:      %s\n", hex);
        }
    }
    return err;
}

int run_chacha20_poly1305_tests(void) {
    int err=0;
    // Test vectors from RFC 8439
    // note that that we change the ADD to be empty.
    const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    const uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };

    const uint8_t plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    const uint8_t expected_ciphertext[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };

    const uint8_t expected_tag[16] = {
        0x54, 0x7D, 0x4D, 0x03, 0x65, 0xBA, 0x76, 0x00,
        0xC2, 0x5B, 0xC1, 0x03, 0x5D, 0xE8, 0x5F, 0x01
    };

    printf("Running ChaCha20-Poly1305 tests...\n");

    // Test ChaCha20 encryption
    uint8_t ciphertext[sizeof(plaintext)];
    chacha20_ctx chacha;
    chacha20_init(&chacha, key, nonce);
    chacha20_encrypt(&chacha, plaintext, ciphertext, sizeof(plaintext), 1);

    if (memcmp(ciphertext, expected_ciphertext, sizeof(plaintext)) == 0) {
        printf("  ChaCha20 encryption: PASSED\n");
    } else {
        err = 1;
        printf("  ChaCha20 encryption: FAILED\n");
    }

    // Test Poly1305 MAC
    // Derive Poly1305 key by encrypting 32 zeros
    uint8_t poly_key[32];
    memset(poly_key, 0, 32);
    chacha20_ctx temp_ctx;
    chacha20_init(&temp_ctx, key, nonce);
    chacha20_encrypt(&temp_ctx, poly_key, poly_key, 32, 0);

    poly1305_ctx poly;
    poly1305_init(&poly, poly_key);

    // Process AAD (0 bytes) - nothing to add
    // Process ciphertext
    poly1305_update(&poly, ciphertext, sizeof(ciphertext));

    // Add padding for ciphertext (to reach 16-byte boundary)
    size_t padding_len = (16 - (sizeof(ciphertext) % 16)) % 16;
    if (padding_len) {
        uint8_t zeros[16] = {0};
        poly1305_update(&poly, zeros, padding_len);
    }

    // Append lengths: AAD length (0) and ciphertext length (114)
    uint8_t lengths[16];
    put_le64(lengths, 0); // AAD length
    put_le64(lengths+8, sizeof(ciphertext)); // ciphertext length
    poly1305_update(&poly, lengths, sizeof(lengths));

    uint8_t tag[16];
    poly1305_final(&poly, tag);

    if (memcmp(tag, expected_tag, sizeof(tag)) == 0) {
        printf("  Poly1305 MAC: PASSED\n");
    } else {
        err = 1;
        printf("  Poly1305 MAC: FAILED\n");
    }

    // Securely erase temporary keys and context
    explicit_bzero(poly_key, sizeof(poly_key));
    explicit_bzero(&temp_ctx, sizeof(temp_ctx));

    // Test decryption
    uint8_t decrypted[sizeof(plaintext)];
    chacha20_init(&chacha, key, nonce);
    chacha20_encrypt(&chacha, ciphertext, decrypted, sizeof(plaintext), 1);

    if (memcmp(decrypted, plaintext, sizeof(plaintext)) == 0) {
        printf("  ChaCha20 decryption: PASSED\n");
    } else {
        err = 1;
        printf("  ChaCha20 decryption: FAILED\n");
    }
    return err;
}

void get_password(char *password, size_t max_len) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fgets(password, max_len, stdin);
    password[strcspn(password, "\n")] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

void derive_key(const char *password, uint8_t key[KEY_SIZE]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)password, strlen(password));
    sha256_final(&ctx, key);
}

void put_le64(uint8_t *buf, uint64_t val) {
    buf[0] = val;
    buf[1] = val >> 8;
    buf[2] = val >> 16;
    buf[3] = val >> 24;
    buf[4] = val >> 32;
    buf[5] = val >> 40;
    buf[6] = val >> 48;
    buf[7] = val >> 56;
}

uint64_t get_le64(const uint8_t *buf) {
    return (uint64_t)buf[0] | ((uint64_t)buf[1] << 8) |
           ((uint64_t)buf[2] << 16) | ((uint64_t)buf[3] << 24) |
           ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
}
