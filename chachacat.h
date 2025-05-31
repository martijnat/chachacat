#ifndef CHACHACAT_H
#define CHACHACAT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <sys/stat.h>

#define CCC_PORT 4500
#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define CHUNK_SIZE 4096
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SHA-256
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

// ChaCha20
typedef struct {
    uint32_t state[16];
} chacha20_ctx;

void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12]);
void chacha20_block(chacha20_ctx *ctx, uint32_t counter, uint8_t *out);
void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len, uint32_t counter);

// Poly1305
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_ctx;

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);
void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t bytes);
void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16]);

// Utility
void secure_erase(void *s, size_t len);
void get_password(char *password, size_t max_len);
void derive_key(const char *password, uint8_t key[KEY_SIZE]);
void put_le64(uint8_t *buf, uint64_t val);
uint64_t get_le64(const uint8_t *buf);

#endif
