#include "chachacat.h"

static void chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d = ROTL32(*d ^ *a, 16);
    *c += *d; *b = ROTL32(*b ^ *c, 12);
    *a += *b; *d = ROTL32(*d ^ *a, 8);
    *c += *d; *b = ROTL32(*b ^ *c, 7);
}

void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
        ctx->state[4+i] = ((uint32_t*)key)[i];
    ctx->state[12] = 0;
    for (int i = 0; i < 3; i++)
        ctx->state[13+i] = ((uint32_t*)nonce)[i];
}

void chacha20_block(chacha20_ctx *ctx, uint32_t counter, uint8_t *out) {
    uint32_t x[16];
    memcpy(x, ctx->state, sizeof(x));
    x[12] = counter;

    for (int i = 0; i < 10; i++) {
        chacha20_quarterround(&x[0], &x[4], &x[8],  &x[12]);
        chacha20_quarterround(&x[1], &x[5], &x[9],  &x[13]);
        chacha20_quarterround(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarterround(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarterround(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarterround(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarterround(&x[2], &x[7], &x[8],  &x[13]);
        chacha20_quarterround(&x[3], &x[4], &x[9],  &x[14]);
    }

    for (int i = 0; i < 16; i++) {
        uint32_t val = x[i] + ctx->state[i];
        out[4*i]   = val;
        out[4*i+1] = val >> 8;
        out[4*i+2] = val >> 16;
        out[4*i+3] = val >> 24;
    }
}

void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len, uint32_t counter) {
    uint8_t key_stream[64];
    for (size_t i = 0; i < len; i++) {
        if (i % 64 == 0) {
            chacha20_block(ctx, counter++, key_stream);
        }
        out[i] = in[i] ^ key_stream[i % 64];
    }
}
