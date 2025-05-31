#include "chachacat.h"

static void poly1305_add(poly1305_ctx *ctx, const uint8_t *m) {
    uint32_t t0 = (m[0]) | (m[1] << 8) | (m[2] << 16) | (m[3] << 24);
    uint32_t t1 = (m[4]) | (m[5] << 8) | (m[6] << 16) | (m[7] << 24);
    uint32_t t2 = (m[8]) | (m[9] << 8) | (m[10] << 16) | (m[11] << 24);
    uint32_t t3 = (m[12]) | (m[13] << 8) | (m[14] << 16) | (m[15] << 24);

    ctx->h[0] += t0 & 0x3ffffff;
    ctx->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    ctx->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    ctx->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    ctx->h[4] += (t3 >> 8) | (1 << 24);
}

static void poly1305_squeeze(poly1305_ctx *ctx) {
    uint32_t g0, g1, g2, g3, g4;
    uint64_t t0, t1, t2, t3;

    t0 = ctx->h[0] + (uint64_t)ctx->pad[0];
    t1 = ctx->h[1] + (uint64_t)ctx->pad[1] + (t0 >> 26);
    t0 &= 0x3ffffff;
    t2 = ctx->h[2] + (uint64_t)ctx->pad[2] + (t1 >> 26);
    t1 &= 0x3ffffff;
    t3 = ctx->h[3] + (uint64_t)ctx->pad[3] + (t2 >> 26);
    t2 &= 0x3ffffff;
    g4 = ctx->h[4] + (t3 >> 26);
    t3 &= 0x3ffffff;

    g0 = t0 + 5;
    g1 = t1 + (g0 >> 26); g0 &= 0x3ffffff;
    g2 = t2 + (g1 >> 26); g1 &= 0x3ffffff;
    g3 = t3 + (g2 >> 26); g2 &= 0x3ffffff;
    g4 += (g3 >> 26); g3 &= 0x3ffffff;
    g0 += (g4 >> 2) * 5;
    g1 += (g0 >> 26);
    g0 &= 0x3ffffff;

    ctx->h[0] = (g0 > 0x3ffffff) ? g0 - 5 : t0;
    ctx->h[1] = (g1 > 0x3ffffff) ? g1 - (g0 >> 26) : t1;
    ctx->h[2] = (g2 > 0x3ffffff) ? g2 - (g1 >> 26) : t2;
    ctx->h[3] = (g3 > 0x3ffffff) ? g3 - (g2 >> 26) : t3;
    ctx->h[4] = 0;
}

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    ctx->r[0] = ((uint32_t*)key)[0] & 0x0fffffff;
    ctx->r[1] = ((uint32_t*)key)[1] & 0x0ffffffc;
    ctx->r[2] = ((uint32_t*)key)[2] & 0x0ffffffc;
    ctx->r[3] = ((uint32_t*)key)[3] & 0x0ffffffc;

    ctx->pad[0] = ((uint32_t*)key)[4];
    ctx->pad[1] = ((uint32_t*)key)[5];
    ctx->pad[2] = ((uint32_t*)key)[6];
    ctx->pad[3] = ((uint32_t*)key)[7];

    memset(ctx->h, 0, sizeof(ctx->h));
    ctx->leftover = 0;
    ctx->final = 0;
}

void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > bytes) want = bytes;
        memcpy(ctx->buffer + ctx->leftover, m, want);
        bytes -= want;
        m += want;
        ctx->leftover += want;
        if (ctx->leftover < 16) return;
        poly1305_add(ctx, ctx->buffer);
        ctx->leftover = 0;
    }

    while (bytes >= 16) {
        poly1305_add(ctx, m);
        poly1305_squeeze(ctx);
        m += 16;
        bytes -= 16;
    }

    if (bytes) {
        memcpy(ctx->buffer, m, bytes);
        ctx->leftover = bytes;
    }
}

void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16]) {
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < 16; i++) ctx->buffer[i] = 0;
        ctx->final = 1;
        poly1305_add(ctx, ctx->buffer);
        poly1305_squeeze(ctx);
    }

    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];

    uint32_t g0, g1, g2, g3;
    g0 = h0 + 5;
    g1 = h1 + (g0 >> 26); g0 &= 0x3ffffff;
    g2 = h2 + (g1 >> 26); g1 &= 0x3ffffff;
    g3 = h3 + (g2 >> 26); g2 &= 0x3ffffff;
    g0 += (g3 >> 26) * 5; g3 &= 0x3ffffff;
    g1 += g0 >> 26; g0 &= 0x3ffffff;

    h0 = (g0 > 0x3ffffff) ? g0 - 5 : h0;
    h1 = (g1 > 0x3ffffff) ? h1 : g1;
    h2 = (g2 > 0x3ffffff) ? h2 : g2;
    h3 = (g3 > 0x3ffffff) ? h3 : g3;

    uint32_t t0 = h0 + ctx->pad[0];
    uint32_t t1 = h1 + ctx->pad[1] + (t0 >> 26);
    t0 &= 0x3ffffff;
    uint32_t t2 = h2 + ctx->pad[2] + (t1 >> 26);
    t1 &= 0x3ffffff;
    uint32_t t3 = h3 + ctx->pad[3] + (t2 >> 26);
    t2 &= 0x3ffffff;
    t3 &= 0xffffffff;

    mac[0]  = t0; mac[1]  = t0 >> 8; mac[2]  = t0 >> 16; mac[3]  = t0 >> 24;
    mac[4]  = t1; mac[5]  = t1 >> 8; mac[6]  = t1 >> 16; mac[7]  = t1 >> 24;
    mac[8]  = t2; mac[9]  = t2 >> 8; mac[10] = t2 >> 16; mac[11] = t2 >> 24;
    mac[12] = t3; mac[13] = t3 >> 8; mac[14] = t3 >> 16; mac[15] = t3 >> 24;
}
