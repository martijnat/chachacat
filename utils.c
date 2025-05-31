// utils.c
#include "chachacat.h"

void secure_erase(void *s, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)s;
    while (len--) *p++ = 0;
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
