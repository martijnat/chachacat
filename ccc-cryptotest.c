#include "chachacat.h"

int main() {
    int err=0;
    err |= run_sha256_tests();
    err |= run_chacha20_poly1305_tests();
    return err;
}
