#include "chachacat.h"

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <server-ip> <input-file> [port=%d]\n", argv[0], CCC_PORT);
        return 1;
    }

    char *ip = argv[1];
    char *input_file = argv[2];
    int port = (argc == 4) ? atoi(argv[3]) : CCC_PORT;

    // Get password
    char password[1024];
    printf("Enter password: ");
    fflush(stdout);
    get_password(password, sizeof(password));

    // Derive key
    uint8_t key[KEY_SIZE];
    derive_key(password, key);
    secure_erase(password, sizeof(password));

    // Open input file
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("fopen");
        return 1;
    }

    // Get file size
    fseek(in, 0, SEEK_END);
    uint64_t file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    // Generate nonce
    uint8_t nonce[NONCE_SIZE];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, nonce, NONCE_SIZE) != NONCE_SIZE) {
        perror("Failed to generate nonce");
        if (fd >= 0) close(fd);
        fclose(in);
        return 1;
    }
    close(fd);

    // Setup socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        fclose(in);
        return 1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        fclose(in);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("connect");
        close(sock);
        fclose(in);
        return 1;
    }

    // Send file size and nonce
    uint8_t size_buf[8];
    put_le64(size_buf, file_size);
    if (send(sock, size_buf, 8, 0) != 8 ||
        send(sock, nonce, NONCE_SIZE, 0) != NONCE_SIZE) {
        perror("send header");
        close(sock);
        fclose(in);
        return 1;
    }

    // Initialize encryption
    chacha20_ctx chacha;
    chacha20_init(&chacha, key, nonce);
    poly1305_ctx poly;
    poly1305_init(&poly, key);
    secure_erase(key, KEY_SIZE);

    // Encrypt and send data
    uint8_t in_buf[CHUNK_SIZE], out_buf[CHUNK_SIZE];
    uint64_t total = 0;
    uint32_t counter = 1;  // Start from block 1

    while (total < file_size) {
        int to_read = (file_size - total > CHUNK_SIZE) ? CHUNK_SIZE : file_size - total;
        int n = fread(in_buf, 1, to_read, in);
        if (n != to_read) {
            perror("fread");
            fclose(in);
            close(sock);
            return 1;
        }

        // Encrypt chunk
        chacha20_encrypt(&chacha, in_buf, out_buf, n, counter);
        counter += (n + 63) / 64;  // Increment block counter

        // Update MAC
        poly1305_update(&poly, out_buf, n);

        // Send encrypted data
        if (send(sock, out_buf, n, 0) != n) {
            perror("send data");
            fclose(in);
            close(sock);
            return 1;
        }

        total += n;
    }

    // Generate and send MAC
    uint8_t mac[TAG_SIZE];
    poly1305_final(&poly, mac);
    if (send(sock, mac, TAG_SIZE, 0) != TAG_SIZE) {
        perror("send MAC");
        fclose(in);
        close(sock);
        return 1;
    }

    fclose(in);
    close(sock);
    return 0;
}
