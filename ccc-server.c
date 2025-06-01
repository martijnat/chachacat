#include "chachacat.h"

int main(int argc, char *argv[]) {
    char *output_file = "/dev/stdout";
    int port = CCC_PORT;

    if (argc >= 2) output_file = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    // Get password
    char password[1024];
    printf("Enter password: ");
    fflush(stdout);
    get_password(password, sizeof(password));

    // Derive key
    uint8_t key[KEY_SIZE];
    derive_key(password, key);
    explicit_bzero(password, sizeof(password));

    // Setup server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1)) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Listening on port %d...\n", port);
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        return 1;
    }

    // Receive file size and nonce
    uint8_t size_buf[8], nonce[NONCE_SIZE];
    if (recv(client_fd, size_buf, 8, MSG_WAITALL) != 8 ||
        recv(client_fd, nonce, NONCE_SIZE, MSG_WAITALL) != NONCE_SIZE) {
        perror("recv header");
        close(client_fd);
        close(server_fd);
        return 1;
    }

    uint64_t file_size = get_le64(size_buf);
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("fopen");
        close(client_fd);
        close(server_fd);
        return 1;
    }

    // Initialize decryption
    chacha20_ctx chacha;
    chacha20_init(&chacha, key, nonce);
    poly1305_ctx poly;
    poly1305_init(&poly, key);
    explicit_bzero(key, KEY_SIZE);

    // Receive and decrypt data
    uint8_t in_buf[CHUNK_SIZE], out_buf[CHUNK_SIZE];
    uint64_t received = 0;
    uint32_t counter = 1;  // Start from block 1

    while (received < file_size) {
        uint64_t to_read = (file_size - received > CHUNK_SIZE) ? CHUNK_SIZE : file_size - received;
        int n = recv(client_fd, in_buf, to_read, MSG_WAITALL);
        if (n <= 0) {
            perror("recv data");
            fclose(out);
            close(client_fd);
            close(server_fd);
            return 1;
        }

        // Update MAC
        poly1305_update(&poly, in_buf, n);

        // Decrypt chunk
        chacha20_encrypt(&chacha, in_buf, out_buf, n, counter);
        counter += (n + 63) / 64;  // Increment block counter

        // Write decrypted data
        // safe to cast n, already checked earlier
        if (fwrite(out_buf, 1, n, out) != (uint64_t) n) {
            perror("fwrite");
            fclose(out);
            close(client_fd);
            close(server_fd);
            return 1;
        }

        received += n;
    }

    // Verify MAC
    uint8_t received_mac[TAG_SIZE], computed_mac[TAG_SIZE];
    if (recv(client_fd, received_mac, TAG_SIZE, MSG_WAITALL) != TAG_SIZE) {
        perror("recv MAC");
        fclose(out);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    poly1305_final(&poly, computed_mac);
    if (memcmp(received_mac, computed_mac, TAG_SIZE) != 0) {
        fprintf(stderr, "MAC verification failed!\n");
        fclose(out);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    fclose(out);
    close(client_fd);
    close(server_fd);
    printf("File received and verified successfully\n");
    return 0;
}
