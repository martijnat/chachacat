# ChaChaCat

Command line tools for streaming files encrypted using
ChaCha2020-Poly1305 over TCP.

This project has no external dependencies and compiles to static
binaries so it should work on a wide array of operating systems.

# Instructions
To build the project:
```bash
make
```

To run the selftests
```bash
make test
```

To run:
```bash
# Server (output to file, listen on port 4500)
./ccc-server output.txt 4500

# Client (connect to server, send file)
./ccc-client 127.0.0.1 input.txt 4500
```
