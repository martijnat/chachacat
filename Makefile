CC = gcc
CFLAGS = -O3 -Wall -Wextra -pedantic

all: ccc-server ccc-client

ccc-server: ccc-server.o utils.o sha256.o chacha20.o poly1305.o
	$(CC) $(CFLAGS) -o $@ $^

ccc-client: ccc-client.o utils.o sha256.o chacha20.o poly1305.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c chachacat.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ccc-server ccc-client *.o

selftest: ccc-server ccc-client
	head -c 1K /dev/urandom > random_input.txt
	echo -n "password" | ./ccc-server random_output.txt &
	echo -n "password" | ./ccc-client 127.0.0.1 random_input.txt
	diff -q random_input.txt random_output.txt
	rm random_input.txt random_output.txt


