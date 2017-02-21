CC=gcc
CFLAGS=-Wall -DDEBUG --debug -I../ -I./
MBEDTLS=aes.o sha512.o aesni.o

all: hashcrypt

%.o: %.c
	$(CC) $(CFLAGS) -c $<

mbedtls: $(MBEDTLS)

hashcrypt: main.cpp mbedtls macros.h
	g++ $(CFLAGS) -o $@ main.cpp $(MBEDTLS)

run: hashcrypt
	./hashcrypt

clean:
	rm -f *.o hashcrypt
