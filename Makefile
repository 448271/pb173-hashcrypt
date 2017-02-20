CC=gcc
CFLAGS=-Wall -DDEBUG --debug
HEADERS=debug.h
OBJECTS=aes.o sha512.o aesni.o

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $<

hashcrypt: main.cpp $(OBJECTS)
	g++ $(CFLAGS) -o $@ main.cpp $(OBJECTS)

run: hashcrypt
	./hashcrypt

clean:
	rm -f *.o hashcrypt
