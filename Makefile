CFLAGS=-g -O3 -Wall -pthread
CC=gcc

all: bruteforce-erldp crack-prng crack-hash complete-cookie

bruteforce-erldp: bruteforce-erldp.o jsmn.o erldp.o
	$(CC) -o bruteforce-erldp bruteforce-erldp.o jsmn.o erldp.o -lnettle -lpthread

crack-prng: crack-prng.o erldp.o
	$(CC) -o crack-prng crack-prng.o erldp.o -lnettle -lpthread

crack-hash: crack-hash.o erldp.o
	$(CC) -o crack-hash crack-hash.o erldp.o -lnettle -lpthread

complete-cookie: complete-cookie.o erldp.o
	$(CC) -o complete-cookie complete-cookie.o erldp.o -lnettle -lpthread
