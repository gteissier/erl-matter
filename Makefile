CFLAGS=-g -O3 -Wall -pthread
CC=gcc

all: bruteforce-erldp crack-prng mass-prng crack-hash

bruteforce-erldp: bruteforce-erldp.o erldp.o
	$(CC) -o bruteforce-erldp bruteforce-erldp.o erldp.o -lnettle -lpthread

crack-prng: crack-prng.o erldp.o
	$(CC) -o crack-prng crack-prng.o erldp.o -lnettle -lpthread

mass-prng: mass-prng.o erldp.o
	$(CC) -o mass-prng mass-prng.o erldp.o -lnettle -lpthread

crack-hash: crack-hash.o erldp.o
	$(CC) -o crack-hash crack-hash.o erldp.o -lnettle -lpthread
