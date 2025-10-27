CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -pedantic

OBJS = des.o des_tables.o main.o

all: des_test

des_test: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

des.o: des.c des.h des_tables.h des_bytes.h
	$(CC) $(CFLAGS) -c des.c

des_tables.o: des_tables.c des_tables.h
	$(CC) $(CFLAGS) -c des_tables.c

main.o: main.c des.h des_tables.h des_bytes.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(OBJS) des_test

.PHONY: all clean
