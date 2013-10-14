CC = gcc
CFLAGS= -I/usr/local/lib/cryptlib
LIBS= -L/usr/local/lib/cryptlib

connect: connect.o 
	$(CC) connect.o -lcl $(LIBS) -lpthread -o connect

connect.o: connect.c
	$(CC) -c $(CFLAGS) connect.c 

clean:
	rm connect connect.o 
