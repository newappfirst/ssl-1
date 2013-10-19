CC = gcc
CFLAGS= -I/usr/local/lib/cryptlib
LIBS= -L/usr/local/lib/cryptlib

connect: connect.o util.o
	$(CC) connect.o util.o -lcl $(LIBS) -lpthread -o connect

connect.o: connect.c 
	$(CC) -c $(CFLAGS) connect.c 

util.o: util.c 
	$(CC) -c $(CFLAGS) util.c 

clean:
	rm connect *.o 
