CC = gcc
connect: connect.o 
	#utils.o
	$(CC) connect.o -lcl -L/Users/bray/github/ssl/src/cryptlib -lpthread -o connect

connect.o: connect.c
	$(CC) -c -I/Users/bray/github/ssl/src/cryptlib connect.c 
#utils.o: utils.c
#	$(CC) -c -I/Users/bray/github/ssl/src/cryptlib utils.c 

clean:
	rm connect 
