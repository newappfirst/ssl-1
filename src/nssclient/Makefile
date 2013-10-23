connect: connect.c
	#need to hardcode "usr/include/nspr" as Ubuntu nss3 headers are broken
	#and won't compile without it
	$(CC) -g -I/usr/include/nspr connect.c -lnss3 -lnspr4 -lssl3 -o connect
clean:
	rm connect
