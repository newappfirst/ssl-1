MATRIX_SSL_HOME = /home/suman/Desktop/matrixssl_test/matrixssl-3-4-2-open
connect: connect.c
	$(CC) -DMAKEFILE_BUILD -DPOSIX -I $(MATRIX_SSL_HOME) -lmatrixssl -L $(MATRIX_SSL_HOME) connect.c -o connect
clean:
	rm connect
