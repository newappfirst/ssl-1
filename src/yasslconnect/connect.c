#include <cyassl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
int tcp_connect(char *host, int port)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int fd, s;
	char port_str[12];
	snprintf(port_str, sizeof(port_str), "%d", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	s = getaddrinfo(host, port_str, &hints, &result);
	if (s) {
		fd = -1;
		goto out;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(fd);
	}

	if (!rp) {
		fd = -1;
		goto out;
	}

	out:
	freeaddrinfo(result);
	return fd;
}
/**
 * Simple script that just connects to a server and uses CyaSSL to do a SSL handshake
 * returns 0 if the the program ran successfully, output is the error code from SSL_connect
 */
int main(int argc, char **argv)
{
	CYASSL_CTX     *ctx;
	CYASSL         *ssl;
	char           *host;
	int            port;
	char           *cafile;
	int            sockfd;
	int            rv;
	char           errorString[80] = {0};
	if (argc != 4) {
		printf("Usage: %s host port cacerts\n");
		return EXIT_SUCCESS;
	}
	host = argv[1];
	port = atoi(argv[2]);
	cafile = argv[3];
	CyaSSL_Init();
	/* set up the context */
	if (!(ctx = CyaSSL_CTX_new(CyaSSLv23_client_method()))){
		fprintf(stderr, "Error setting up CyaSSL context");
		return EXIT_FAILURE;
	}

	if (CyaSSL_CTX_load_verify_locations(ctx, cafile, NULL) != SSL_SUCCESS) {
		fprintf(stderr, "Error loading trusted certs from %s\n", cafile);
		return EXIT_FAILURE;
	}
	ssl = CyaSSL_new(ctx);
	/*connect the socket */
	sockfd = tcp_connect(host, port);
	if (sockfd < 0) {
		fprintf(stderr, "Error connecting to host %s:%d\n", host, port);
		return EXIT_FAILURE;
	}
	CyaSSL_set_fd(ssl, sockfd);
	rv = CyaSSL_connect(ssl);
	if (rv != SSL_SUCCESS) {
		rv = CyaSSL_get_error(ssl, rv);
		CyaSSL_ERR_error_string(rv, errorString);
	} else {
		rv = 0;
	}
	printf("%d\n", rv);
	close(sockfd);
	return EXIT_SUCCESS;
}
