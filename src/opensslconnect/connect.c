#include <openssl/ssl.h>
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
 * Simple script that just connects to a server and uses SSL to do a SSL handshake
 * returns 0 if the the program ran successfully, output is the error code from SSL_connect
 */
int main(int argc, char **argv)
{
	SSL_CTX     *ctx;
	SSL         *ssl;
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
	SSL_load_error_strings();
	SSL_library_init();
	/* set up the context */
	if (!(ctx = SSL_CTX_new(SSLv23_client_method()))){
		fprintf(stderr, "Error setting up SSL context");
		return EXIT_FAILURE;
	}

	if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
		fprintf(stderr, "Error loading trusted certs from %s\n", cafile);
		return EXIT_FAILURE;
	}
	ssl = SSL_new(ctx);
	/*connect the socket */
	sockfd = tcp_connect(host, port);
	if (sockfd < 0) {
		fprintf(stderr, "Error connecting to host %s:%d\n", host, port);
		return EXIT_FAILURE;
	}
	SSL_set_fd(ssl, sockfd);
	rv = SSL_connect(ssl);
	/* in openSSL this shouldn't fail unless the handshake messes up
	 * cyaSSL on the other hand has SSL_connect fail on verification failure
	 * ???
	 */
	if (rv != 1) {
		rv = SSL_get_error(ssl, rv);
		ERR_error_string_n(rv, errorString, sizeof(errorString));
	} else {
		rv = SSL_get_verify_result(ssl);
		if (rv == X509_V_OK) {
			rv = 0;
		} else {
			snprintf(errorString, sizeof(errorString), "%s", X509_verify_cert_error_string(rv));
		}
	}
	printf("%d\n", rv);
	close(sockfd);
	return EXIT_SUCCESS;
}
