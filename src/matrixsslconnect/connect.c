#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include "matrixssl/matrixsslApi.h"

#define INVALID_SOCKET -1

#define TRACE(s, ...) fprintf(stderr, s, ##__VA_ARGS__)
#define PRINT_VERIFY_RESULT(res) fprintf(stdout, "%d\n", res)
static int certCb(ssl_t *ssl, psX509Cert_t *cert, int alert);
static int socketConnect(char *host, int port);
static void closeConn(ssl_t *ssl, int fd);


static int startClientConnection(sslKeys_t *keys, sslSessionId_t *sid, char *host, int port)
{
	int			rc, transferred, len, complete;
	ssl_t			*ssl;
	unsigned char	*buf;
	int			fd;
	
	complete = 0;
	fd = socketConnect(host, port);
	if (fd == INVALID_SOCKET)  {
		TRACE("Connect failed: %d.  Exiting\n", fd);
		return -1;
	}
	
	rc = matrixSslNewClientSession(&ssl, keys, sid, 0, certCb, NULL, NULL, 0);
	if (rc != MATRIXSSL_REQUEST_SEND) {
		TRACE("New Client Session Failed: %d.  Exiting\n", rc);
		close(fd);
		return -1;
	}

	while ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
		transferred = send(fd, buf, len, 0);
		if (transferred <= 0) {
			goto L_CLOSE_ERR;
		} else {
			/* Indicate that we've written > 0 bytes of data */
			if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
				goto L_CLOSE_ERR;
			}
			if (rc == MATRIXSSL_REQUEST_CLOSE) {
				closeConn(ssl, fd);
				return MATRIXSSL_SUCCESS;
			} 
			if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
				return 0;
			}
		}
	}
READ_MORE:
	if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0) {
		goto L_CLOSE_ERR;
	}
	if ((transferred = recv(fd, buf, len, 0)) < 0) {
		goto L_CLOSE_ERR;
	}
	/*	If EOF, remote socket closed. But we haven't received 
                the HTTP response so we consider it an error in the case 
                of an HTTP client */
	if (transferred == 0) {
		goto L_CLOSE_ERR;
	}
	if ((rc = matrixSslReceivedData(ssl, (int)transferred, &buf,
							(uint*)&len)) < 0) {
		goto L_CLOSE_ERR;
	}
	
PROCESS_MORE:
	switch (rc) {
		case MATRIXSSL_HANDSHAKE_COMPLETE:
			return 0;
		case MATRIXSSL_APP_DATA:
			rc = matrixSslProcessedData(ssl, &buf, (uint*)&len);
			closeConn(ssl, fd);
			if (rc < 0) {
				return -1;
			} else {
				if (rc > 0) {
					TRACE("HTTP data parsing not supported, ignoring.\n");
				}
				TRACE("SUCCESS: Received HTTP Response\n");
				return 0;
			}
			/* We processed a partial HTTP message */
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint*)&len)) == 0) {
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		case MATRIXSSL_REQUEST_SEND:
			//goto WRITE_MORE;
			return 0;
		case MATRIXSSL_REQUEST_RECV:
			goto READ_MORE;
		case MATRIXSSL_RECEIVED_ALERT:
			/* The first byte of the buffer is the level */
			/* The second byte is the description */
			if (*buf == SSL_ALERT_LEVEL_FATAL) {
				psTraceIntInfo("Fatal alert: %d, closing connection.\n", 
							*(buf + 1));
				goto L_CLOSE_ERR;
			}
			/* Closure alert is normal (and best) way to close */
			if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
				closeConn(ssl, fd);
				return 0;
			}
			psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint*)&len)) == 0) {
				/* No more data in buffer. Might as well read for more. */
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		default:
			/* If rc <= 0 we fall here */
			goto L_CLOSE_ERR;
	}
	
L_CLOSE_ERR:
	TRACE("FAIL: No response from the server\n");
	matrixSslDeleteSession(ssl);
	close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	int			rc, CAstreamLen;
	sslKeys_t		*keys;
	sslSessionId_t		*sid;
	char			*CAstream;

	char *host = argv[1];
	int port = atoi(argv[2]);
	char *cafile = argv[3];
	
	if ((rc = matrixSslOpen()) < 0) {
		TRACE("MatrixSSL library init failure.  Exiting\n");
		return rc; 
	}
	if (matrixSslNewKeys(&keys) < 0) {
		TRACE("MatrixSSL library key init failure.  Exiting\n");
		return -1;
	}

/*
	File based keys
*/
	CAstreamLen = 0;
	CAstreamLen += (int)strlen(cafile) + 1;
	if (CAstreamLen > 0) {
		CAstream = psMalloc(NULL, CAstreamLen);
		memset(CAstream, 0x0, CAstreamLen);
	} else {
		CAstream = NULL;
	}
	
	CAstreamLen = 0;
	memcpy(CAstream, cafile, strlen(cafile));
	CAstreamLen += strlen(cafile);

	if ((rc = matrixSslLoadRsaKeys(keys, NULL, NULL, NULL,
		(char*)CAstream)) < 0) {
		TRACE("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}

	if (CAstream) psFree(CAstream);


	matrixSslNewSessionId(&sid);
	rc = startClientConnection(keys, sid, host, port);

	matrixSslDeleteSessionId(sid);
	matrixSslDeleteKeys(keys);
	matrixSslClose();

	return rc;
}

static void closeConn(ssl_t *ssl, int fd)
{
	unsigned char	*buf;
	int			len;
	
	/* Set the socket to non-blocking to flush remaining data */
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	/* Quick attempt to send a closure alert, don't worry about failure */
	if (matrixSslEncodeClosureAlert(ssl) >= 0) {
		if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
			if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(ssl, len);
			}
		}
	}
	matrixSslDeleteSession(ssl);
	if (fd != INVALID_SOCKET) close(fd);
}

static int certCb(ssl_t *ssl, psX509Cert_t *cert, int alert)
{
	struct tm	t;
	time_t		rawtime;
	char		*c;
	int			y, m, d;
	
	/* Example to allow anonymous connections based on a define */
	if (alert > 0) {
		PRINT_VERIFY_RESULT(alert);
		//TRACE("Certificate callback returning fatal alert\n");
		return alert;
	}
	
	/* Validate the dates in the cert */
	time(&rawtime);
	localtime_r(&rawtime, &t);
	/* Localtime does months from 0-11 and (year-1900)! Normalize it. */
	t.tm_mon++;
	t.tm_year += 1900;
	
	/* Validate the 'not before' date */
	if ((c = cert->notBefore) != NULL) {
		if (strlen(c) < 8) {
			PRINT_VERIFY_RESULT(-1);
			return -1;
		}
		/* UTCTIME, defined in 1982, has just a 2 digit year */
		if (cert->notBeforeTimeType == ASN_UTCTIME) {
			y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		} else {
			y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') + 
			10 * (c[2] - '0') + (c[3] - '0'); c += 4;
		}
		m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		d = 10 * (c[0] - '0') + (c[1] - '0'); 
		if (t.tm_year < y) return PS_FAILURE; 
		if (t.tm_year == y) {
			if (t.tm_mon < m) return PS_FAILURE;
			if (t.tm_mon == m && t.tm_mday < d) return PS_FAILURE;
		}
/*		TRACEStr("Validated notBefore: %s\n", cert->notBefore); */
	}
	
	/* Validate the 'not after' date */
	if ((c = cert->notAfter) != NULL) {
		if (strlen(c) < 8) {
			PRINT_VERIFY_RESULT(-1);
			return -1;
		}
		/* UTCTIME, defined in 1982 has just a 2 digit year */
		if (cert->notAfterTimeType == ASN_UTCTIME) {
			y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		} else {
			y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') + 
			10 * (c[2] - '0') + (c[3] - '0'); c += 4;
		}
		m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		d = 10 * (c[0] - '0') + (c[1] - '0'); 
		if (t.tm_year > y) return PS_FAILURE; 
		if (t.tm_year == y) {
			if (t.tm_mon > m) return PS_FAILURE;
			if (t.tm_mon == m && t.tm_mday > d) return PS_FAILURE;
		}
/*		TRACEStr("Validated notAfter: %s\n", cert->notAfter); */
	}
	PRINT_VERIFY_RESULT(0);
	//TRACE("Validated cert for: %s.\n", cert->subject.commonName);
	
	return 0;
}


static int socketConnect(char *host, int port)
{
	int			fd;
        struct addrinfo 	hints;
        struct addrinfo 	*result = NULL, *rp;
        int 			s;
        char 			port_str[12];

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
