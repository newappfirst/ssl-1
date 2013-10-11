/*
 *  SSL client demonstration program
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"
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


#define DEBUG_LEVEL 1

void my_debug( void *ctx, int level, const char *str )
{
    if( level < DEBUG_LEVEL )
    {
        fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_CLI_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_RSA_C) ||         \
    !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_BIGNUM_C and/or POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_CLI_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret, len, server_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    x509_cert cacert;

    char *host = argv[1];
    int port = atoi(argv[2]);
    char *cafile = argv[3];
    /*
     * 0. Initialize the RNG and the session data
     */
    memset( &ssl, 0, sizeof( ssl_context ) );
    memset( &cacert, 0, sizeof( x509_cert ) );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
	    return 1;
    }

    /*
     * 0. Initialize certificates
     */
    ret = x509parse_crtfile( &cacert, cafile);

    if( ret < 0 )
    {
	    return -1;
    }

    /*
     * 1. Start the connection
     */
    server_fd = tcp_connect(host, port);
    if (server_fd < 0)
	    return -1;

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
	    return -1;
    }


    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
    ssl_set_authmode( &ssl, SSL_VERIFY_OPTIONAL );
    ssl_set_ca_chain( &ssl, &cacert, NULL, "PolarSSL Server 1" );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_bio( &ssl, net_recv, &server_fd,
                       net_send, &server_fd );

    /*
     * 4. Handshake
     */

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }


    /*
     * 5. Verify the server certificate
     */

    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
	    ret = ret & ~BADCERT_CN_MISMATCH;
    }
    printf("%d\n", ret);


    ssl_close_notify( &ssl );

exit:

    x509_free( &cacert );
    net_close( server_fd );
    ssl_free( &ssl );

    memset( &ssl, 0, sizeof( ssl ) );


    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_ENTROPY_C && POLARSSL_SSL_TLS_C &&
          POLARSSL_SSL_CLI_C && POLARSSL_NET_C && POLARSSL_RSA_C &&
          POLARSSL_CTR_DRBG_C */
