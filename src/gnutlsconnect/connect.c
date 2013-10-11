#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
unsigned verification_result = 0;
char *error = "";
/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
static int
_verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  int ret, type;
  const char *hostname;
  gnutls_datum_t out;

  hostname = gnutls_session_get_ptr (session);
  ret = gnutls_certificate_verify_peers3 (session, NULL, &status);
  if (ret < 0) {
	  return GNUTLS_E_CERTIFICATE_ERROR;
  }

  type = gnutls_certificate_type_get (session);
  ret = gnutls_certificate_verification_status_print( status, type, &out, 0);

  if (status != 0) {
      error = out.data;
      verification_result = status;
      return GNUTLS_E_CERTIFICATE_ERROR;
  }
  return 0;
}
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
static int verify_certificate_callback (gnutls_session_t session);

int main (int argc, char **argv)
{
  int ret, sd, ii;
  gnutls_session_t session;
  char buffer[1024];
  const char *err;
  char *host = argv[1];
  int port = atoi(argv[2]);
  char *cafile = argv[3];

  gnutls_certificate_credentials_t xcred;

  gnutls_global_init ();

  /* X509 stuff */
  gnutls_certificate_allocate_credentials (&xcred);

  /* sets the trusted cas file
   */
  gnutls_certificate_set_x509_trust_file (xcred, cafile, GNUTLS_X509_FMT_PEM);
  gnutls_certificate_set_verify_function (xcred, _verify_certificate_callback);

  /* Initialize TLS session 
   */
  gnutls_init (&session, GNUTLS_CLIENT);
  gnutls_session_set_ptr (session, (void *) "my_host_name");

  gnutls_server_name_set (session, GNUTLS_NAME_DNS, "my_host_name", 
                          strlen("my_host_name"));

  /* Use default priorities */
  ret = gnutls_priority_set_direct (session, "NORMAL", &err);
  if (ret < 0)
    {
      if (ret == GNUTLS_E_INVALID_REQUEST)
        {
          fprintf (stderr, "Syntax error at: %s\n", err);
        }
      exit (1);
    }

  /* put the x509 credentials to the current session
   */
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  /* connect to the peer
   */
  sd = tcp_connect (host, port);

  gnutls_transport_set_int (session, sd);
  gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  /* Perform the TLS handshake
   */

  /* Perform the TLS handshake
   */
  do
    {
      ret = gnutls_handshake (session);
    }
  while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

  if (ret < 0)
    {
      if (ret != GNUTLS_E_CERTIFICATE_ERROR)
	      exit(1);
    }
  gnutls_record_send (session, "", strlen (""));

  ret = gnutls_record_recv (session, buffer, sizeof(buffer));


  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  printf("%d\n", verification_result);
end:

  close(sd);
  gnutls_deinit (session);

  gnutls_certificate_free_credentials (xcred);

  gnutls_global_deinit ();

  return 0;
}

