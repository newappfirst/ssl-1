#include <ctype.h>
#include "cryptlib.h"
#include "test/test.h"

#include "stdio.h"

#define TRACE(s, ...) fprintf(stderr, s, ##__VA_ARGS__)
#define CONNECT_OK  0

/*todo: print errors from util.c*/
int importCertFile( CRYPT_CERTIFICATE *cryptCert, const char* fileName ) {
	FILE *filePtr;
	char buffer[ BUFFER_SIZE ];
	int count;

	if( ( filePtr = fopen( convertFileName( fileName ), "rb" ) ) == NULL )
		return( CRYPT_ERROR_OPEN );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
    if( count == BUFFER_SIZE )	/* Item too large for buffer */
		return( CRYPT_ERROR_OVERFLOW );

	/* Import the certificate */
	return( cryptImportCert( buffer, count, CRYPT_UNUSED, cryptCert ) );

}


int main(int argc, char **argv) {
	char  *host = "https://www.pcwebshop.co.uk/";
	int   port  = 443;
	char  *cafile;
	int   status;
  char* serverName;

	CRYPT_CERTIFICATE cryptCert;
  CRYPT_SESSION cryptSession;

  if (argc == 4) {
    host = argv[1];
	  port = atoi(argv[2]);
	  cafile = argv[3];
  }

	printf("Testing Cryptlib\n");

  memset(&cryptSession, 0, sizeof(cryptSession));

  status = cryptInit();
  if (status != CONNECT_OK) {
    TRACE("Failed to initialize library : %d\n", status);
    return -1;
  }


  //Create the session
  status = cryptCreateSession(&cryptSession, CRYPT_UNUSED, CRYPT_SESSION_SSL );
  if (status != CONNECT_OK) {
    TRACE("Failed to crate session : %d\n", status);
    return -1;
  }


  serverName = host;
  status = cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_SERVER_NAME, serverName,
								paramStrlen( serverName ) );
  if (status != CONNECT_OK) {
    TRACE("Failed cryptSetAttribute CRYPT_SESSINFO_SERVER_NAME: %d\n", status);
    return -1;
  }


  //Specify the Port
  status = cryptSetAttribute( cryptSession,
								CRYPT_SESSINFO_SERVER_PORT,
                443 );
  if (status != CONNECT_OK) {
    TRACE("Failed cryptSetAttribute CRYPT_SESSINFO_SERVER_PORT: %d\n", status);
    return -1;
  }

  // Activate the session
  status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
  if (status != CONNECT_OK) {
    printf("Failed to setup connection : %d\n", status);
  }
  else {
    printf("%d\n",CONNECT_OK);
  }

  return CONNECT_OK;

}
