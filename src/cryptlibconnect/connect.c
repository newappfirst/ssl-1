#include <ctype.h>
#include "cryptlib.h"
#include "test/test.h"

#include "stdio.h"

#define TRACE(s, ...) fprintf(stderr, s, ##__VA_ARGS__)

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





int AddGloballyTrustedCert(CRYPT_CERTIFICATE *trustedCert, C_STR fileTemplate) {
	int status;

	/* Read the CA root certificate and make it trusted */
	status = importCertFromTemplate(trustedCert, fileTemplate, 1 );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of trusted "
			  "certificate write..." );
		return( TRUE );
		}
	cryptSetAttribute( *trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );

	/* Update the config file with the globally trusted certificate */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Globally trusted certificate add failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	puts( "Globally trusted certificate add succeeded.\n" );
	return( TRUE );
}

int DeleteGloballyTrustedCert(CRYPT_CERTIFICATE trustedCert) {
	int status;

	/* Make the certificate untrusted and update the config again */
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Globally trusted certificate delete failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
}


int importCertFromTemplate( CRYPT_CERTIFICATE *cryptCert,
							const C_STR fileTemplate, const int number )
	{
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */

	filenameFromTemplate( filenameBuffer, fileTemplate, number );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	return( importCertFile( cryptCert, wcBuffer ) );
#else
	return( importCertFile( cryptCert, filenameBuffer ) );
#endif /* UNICODE_STRINGS */
	}


int main(int argc, char **argv) {
	char  *host = "https://www.pcwebshop.co.uk/";
	int   port  = 443;
	char  *cafile;
	int   status;
  char* serverName;


	CRYPT_CERTIFICATE cryptCert;
  CRYPT_SESSION cryptSession;
  CRYPT_CERTIFICATE trustedCert;
  CRYPT_ATTRIBUTE_TYPE errorLocus;
  CRYPT_ERRTYPE_TYPE errorType;

  if (argc == 4) {
    host = argv[1];
	  port = atoi(argv[2]);
	  cafile = argv[3];
  }  else {
    printf("!!Incorrect arguments");
    return -1;
  }

	printf("Testing Cryptlib\n");

  memset(&cryptSession, 0, sizeof(cryptSession));

  status = cryptInit();
  if (status != CRYPT_OK) {
    TRACE("Failed to initialize library : %d\n", status);
    return -1;
  }

  if(AddGloballyTrustedCert(&trustedCert, cafile) == FALSE) {
    return -1;
  }

  //Create the session
  status = cryptCreateSession(&cryptSession, CRYPT_UNUSED, CRYPT_SESSION_SSL );
  if (status != CRYPT_OK) {
    TRACE("Failed to crate session : %d\n", status);
    return -1;
  }


  serverName = host;
  status = cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_SERVER_NAME, serverName,
								paramStrlen( serverName ) );
  if (status != CRYPT_OK) {
    TRACE("Failed cryptSetAttribute CRYPT_SESSINFO_SERVER_NAME: %d\n", status);
    return -1;
  }


  //Specify the Port
  status = cryptSetAttribute( cryptSession,
								CRYPT_SESSINFO_SERVER_PORT,
                port );
  if (status != CRYPT_OK) {
    TRACE("Failed cryptSetAttribute CRYPT_SESSINFO_SERVER_PORT: %d\n", status);
    return -1;
  }

  // Activate the session
  status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) ) {
    if (status == CRYPT_ERROR_INVALID) {
      printf("%d\n",CRYPT_ERROR_INVALID);
      /*
       * Todo: if we need to know the reason :
       * CRYPT_CERTIFICATE cryptCertificate;
       * cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE, &cryptCertificate );
       */
      return 0;
    }
    else {
      TRACE("Failed to setup connection : %d\n", status);
      return -1;
    }
  }
  else
    printf("%d\n",CRYPT_OK);


  DeleteGloballyTrustedCert(trustedCert);
  return CRYPT_OK;

}
