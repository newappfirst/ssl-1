#include <stdio.h>
#include <stdlib.h>

#include <ctype.h>
#include "cryptlib.h"

#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

#define BUFFER_SIZE			16384


int import_cert_file( CRYPT_CERTIFICATE *cryptCert, const char* fileName ) {
	FILE *filePtr;
	char buffer[ BUFFER_SIZE ];
	int count;

	if( ( filePtr = fopen(fileName, "rb" ) ) == NULL )
		return( CRYPT_ERROR_OPEN );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
    if( count == BUFFER_SIZE )	/* Item too large for buffer */
		return( CRYPT_ERROR_OVERFLOW );

	/* Import the certificate */
	return( cryptImportCert( buffer, count, CRYPT_UNUSED, cryptCert ) );

}

int add_globally_trusted_cert(CRYPT_CERTIFICATE *trustedCert, C_STR fileName) {

	int status;

	/* Read the CA root certificate and make it trusted */
	status = import_cert_file(trustedCert, fileName);
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

  //puts( "Globally trusted certificate add succeeded.\n" );
	return( TRUE );
}

int delete_globally_trusted_cert(CRYPT_CERTIFICATE trustedCert) {
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


