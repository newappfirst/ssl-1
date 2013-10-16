
#include <stdio.h>
#include <stdlib.h>

#include <ctype.h>
#include "cryptlib.h"
#include "test/test.h"


extern int add_globally_trusted_cert(CRYPT_CERTIFICATE *trustedCert, C_STR fileTemplate);
extern int delete_globally_trusted_cert(CRYPT_CERTIFICATE trustedCert);

#define __DETAILED__
#define TRACE(s, ...) fprintf(stderr, s, ##__VA_ARGS__)


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

  memset(&cryptSession, 0, sizeof(cryptSession));

  status = cryptInit();
  if (status != CRYPT_OK) {
    TRACE("Failed to initialize library : %d\n", status);
    return -1;
  }

  if(add_globally_trusted_cert(&trustedCert, cafile) == FALSE) {
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
                             CRYPT_SESSINFO_SERVER_PORT, port );
  if (status != CRYPT_OK) {
    TRACE("Failed cryptSetAttribute CRYPT_SESSINFO_SERVER_PORT: %d\n", status);
    return -1;
  }

  // Activate the session
  status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );

  if( cryptStatusError( status ) ) {
    if (status == CRYPT_ERROR_INVALID) {
      printf("%d\n",CRYPT_ERROR_INVALID);


#ifdef __DETAILED__

      BYTE buffer[ 1024 ];
    	int length;

      status = cryptGetAttributeString( cryptSession,
									CRYPT_ATTRIBUTE_ERRORMESSAGE, buffer,
									&length );

      puts(buffer);

      CRYPT_CERTIFICATE cryptCertificate;

      status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE, &cryptCertificate );


      if( cryptStatusError( status ) ) {
        TRACE( "Couldn't get certificate, status %d, line %d.\n",
					status, __LINE__ );
        return 0;
			}
      int errorType, errorLocus;

      status = cryptGetAttribute( cryptCertificate, CRYPT_ATTRIBUTE_ERRORTYPE,
									&errorType );
      printf("errorType = %d\n", errorType);

      if( cryptStatusError( status ) ) {
        status = cryptGetAttribute( cryptCertificate,
										CRYPT_ATTRIBUTE_ERRORLOCUS,
										&errorLocus );
        printf("errorLocus = %d\n", errorLocus);
      }

      /*if( cryptStatusOK( status ) && \
			errorType == CRYPT_ERRTYPE_CONSTRAINT && \
			errorLocus == CRYPT_CERTINFO_VALIDFROM )
      */

#endif
      return 0;

    }
    else {
      TRACE("Failed to setup connection : %d\n", status);
      return -1;
    }
  }
  else
    printf("%d\n",CRYPT_OK);


  delete_globally_trusted_cert(trustedCert);
  return CRYPT_OK;

}


