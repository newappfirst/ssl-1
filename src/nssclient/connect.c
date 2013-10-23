//Most of the code stripped from http://docs.fedoraproject.org/
//en-US/Fedora_Security_Teamx/html/Defensive_Coding/sect-Defensive
//_Coding-TLS-Client-NSS.html
// NSPR include files
#include <nspr/prerror.h>
#include <nspr/prinit.h>

// NSS include files
#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/pkcs11.h>
#include <nss/secmod.h>
#include <nss/ssl.h>
#include <nss/sslproto.h>

#define MAX_STRING 200
#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
                (x)->pValue=(v); (x)->ulValueLen = (l);
// Private API, no other way to turn a POSIX file descriptor into an
// NSPR handle.
NSPR_API(PRFileDesc*) PR_ImportTCPSocket(int);

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

static SECStatus bad_cert_handler(void *arg, PRFileDesc *ssl)
{
	SECStatus success = SECSuccess;
	PRErrorCode err;
	int *is_good = (int *)arg;

	*is_good = 0;
	if (!ssl) {
		return SECFailure;
	}

	err = PORT_GetError();
	fprintf(stdout, "%d\n", err);
	/* Return success here irrespective of the result, as
           the result is printed above*/
	return success;
}

/* Function taken from curl source code*/
static int nss_load_cert(const char *filename)
{
	CK_SLOT_ID slotID;
	PK11SlotInfo * slot = NULL;
	PK11GenericObject *rv;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE theTemplate[20];
	CK_BBOOL cktrue = CK_TRUE;
	CK_BBOOL ckfalse = CK_FALSE;
	CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
	char slotname[MAX_STRING];
	CERTCertificate *cert;
	char *n = NULL;

	attrs = theTemplate;

	/* All CA and trust objects go into slot 0.*/ 
	slotID = 0;

	snprintf(slotname, 100, "PEM Token #%ld", slotID);

	slot = PK11_FindSlotByName(slotname);

	if(!slot) {
		return -1;
	}

	PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) );
	attrs++;
	PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) );
	attrs++;
	PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)filename,
                strlen(filename)+1);
	attrs++;
	PK11_SETATTRS(attrs, CKA_TRUST, &cktrue, sizeof(CK_BBOOL) );
	attrs++;

	/* This load the certificate in our PEM module into the appropriate
	* slot.
	*/
	rv = PK11_CreateGenericObject(slot, theTemplate, 4, PR_FALSE /* isPerm */);

	PK11_FreeSlot(slot);

	if(rv == NULL) {
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	NSSInitContext *ctx;
	PRErrorCode err;
	PRInt32 policy;
	PRUint16 *p;
	char *host;
	int port;
	char *cacertpath;
	char configstring[MAX_STRING];
	SECMODModule* mod = NULL;

	if (argc!=4) {
		fprintf(stderr, "Incorrect no. of arguments..exiting\n");
		return -1;
	}
	host = argv[1];
	port = atoi(argv[2]);
	cacertpath = argv[3];

	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
#ifdef NSS_ENABLE_PEM
	ctx = NSS_InitContext("", "", "", "", NULL,
			    NSS_INIT_READONLY | NSS_INIT_NOCERTDB);
#else
	ctx = NSS_InitContext(cacertpath, "", "", "", NULL,
			    NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
#endif
	if (ctx == NULL) {
		err = PR_GetError();
		fprintf(stderr, "error: NSPR error code %d: %s\n",
			err, PR_ErrorToName(err));
		return -1;
	}


	if (NSS_SetDomesticPolicy() != SECSuccess) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: NSS_SetDomesticPolicy: error %d: %s\n",
		      err, PR_ErrorToName(err));
		return -1;
	}

#ifdef NSS_ENABLE_PEM
	sprintf(configstring, "library=%s name=PEM", "libnsspem.so");
	mod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);

	if(!mod || !mod->loaded) {
		if(mod) {
			SECMOD_DestroyModule(mod);
			mod = NULL;
		}
		fprintf(stderr,"ERROR: failed to load NSS PEM library");
		return -1;
	}
	
	// Initialize the trusted certificate store.
	if (nss_load_cert(cacertpath)!=0) {
		fprintf(stderr, "error: Couldn't load the CA cert\n");
	  	return -1;
	}
#endif

	char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
	SECMODModule *module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
	if (module == NULL || !module->loaded) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: NSPR error code %d: %s\n",
			err, PR_ErrorToName(err));
	  	return -1;
	}

	int sockfd = tcp_connect(host, port);
	// Wrap the POSIX file descriptor.  This is an internal NSPR
	// function, but it is very unlikely to change.
	PRFileDesc* nspr = PR_ImportTCPSocket(sockfd);
	sockfd = -1; // Has been taken over by NSPR.

	// Add the SSL layer.
	PRFileDesc *model = PR_NewTCPSocket();
	PRFileDesc *newfd = SSL_ImportFD(NULL, model);
	if (newfd == NULL) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: NSPR error code %d: %s\n",
			err, PR_ErrorToName(err));
		return -1;
	}
	model = newfd;
	newfd = NULL;
	int is_cert_good = 1;
	
	// Need to hook the certificate handler to get the error code.
	if (SSL_BadCertHook(model, bad_cert_handler, (char *)(&is_cert_good)) != SECSuccess) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: SSL_BadCertHook error %d: %s\n",
		      err, PR_ErrorToName(err));
		return -1;
	}


	newfd = SSL_ImportFD(model, nspr);
	if (newfd == NULL) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
			err, PR_ErrorToName(err));
		return -1;
	}
	nspr = newfd;
	PR_Close(model);

	// Perform the handshake.
	if (SSL_ResetHandshake(nspr, PR_FALSE) != SECSuccess) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
			err, PR_ErrorToName(err));
		return -1;
	}
	if (SSL_SetURL(nspr, host) != SECSuccess) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
			err, PR_ErrorToName(err));
		return -1;
	}
	if (SSL_ForceHandshake(nspr) != SECSuccess) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
			err, PR_ErrorToName(err));
		return -1;
	}

	if (is_cert_good)
		fprintf(stdout, "%d\n", 0);

	// Closes the underlying POSIX file descriptor, too.
	PR_Close(nspr);
	return 0;
}

