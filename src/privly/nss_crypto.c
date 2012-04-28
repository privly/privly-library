/**
 * Implementation of the Privly crypto interface, using Mozilla NSS library.
 *
 * TODO:
 * [2012/04/08:jhostetler] Use consistent memory allocation mechanism throughout:
 * https://developer.mozilla.org/en/Choosing_the_right_memory_allocator
 *
 * [2012/04/09:jhostetler] Do we want to use InternalKeySlot() or 
 * BestSlot( mech )? For some wrapping operations, we have to move keys so 
 * that they're on the same slot, which requires that we wrap the private 
 * keys. This is straightforward, but it requires work.
 *
 * [2012/04/09:jhostetler] SECItems should have the .type field set (e.g. siBuffer).
 */

#include "privly/ccrypto.h"

#include <nss/nss.h>
#include <nss/nssbase.h>
#include <nss/cert.h>
/* #include <nss/certdb.h> */
#include <nss/cryptohi.h>
#include <nss/keyhi.h>
#include <nss/pk11pub.h>
#include <nss/pk11priv.h>
#include <nss/sechash.h>

#include <assert.h>
#include <limits.h>

/* ---------------------------------------------------------------------------
 * Global constants
 * -------------------------------------------------------------------------*/

/* TODO: These defaults need to be in the protocol spec. */
#define privly_HASH_ALGORITHM 		HASH_AlgSHA512
#define privly_HASH_LENGTH			SHA512_LENGTH
#define privly_RSA_KEYGEN_PE		65537L

/* NSS has no "invalid" CK_MECHANISM_TYPE; this one appears to be unused. */
static CK_MECHANISM_TYPE const CKM_INVALID = (CK_MECHANISM_TYPE) -1; 

/* ---------------------------------------------------------------------------
 * PostData datatype
 * -------------------------------------------------------------------------*/

/**
 * Data that we need to keep track of for each post.
 */
struct PostData
{
	enum privly_PostKeyType type;
	PK11SymKey* key;
	CK_MECHANISM_TYPE mechanism;
	int key_size;
	int block_size;
	
	SECItem* iv_param;
	
	int kdf_iterations;
	SECItem* salt_item;
};

/**
 * PostData constructor.
 */
static struct PostData* 
PostData_New( enum privly_PostKeyType type, PK11SymKey* key, CK_MECHANISM_TYPE mechanism, 
			  int key_size, int block_size, SECItem* iv_param, 
			  int kdf_iterations, SECItem* salt_item )
{
	struct PostData* pd = (struct PostData*) malloc( sizeof( struct PostData ) );
	if( !pd ) {
		return NULL;
	}
	
	pd->type = type;
	pd->key = key;
	pd->mechanism = mechanism;
	pd->key_size = key_size;
	pd->block_size = block_size;
	pd->iv_param = iv_param;
	pd->kdf_iterations = kdf_iterations;
	pd->salt_item = salt_item;
	
	return pd;
}

/**
 * Free PostData.
 */
static void PostData_Free( struct PostData* post_data )
{
	if( post_data->key ) {
		PK11_FreeSymKey( post_data->key );
	}
	if( post_data->iv_param ) {
		SECITEM_FreeItem( post_data->iv_param, PR_TRUE );
	}
	if( post_data->salt_item ) {
		SECITEM_FreeItem( post_data->salt_item, PR_TRUE );
	}
	
	free( post_data );
}

/* ---------------------------------------------------------------------------
 * Session datatype
 * -------------------------------------------------------------------------*/

/**
 * Linked list node for PostData.
 */
struct PostDataNode
{
	privly_postid_t id;
	struct PostData* data;
	struct PostDataNode* next;
};

/**
 * Stores the state of the current session.
 */
struct Session
{
	char* username;
	char* passphrase;
	
	struct PostDataNode* post_data_list;
};

static struct Session* Session_New( char const* username, char const* passphrase )
{
	struct Session* session = (struct Session*) malloc( sizeof( struct Session ) );
	if( !session ) {
		return NULL;
	}
	
	session->username = PL_strdup( username );
	session->passphrase = PL_strdup( passphrase );
	session->post_data_list = NULL;
	
	return session;
}

static void Session_Free( struct Session* session )
{
	struct PostDataNode* head = session->post_data_list;
	struct PostDataNode* lag = NULL;
	
	while( head ) {
		free( head->data );
		lag = head;
		head = head->next;
		free( lag );
	}
	
	PL_strfree( session->username );
	PL_strfree( session->passphrase );
}

static struct PostData* Session_GetPostData( struct Session* session, privly_postid_t post_id )
{
	struct PostData* data = NULL;
	struct PostDataNode* head = session->post_data_list;
	
	while( head ) {
		if( head->id == post_id ) {
			data = head->data;
			break;
		}
		
		head = head->next;
	}
	
	return data;
}

/**
 * 'data' must have been allocated with malloc(). Session takes ownership of 'data'
 */
static int Session_SetPostData( struct Session* session, privly_postid_t post_id, struct PostData* data )
{
	struct PostDataNode* new_head = (struct PostDataNode*) malloc( sizeof(struct PostDataNode) );
	if( !new_head ) {
		return PRIVLY_CRYPTO_OUT_OF_MEMORY;
	}
	
	new_head->id = post_id;
	new_head->data = data;
	new_head->next = session->post_data_list;
	session->post_data_list = new_head;
	
	return PRIVLY_CRYPTO_SUCCESS;
}

/**
 * The PostData object is freed, if it is present.
 */
static void Session_ForgetPostData( struct Session* session, privly_postid_t post_id )
{
	struct PostDataNode* head = session->post_data_list;
	struct PostDataNode* lag = NULL;
	while( head ) {
		if( head->id == post_id ) {
			if( lag ) {
				lag->next = head->next;
			}
			
			free( head->data );
			free( head );
			break;
		}
		
		lag = head;
		head = head->next;
	}
}

/* ---------------------------------------------------------------------------
 * Free functions
 * -------------------------------------------------------------------------*/

/**
 * Compute a passphrase hash using the default hash mechanism.
 */
static SECStatus hash_passphrase( char const* passphrase, unsigned char* hashed )
{
	int const len = PL_strlen( passphrase );
	SECStatus status = HASH_HashBuf( privly_HASH_ALGORITHM, hashed, (unsigned char*) passphrase, len );
	return status;
}

/* -------------------------------------------------------------------------*/

/**
 * Translates a Privly cipher algorithm ID to an NSS CK_MECHANISM_TYPE.
 *
 * Returns our made-up value 'CKM_INVALID' on failure.
 */
static CK_MECHANISM_TYPE privly_cipher_to_ckm( enum privly_CipherAlgorithm algorithm )
{
	switch( algorithm ) {
	case PRIVLY_CRYPTO_CIPHER_AES_CBC:
		return CKM_AES_CBC_PAD;
	default:
		return CKM_INVALID;
	}
}

/* -------------------------------------------------------------------------*/

/**
 * Creates a random initialization vector of length 'bytes' for a cipher
 * using mechanism 'cipher_mech'. Random numbers are generated with NSS via
 * 'PK11_GenerateRandom()'.
 */
static SECItem* make_initialization_vector( CK_MECHANISM_TYPE cipher_mech, int bytes )
{
	SECStatus status = SECSuccess;
	SECItem* sec_param = NULL;
	SECItem* iv_item = NULL;
	
	iv_item = SECITEM_AllocItem( NULL, NULL, bytes );
	if( !iv_item ) {
		return NULL;
	}
	
	status = PK11_GenerateRandom( iv_item->data, bytes );
	if( SECSuccess != status ) {
		SECITEM_FreeItem( iv_item, PR_TRUE );
		return NULL;
	}
	
	sec_param = PK11_ParamFromIV( cipher_mech, iv_item );
	SECITEM_FreeItem( iv_item, PR_TRUE );
	return sec_param;
}

/* -------------------------------------------------------------------------*/

/**
 * Computes a random salt of length 'bytes' and stores it in an SECItem.
 */
static SECItem* make_salt( int bytes )
{
	SECStatus status = SECSuccess;
	SECItem* salt_item = SECITEM_AllocItem( NULL, NULL, bytes );
	if( !salt_item ) {
		return NULL;
	}
	
	status = PK11_GenerateRandom( salt_item->data, salt_item->len );
	if( SECSuccess != status ) {
		SECITEM_FreeItem( salt_item, PR_TRUE );
		return NULL;
	}
	
	return salt_item;
}

/* -------------------------------------------------------------------------*/

/**
 * Derives a symmetric key from a passphrase hash and some KDF parameters.
 */
static int derive_key( void* session, unsigned char* passphrase_hash, 
					   int iterations, SECItem* salt, PK11SymKey** key )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	PK11SlotInfo* slot = NULL;
	SECItem* passphrase_item = NULL;
	SECAlgorithmID* kdf = NULL;
	
	passphrase_item = SECITEM_AllocItem( NULL, NULL, privly_HASH_LENGTH );
	if( !passphrase_item ) {
		rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
		goto cleanup;
	}
	memcpy( passphrase_item->data, passphrase_hash, privly_HASH_LENGTH );
	
	slot = PK11_GetInternalKeySlot(); /* TODO: ? PK11_GetBestSlot( CKM_AES_CBC, NULL ); */
	if( !slot ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	kdf = PK11_CreatePBEV2AlgorithmID( SEC_OID_PKCS5_PBKDF2,	/* We want to specify cipher/MAC */
									   SEC_OID_AES_256_CBC,		/* Cipher algorithm */
									   SEC_OID_HMAC_SHA1,		/* HMAC algorithm */
									   256 / 8,					/* Key length */
									   iterations, salt );
	if( !kdf ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	*key = PK11_PBEKeyGen( slot, kdf, passphrase_item, PR_FALSE, session );
	if( !*key ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
cleanup:
	if( kdf ) {
		SECOID_DestroyAlgorithmID( kdf, PR_TRUE );
	}
	if( passphrase_item ) {
		SECITEM_FreeItem( passphrase_item, PR_TRUE );
	}
	if( slot ) {
		PK11_FreeSlot( slot );
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/

/**
 * Looks up a private key in the database by nickname. If there is no such key
 * in the database, the function returns PRIVLY_CRYPTO_SUCCESS but
 * 'private_key' is set to NULL.
 */
int get_private_key( void* session, char const* nickname, SECKEYPrivateKey** private_key )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	PK11SlotInfo* slot = NULL;
	SECKEYPrivateKeyList* private_key_list = NULL;
	SECKEYPrivateKeyListNode* list_node = NULL;
	char const* tmp_nickname = NULL;
	
	slot = PK11_GetInternalKeySlot(); /* TODO: GetBestSlot() */
	if( !slot ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	private_key_list = PK11_ListPrivKeysInSlot( slot, nickname, session );
	if( !private_key_list ) {
		/* No key found. */
		*private_key = NULL;
		rv = PRIVLY_CRYPTO_SUCCESS;
		goto cleanup;
	}
	
	for( list_node = PRIVKEY_LIST_HEAD( private_key_list ); 
		 !PRIVKEY_LIST_END( list_node, private_key_list ); 
		 list_node = PRIVKEY_LIST_NEXT( list_node ) )
	{
		tmp_nickname = PK11_GetPrivateKeyNickname( list_node->key );
		if( PL_strcmp( nickname, tmp_nickname ) == 0 ) {
			break;
		}
	}
	if( PRIVKEY_LIST_END( list_node, private_key_list ) ) {
		/* No key found. */
		*private_key = NULL;
		rv = PRIVLY_CRYPTO_SUCCESS;
		goto cleanup;
	}
	
	*private_key = SECKEY_CopyPrivateKey( list_node->key );
	if( !*private_key ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
cleanup:
	if( private_key_list ) {
		SECKEY_DestroyPrivateKeyList( private_key_list );
	}
	if( slot ) {
		PK11_FreeSlot( slot );
	}
	
	return rv;
}

/* ---------------------------------------------------------------------------
 * These CERT functions are lightly modified versions of functions of the
 * same names from 'certutil.c' in the NSS distribution.
 * -------------------------------------------------------------------------*/

#if 0
 
static certutilExtnList nullextnlist = {{PR_FALSE, NULL}};
 
/**
 * Creates a certificate request and outputs it to a file.
 */
static SECStatus
CertReq( SECKEYPrivateKey *privk, SECKEYPublicKey *pubk, KeyType keyType,
		 SECOidTag hashAlgTag, CERTName *subject, char *phone, int ascii,
		 const char *emailAddrs, const char *dnsNames, certutilExtnList extnList,
		 PRFileDesc *outFile )
{
    CERTSubjectPublicKeyInfo *spki;
    CERTCertificateRequest *cr;
    SECItem *encoding;
    SECOidTag signAlgTag;
    SECItem result;
    SECStatus rv;
    PRArenaPool *arena;
    PRInt32 numBytes;
    void *extHandle;

    /* Create info about public key */
    spki = SECKEY_CreateSubjectPublicKeyInfo(pubk);
    if (!spki) {
	SECU_PrintError(progName, "unable to create subject public key");
	return SECFailure;
    }
    
    /* Generate certificate request */
    cr = CERT_CreateCertificateRequest(subject, spki, NULL);
    SECKEY_DestroySubjectPublicKeyInfo(spki);
    if (!cr) {
	SECU_PrintError(progName, "unable to make certificate request");
	return SECFailure;
    }

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if ( !arena ) {
	SECU_PrintError(progName, "out of memory");
	return SECFailure;
    }
    
    extHandle = CERT_StartCertificateRequestAttributes(cr);
    if (extHandle == NULL) {
        PORT_FreeArena (arena, PR_FALSE);
	return SECFailure;
    }
    if (AddExtensions(extHandle, emailAddrs, dnsNames, extnList)
                  != SECSuccess) {
        PORT_FreeArena (arena, PR_FALSE);
        return SECFailure;
    }
    CERT_FinishExtensions(extHandle);
    CERT_FinishCertificateRequestAttributes(cr);

    /* Der encode the request */
    encoding = SEC_ASN1EncodeItem(arena, NULL, cr,
                                  SEC_ASN1_GET(CERT_CertificateRequestTemplate));
    CERT_DestroyCertificateRequest(cr);
    if (encoding == NULL) {
	PORT_FreeArena (arena, PR_FALSE);
	SECU_PrintError(progName, "der encoding of request failed");
	return SECFailure;
    }

    /* Sign the request */
    signAlgTag = SEC_GetSignatureAlgorithmOidTag(keyType, hashAlgTag);
    if (signAlgTag == SEC_OID_UNKNOWN) {
	PORT_FreeArena (arena, PR_FALSE);
	SECU_PrintError(progName, "unknown Key or Hash type");
	return SECFailure;
    }
    rv = SEC_DerSignData(arena, &result, encoding->data, encoding->len, 
			 privk, signAlgTag);
    if (rv) {
	PORT_FreeArena (arena, PR_FALSE);
	SECU_PrintError(progName, "signing of data failed");
	return SECFailure;
    }

    /* Encode request in specified format */
    if (ascii) {
	char *obuf;
	char *name, *email, *org, *state, *country;
	SECItem *it;
	int total;

	it = &result;

	obuf = BTOA_ConvertItemToAscii(it);
	total = PL_strlen(obuf);

	name = CERT_GetCommonName(subject);
	if (!name) {
	    name = PORT_Strdup("(not specified)");
	}

	if (!phone)
	    phone = strdup("(not specified)");

	email = CERT_GetCertEmailAddress(subject);
	if (!email)
	    email = PORT_Strdup("(not specified)");

	org = CERT_GetOrgName(subject);
	if (!org)
	    org = PORT_Strdup("(not specified)");

	state = CERT_GetStateName(subject);
	if (!state)
	    state = PORT_Strdup("(not specified)");

	country = CERT_GetCountryName(subject);
	if (!country)
	    country = PORT_Strdup("(not specified)");

	PR_fprintf(outFile, 
	           "\nCertificate request generated by Netscape certutil\n");
	PR_fprintf(outFile, "Phone: %s\n\n", phone);
	PR_fprintf(outFile, "Common Name: %s\n", name);
	PR_fprintf(outFile, "Email: %s\n", email);
	PR_fprintf(outFile, "Organization: %s\n", org);
	PR_fprintf(outFile, "State: %s\n", state);
	PR_fprintf(outFile, "Country: %s\n\n", country);

	PORT_Free(name);
	PORT_Free(email);
	PORT_Free(org);
	PORT_Free(state);
	PORT_Free(country);

	PR_fprintf(outFile, "%s\n", NS_CERTREQ_HEADER);
	numBytes = PR_Write(outFile, obuf, total);
	PORT_Free(obuf);
	if (numBytes != total) {
	    PORT_FreeArena (arena, PR_FALSE);
	    SECU_PrintError(progName, "write error");
	    return SECFailure;
	}
	PR_fprintf(outFile, "\n%s\n", NS_CERTREQ_TRAILER);
    } else {
	numBytes = PR_Write(outFile, result.data, result.len);
	if (numBytes != (int)result.len) {
	    PORT_FreeArena (arena, PR_FALSE);
	    SECU_PrintSystemError(progName, "write error");
	    return SECFailure;
	}
    }
    PORT_FreeArena (arena, PR_FALSE);
    return SECSuccess;
}
 
static CERTCertificate*
MakeV1Cert(	CERTCertDBHandle* handle, CERTCertificateRequest* req,
	    	char const* issuerNickName, PRBool selfsign, unsigned int serialNumber,
			int warpmonths, int validityMonths )
{
    CERTCertificate* issuerCert = NULL;
    CERTValidity* validity;
    CERTCertificate* cert = NULL;
    PRExplodedTime printableTime;
    PRTime now, after;

    if( !selfsign ) {
		issuerCert = CERT_FindCertByNicknameOrEmailAddr( handle, issuerNickName );
		if( !issuerCert ) {
			return NULL;
		}
    }

	/* Construct validity time range. */
    now = PR_Now();
    PR_ExplodeTime( now, PR_GMTParameters, &printableTime );
    if( 0 != warpmonths ) {
		printableTime.tm_month += warpmonths;
		now = PR_ImplodeTime( &printableTime );
		PR_ExplodeTime( now, PR_GMTParameters, &printableTime );
    }
    printableTime.tm_month += validityMonths;
    after = PR_ImplodeTime( &printableTime );

    /* note that the time is now in micro-second unit */
    validity = CERT_CreateValidity( now, after );
    if( validity ) {
        cert = CERT_CreateCertificate( serialNumber, 
									   (selfsign ? &req->subject : &issuerCert->subject), 
									   validity, req );
    
        CERT_DestroyValidity( validity );
    }
    if( issuerCert ) {
		CERT_DestroyCertificate (issuerCert);
    }
    
    return cert;
}

static SECStatus
CreateCert( CERTCertDBHandle* handle, PK11SlotInfo* slot, char const* issuerNickName, 
			PRFileDesc* inFile, PRFileDesc* outFile, SECKEYPrivateKey** selfsignprivkey,
			void* pwarg, SECOidTag hashAlgTag, unsigned int serialNumber, 
			int warpmonths, int validityMonths, char const* emailAddrs,
			char const* dnsNames, PRBool ascii, PRBool selfsign, certutilExtnList extnList )
{
    void *	extHandle;
    SECItem *	certDER;
    CERTCertificate *subjectCert 	= NULL;
    CERTCertificateRequest *certReq	= NULL;
    SECStatus 	rv 			= SECSuccess;
    SECItem 	reqDER;
    CERTCertExtension **CRexts;
	SECStatus status = SECSuccess;

    reqDER.data = NULL;
    
	/* Create a certrequest object from the input cert request der */
	certReq = GetCertRequest(inFile, ascii);
	if (certReq == NULL) {
	    status = SECFailure)
	}

	subjectCert = MakeV1Cert (handle, certReq, issuerNickName, selfsign,
				  serialNumber, warpmonths, validityMonths);
	if (subjectCert == NULL) {
	    GEN_BREAK (SECFailure)
	}
        
        
	extHandle = CERT_StartCertExtensions (subjectCert);
	if (extHandle == NULL) {
	    GEN_BREAK (SECFailure)
	}
        
        rv = AddExtensions(extHandle, emailAddrs, dnsNames, extnList);
        if (rv != SECSuccess) {
	    GEN_BREAK (SECFailure)
	}
        
        if (certReq->attributes != NULL &&
	    certReq->attributes[0] != NULL &&
	    certReq->attributes[0]->attrType.data != NULL &&
	    certReq->attributes[0]->attrType.len   > 0    &&
            SECOID_FindOIDTag(&certReq->attributes[0]->attrType)
                == SEC_OID_PKCS9_EXTENSION_REQUEST) {
            rv = CERT_GetCertificateRequestExtensions(certReq, &CRexts);
            if (rv != SECSuccess)
                break;
            rv = CERT_MergeExtensions(extHandle, CRexts);
            if (rv != SECSuccess)
                break;
        }

	CERT_FinishExtensions(extHandle);

	/* self-signing a cert request, find the private key */
	if (selfsign && *selfsignprivkey == NULL) {
	    *selfsignprivkey = PK11_FindKeyByDERCert(slot, subjectCert, pwarg);
	    if (!*selfsignprivkey) {
		fprintf(stderr, "Failed to locate private key.\n");
		rv = SECFailure;
		break;
	    }
	}

	certDER = SignCert(handle, subjectCert, selfsign, hashAlgTag,
	                   *selfsignprivkey, issuerNickName,pwarg);

	if (certDER) {
	   if (ascii) {
		PR_fprintf(outFile, "%s\n%s\n%s\n", NS_CERT_HEADER, 
		           BTOA_DataToAscii(certDER->data, certDER->len), 
			   NS_CERT_TRAILER);
	   } else {
		PR_Write(outFile, certDER->data, certDER->len);
	   }
	}

    } while (0);
	
cleanup:
    CERT_DestroyCertificateRequest( certReq );
    CERT_DestroyCertificate( subjectCert );
    if( SECSuccess != rv ) {
		PRErrorCode  perr = PR_GetError();
			fprintf(stderr, "%s: unable to create cert (%s)\n", progName,
				   SECU_Strerror(perr));
    }
	
    return rv;
}

#endif

/* -------------------------------------------------------------------------*/

/**
 * Callback used by NSS to get the user's passphrase.
 */
static char* privly_passphrase_callback( PK11SlotInfo* info, PRBool retry, void* arg )
{
	struct Session* session = (struct Session*) arg;
	
	if( !retry ) {
		/* Returned string must be allocated with PR_Malloc or PL_strdup.
		https://developer.mozilla.org/en/NSS_PKCS11_Functions */
		return PL_strdup( session->passphrase );
	}
	else {
		return NULL;
	}
}

/* ---------------------------------------------------------------------------
 * API functions
 * -------------------------------------------------------------------------*/

int PRIVLY_EXPORT 
privly_CreateSession( char const* config_dir, char const* username, 
					  char const* passphrase, void** session )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	struct Session* typed_session = NULL;
	SECStatus status = SECSuccess;

	/* Initialize with read-write key database. */
	status = NSS_InitReadWrite( config_dir );
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_INIT_FAIL;
		goto cleanup;
	}
	
	/* Set "domestic" export control mode.
	TODO: Look into whether we need to use "export" mode for Web-distributed software
	TODO: Why isn't this necessary if we only want to use PK11_* functions?	*/
	/*
	status = NSS_SetDomesticPolicy();
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_INIT_FAIL;
		goto cleanup;
	}
	*/
	
	typed_session = Session_New( username, passphrase );
	if( !typed_session ) {
		rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
		goto cleanup;
	}
	*session = (void*) typed_session;
	
	/* Passphrase callback. */
	PK11_SetPasswordFunc( privly_passphrase_callback );
	
cleanup:
	if( PRIVLY_CRYPTO_SUCCESS != rv && typed_session ) {
		/* Return NULL session on failure. */
		Session_Free( typed_session );
		*session = NULL;
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_DestroySession( void* session )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	struct Session* typed_session = (struct Session*) session;
	
	Session_Free( typed_session );
	
	status = NSS_Shutdown();
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_SHUTDOWN_FAIL;
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_CreatePostKey( void* session, privly_postid_t post_id, 
					  struct privly_AlgorithmDescriptor* cipher )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	PK11SlotInfo* slot = NULL;
	PK11SymKey* key = NULL;
	SECItem* iv_param = NULL;
	struct PostData* post_data = NULL;
	struct Session* typed_session = (struct Session*) session;
	/* TODO: Assuming default AES-256 */
	int const key_bits = 256;
	int const block_bits = 128; /* AES has fixed block size */
	
	if( cipher ) {
		/* Non-default algorithms not implemented yet. */
		rv = PRIVLY_CRYPTO_UNSUPPORTED_ALGORITHM;
		goto cleanup;
	}
	
	/* Check for duplicate post id. */
	if( Session_GetPostData( typed_session, post_id ) ) {
		rv = PRIVLY_CRYPTO_DUPLICATE_POST_ID;
		goto cleanup;
	}
	
	slot = PK11_GetInternalKeySlot(); /* TODO: Should we use "BestSlot" function? */
	if( !slot ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	key = PK11_KeyGen( slot, CKM_AES_KEY_GEN, 0 /* AES has fixed block size */, key_bits / 8, session );
	if( !key ) {
		/* TODO: Maybe there should be a KEYGEN_FAIL error code? */
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	iv_param = make_initialization_vector( CKM_AES_CBC_PAD, block_bits / 8 );
	if( !iv_param ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	post_data = PostData_New( PRIVLY_CRYPTO_POSTKEY_WITH_PUBLIC_KEY, key, 
							  CKM_AES_CBC_PAD, key_bits / 8, block_bits / 8, iv_param,
							  0 /* no kdf_iterations */, NULL /* no kdf_salt */ );
	if( !post_data ) {
		rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
		goto cleanup;
	}
	
	rv = Session_SetPostData( typed_session, post_id, post_data );

cleanup:
	if( slot ) {
		PK11_FreeSlot( slot );
	}
	
	if( PRIVLY_CRYPTO_SUCCESS != rv ) {
		if( post_data ) {
			PostData_Free( post_data ); /* This frees everything */
		}
		else {
			if( key ) {
				PK11_FreeSymKey( key );
			}
			if( iv_param ) {
				SECITEM_FreeItem( iv_param, PR_TRUE );
			}
		}
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_DerivePostKey( void* session, privly_postid_t post_id, 
					  struct privly_AlgorithmDescriptor* cipher,
					  char const* passphrase, int const kdf_iterations, 
					  int const kdf_salt_bytes )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	PK11SlotInfo* slot = NULL;
	PK11SymKey* key = NULL;
	SECItem* salt = NULL;
	SECItem* iv_param = NULL;
	struct PostData* post_data = NULL;
	struct Session* typed_session = (struct Session*) session;
	unsigned char passphrase_hash[privly_HASH_LENGTH];
	/* TODO: Assuming AES algorithm */
	int const key_bits = 256; 	/* AES-256 wrapping key */
	int const block_bits = 128; /* AES has fixed block size */
	
	if( cipher ) {
		/* Non-default algorithms not implemented yet. */
		rv = PRIVLY_CRYPTO_UNSUPPORTED_ALGORITHM;
		goto cleanup;
	}
	
	/* Check for duplicate post id. */
	if( Session_GetPostData( typed_session, post_id ) ) {
		rv = PRIVLY_CRYPTO_DUPLICATE_POST_ID;
		goto cleanup;
	}
	
	slot = PK11_GetInternalKeySlot(); /* TODO: Should use "BestSlot" function */
	if( !slot ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Hash the passphrase */
	status = hash_passphrase( passphrase, passphrase_hash );
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Make a salt for the key derivation. */
	salt = make_salt( kdf_salt_bytes );
	if( !salt ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Derive the post key */
	rv = derive_key( session, passphrase_hash, kdf_iterations, salt, &key );
	if( PRIVLY_CRYPTO_SUCCESS != rv ) {
		rv = PRIVLY_CRYPTO_KDF_FAIL;
		goto cleanup;
	}
	
	/* Create initialization vector for crypto operations. */
	/* TODO: Hardcoded algorithm */
	iv_param = make_initialization_vector( CKM_AES_CBC_PAD, block_bits / 8 );
	if( !iv_param ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Store the key in 'session'. */
	post_data = PostData_New( PRIVLY_CRYPTO_POSTKEY_DERIVED, key, CKM_AES_CBC_PAD, 
							  key_bits / 8, block_bits / 8, iv_param, kdf_iterations, salt );
	if( !post_data ) {
		rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
		goto cleanup;
	}
	
	rv = Session_SetPostData( typed_session, post_id, post_data );

cleanup:
	if( slot ) {
		PK11_FreeSlot( slot );
	}
	if( PRIVLY_CRYPTO_SUCCESS != rv ) {
		if( post_data ) {
			PostData_Free( post_data ); /* This frees everything */
		}
		else {
			if( key ) {
				PK11_FreeSymKey( key );
			}
			if( salt ) {
				SECITEM_FreeItem( salt, PR_TRUE );
			}
			if( iv_param ) {
				SECITEM_FreeItem( iv_param, PR_TRUE );
			}
		}
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_EncryptPost( void* session, privly_postid_t post_id, 
					unsigned char* plaintext, int plain_len,
					unsigned char* ciphertext, int* cipher_len )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	PK11Context* enc_context = NULL;
	int cipherop_len = 0;
	unsigned int final_len = 0;
	struct Session* typed_session = (struct Session*) session;
	struct PostData* post_data = Session_GetPostData( typed_session, post_id );
	
	if( !post_data ) {
		rv = PRIVLY_CRYPTO_NO_POST_KEY;
		goto cleanup;
	}
	
	/* Leave room for padding. */
	*cipher_len = plain_len + post_data->block_size;
	/* Enquiring about output buffer size. */
	if( !ciphertext ) {
		rv = PRIVLY_CRYPTO_ENQ;
		goto cleanup;
	}
	
	enc_context = PK11_CreateContextBySymKey( 
		post_data->mechanism, CKA_ENCRYPT, post_data->key, post_data->iv_param );
	if( !enc_context ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Do encryption. */
	status = PK11_CipherOp( enc_context, ciphertext, &cipherop_len, *cipher_len, plaintext, plain_len );
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Encrypt padding block. */
	status = PK11_DigestFinal( enc_context, ciphertext + cipherop_len, &final_len, *cipher_len - cipherop_len );
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Total cipher len is sum of length of CiperOp and DigestFinal. */
	*cipher_len = cipherop_len + final_len;
	
cleanup:
	if( enc_context ) {
		PK11_DestroyContext( enc_context, PR_TRUE );
	}

	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_ExportPostKey( void* session, privly_postid_t post_id, 
					  char const* user_name, struct privly_PostKeyData* data )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	SECItem* wrapped_key = NULL;
	int b_common_enq = 0;
	struct Session* typed_session = (struct Session*) session;
	struct PostData* post_data = Session_GetPostData( typed_session, post_id );
	CERTCertificate* cert = NULL;
	SECKEYPublicKey* public_key = NULL;
	int key_size = 0;
	
	if( !post_data ) {
		rv = PRIVLY_CRYPTO_NO_POST_KEY;
		goto cleanup;
	}
	
	/* Common fields */
	data->type = post_data->type;
	data->cipher = PRIVLY_CRYPTO_CIPHER_AES_CBC;		/* TODO: Genericize */
	data->key_bits = 256; 								/* TODO: Genericize */
	data->block_bits = 128;								/* TODO: Genericize */
	data->iv_len = post_data->iv_param->len;
	b_common_enq = !data->iv;
	
	if( PRIVLY_CRYPTO_POSTKEY_DERIVED == post_data->type ) {
		/* The key is derived from a passphrase, so we just need to export
		the derivation parameters, salt, and iv.
		(BUT NOT THE KEY!) */
		data->kdf_iterations = post_data->kdf_iterations;
		data->kdf_salt_len = post_data->salt_item->len;
		
		if( b_common_enq || !data->kdf_salt ) {
			rv = PRIVLY_CRYPTO_ENQ;
			goto cleanup;
		}
	
		/* Copy output data */
		memcpy( data->iv, post_data->iv_param->data, post_data->iv_param->len );
		memcpy( data->kdf_salt, post_data->salt_item->data, post_data->salt_item->len );
	} /* PRIVLY_CRYPTO_POSTKEY_DERIVED */
	else if( PRIVLY_CRYPTO_POSTKEY_WITH_PUBLIC_KEY == post_data->type ) {
		/* Export the post key protected by a user's public key. */
		
		if( !user_name ) {
			rv = PRIVLY_CRYPTO_BAD_PARAM;
			goto cleanup;
		}
		
		/* Find the public key. */
		/* TODO: Hardcoded name */
		cert = PK11_FindCertFromNickname( "TestCA", session );
		if( !cert ) {
			rv = PRIVLY_CRYPTO_NO_SUCH_CERTIFICATE;
			goto cleanup;
		}
		public_key = CERT_ExtractPublicKey( cert );
		if( !public_key ) {
			rv = PRIVLY_CRYPTO_NO_PUBLIC_KEY;
			goto cleanup;
		}
		
		/* Figure out how big the exported key will be */
		key_size = SECKEY_PublicKeyStrength( public_key );
		data->key_data_len = key_size;
		if( b_common_enq || !data->key_data ) {
			rv = PRIVLY_CRYPTO_ENQ;
			goto cleanup;
		}
		wrapped_key = SECITEM_AllocItem( NULL, NULL, key_size );
		if( !wrapped_key ) {
			rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
			goto cleanup;
		}
		
		/* Do wrapping */
		status = PK11_PubWrapSymKey( CKM_RSA_PKCS, public_key, post_data->key, wrapped_key );
		if( SECSuccess != rv ) {
			rv = PRIVLY_CRYPTO_PK_WRAP_FAIL;
			goto cleanup;
		}
		
		/* Copy output data */
		memcpy( data->key_data, wrapped_key->data, wrapped_key->len );
		memcpy( data->iv, post_data->iv_param->data, post_data->iv_param->len );
	} /* PRIVLY_CRYPTO_POSTKEY_WITH_PUBLIC_KEY */
	
cleanup:
	if( cert ) {
		CERT_DestroyCertificate( cert );
	}
	if( public_key ) {
		SECKEY_DestroyPublicKey( public_key );
	}
	if( wrapped_key ) {
		SECITEM_FreeItem( wrapped_key, PR_TRUE );
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_ImportPostKey( void* session, privly_postid_t post_id, 
					  char const* user_name, char const* passphrase,
					  struct privly_PostKeyData* data )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	CK_MECHANISM_TYPE cipher_mech = CKM_INVALID;
	struct Session* typed_session = (struct Session*) session;
	SECItem* iv_param = NULL;
	PK11SymKey* post_key = NULL;
	SECItem* salt = NULL;
	unsigned char passphrase_hash[privly_HASH_LENGTH];
	struct PostData* post_data = NULL;
	CERTCertificate* cert = NULL;
	SECKEYPrivateKey* private_key = NULL;
	SECItem* key_item = NULL;
	
	/* Argument checking */
	if( !data->iv ) {
		return PRIVLY_CRYPTO_BAD_PARAM;
	}
	cipher_mech = privly_cipher_to_ckm( data->cipher );
	if( CKM_INVALID == cipher_mech ) {
		return PRIVLY_CRYPTO_UNSUPPORTED_ALGORITHM;
	}
	
	if( Session_GetPostData( typed_session, post_id ) ) {
		return PRIVLY_CRYPTO_DUPLICATE_POST_ID;
	}
	
	/* Extract SECItem for iv. */
	iv_param = SECITEM_AllocItem( NULL, NULL, data->iv_len );
	if( !iv_param ) {
		rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
		goto cleanup;
	}
	memcpy( iv_param->data, data->iv, data->iv_len );
	
	/* TODO: Make these separate functions, if the number of cases gets
	out of hand. */
	if( PRIVLY_CRYPTO_POSTKEY_DERIVED == data->type ) {
		if( data->kdf_iterations == 0 || !data->kdf_salt ) {
			rv = PRIVLY_CRYPTO_BAD_PARAM;
			goto cleanup;
		}
		
		/* Extract SECItem for salt. */
		salt = SECITEM_AllocItem( NULL, NULL, data->kdf_salt_len );
		if( !salt ) {
			rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
			goto cleanup;
		}
		memcpy( salt->data, data->kdf_salt, data->kdf_salt_len );
		
		/* Hash the passphrase */
		status = hash_passphrase( passphrase, passphrase_hash );
		if( SECSuccess != status ) {
			rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
			goto cleanup;
		}
		
		/* Derive the post key */
		rv = derive_key( session, passphrase_hash, data->kdf_iterations, salt, &post_key );
		if( PRIVLY_CRYPTO_SUCCESS != rv ) {
			rv = PRIVLY_CRYPTO_KDF_FAIL;
			goto cleanup;
		}
		
		/* Store the key in 'session'. */
		post_data = PostData_New( data->type, post_key, cipher_mech, 
								  data->key_bits / 8, data->block_bits / 8, 
								  iv_param, data->kdf_iterations, salt );
		if( !post_data ) {
			rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
			goto cleanup;
		}
		
		rv = Session_SetPostData( typed_session, post_id, post_data );
		
	} /* PRIVLY_CRYPTO_POSTKEY_DERIVED */
	else {
		if( !data->key_data ) {
			rv = PRIVLY_CRYPTO_BAD_PARAM;
			goto cleanup;
		}
		
		/* Wrapped key data */
		key_item = SECITEM_AllocItem( NULL, NULL, data->key_data_len );
		if( !key_item ) {
			rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
			goto cleanup;
		}
		memcpy( key_item->data, data->key_data, data->key_data_len );
		
		/* TODO: Hardcoded name */
		cert = PK11_FindCertFromNickname( user_name, session );
		if( !cert ) {
			rv = PRIVLY_CRYPTO_NO_SUCH_CERTIFICATE;
			goto cleanup;
		}
		
		private_key = PK11_FindKeyByAnyCert( cert, session );
		if( !private_key ) {
			rv = PRIVLY_CRYPTO_NO_PRIVATE_KEY;
			goto cleanup;
		}
		
		/* Do unwrap */
		post_key = PK11_PubUnwrapSymKey(
			private_key, key_item, cipher_mech, CKA_UNWRAP, data->key_bits / 8 );
		if( !post_key ) {
			rv = PRIVLY_CRYPTO_PK_UNWRAP_FAIL;
			goto cleanup;
		}
		
		/* Store the key in 'session'. */
		post_data = PostData_New( data->type, post_key, cipher_mech, 
								  data->key_bits / 8, data->block_bits / 8, iv_param,
								  0 /* kdf_iterations */, NULL /* kdf_salt */ );
		if( !post_data ) {
			rv = PRIVLY_CRYPTO_OUT_OF_MEMORY;
			goto cleanup;
		}
		
		rv = Session_SetPostData( typed_session, post_id, post_data );
		
	} /* PRIVLY_CRYPTO_POSTKEY_WITH_PUBLIC_KEY */
	
cleanup:
	if( key_item ) {
		SECITEM_FreeItem( key_item, PR_TRUE );
	}
	if( cert ) {
		CERT_DestroyCertificate( cert );
	}
	if( private_key ) {
		SECKEY_DestroyPrivateKey( private_key );
	}
	
	if( PRIVLY_CRYPTO_SUCCESS != rv ) {
		if( post_data ) {
			PostData_Free( post_data );
		}
		else {
			if( iv_param ) {
				SECITEM_FreeItem( iv_param, PR_TRUE );
			}
			if( salt ) {
				SECITEM_FreeItem( salt, PR_TRUE );
			}
			if( post_key ) {
				PK11_FreeSymKey( post_key );
			}
		}
	}
	
	return rv;
}

/* -------------------------------------------------------------------------*/
	  
int PRIVLY_EXPORT
privly_DecryptPost( void* session, privly_postid_t post_id,
					unsigned char* ciphertext, int cipher_len,
					unsigned char* plaintext, int* plain_len )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	PK11Context* enc_context = NULL;
	int cipherop_len = 0;
	unsigned int final_len = 0;
	struct Session* typed_session = (struct Session*) session;
	struct PostData* post_data = Session_GetPostData( typed_session, post_id );
	
	if( !post_data ) {
		rv = PRIVLY_CRYPTO_NO_POST_KEY;
		goto cleanup;
	}
	
	enc_context = PK11_CreateContextBySymKey( 
		post_data->mechanism, CKA_DECRYPT, post_data->key, post_data->iv_param );
	if( !enc_context ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Do decryption. */
	status = PK11_CipherOp( enc_context, plaintext, &cipherop_len, cipher_len, ciphertext, cipher_len );
	if( SECSuccess != status ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Decrypt padding block. */
	status = PK11_DigestFinal( enc_context, plaintext + cipherop_len, &final_len, cipher_len - cipherop_len );
	if( SECSuccess != status ) {
		/* TODO: This step is the one that will fail if you have the wrong key
		(e.g., you typed in the wrong passphrase when deriving a key).
		This deserves a special error code. If possible, figure out which
		particular NSS error(s) can correspond to wrong passphrases, and
		check for them. */
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Total cipher len is sum of length of CiperOp and DigestFinal. */
	*plain_len = cipherop_len + final_len;
	
cleanup:
	if( enc_context ) {
		PK11_DestroyContext( enc_context, PR_TRUE );
	}

	return rv;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_ForgetPostKey( void* session, privly_postid_t post_id )
{
	struct Session* typed_session = (struct Session*) session;
	Session_ForgetPostData( typed_session, post_id );
	return PRIVLY_CRYPTO_SUCCESS;
}

/* -------------------------------------------------------------------------*/

int PRIVLY_EXPORT
privly_GenerateKeyPair( void* session, char const* nickname, int const key_bits )
{
	int rv = PRIVLY_CRYPTO_SUCCESS;
	SECStatus status = SECSuccess;
	SECKEYPrivateKey* private_key = NULL;
	SECKEYPublicKey* public_key = NULL;
	PK11SlotInfo* slot = NULL;
	PK11RSAGenParams rsa_params;
	
	/* 2048 is our minimum value; 8192 is NSS's maximum value. */
	if( key_bits != 2048 && key_bits != 4096 && key_bits != 8192 ) {
		rv = PRIVLY_CRYPTO_BAD_PARAM;
		goto cleanup;
	}
	
	rv = get_private_key( session, nickname, &private_key );
	if( PRIVLY_CRYPTO_SUCCESS != rv ) {
		goto cleanup;
	}
	else if( private_key ) {
		/* Key exists. */
		rv = PRIVLY_CRYPTO_DUPLICATE_KEYPAIR;
		goto cleanup;
	}
	
	slot = PK11_GetInternalKeySlot(); /* TODO: GetBestSlot() */
	if( !slot ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	/* Key generation parameters. */
	rsa_params.keySizeInBits = key_bits;
	rsa_params.pe = privly_RSA_KEYGEN_PE;
	
	/* PR_TRUE's = key isPerm and isSensitive;
	Keys will be stored in the NSS database. */
	private_key = PK11_GenerateKeyPair( slot, CKM_RSA_PKCS_KEY_PAIR_GEN,
										&rsa_params, &public_key,
										PR_TRUE, PR_TRUE, session );
	if( !private_key ) {
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
	status = PK11_SetPrivateKeyNickname( private_key, nickname );
	if( SECSuccess != status ) {
		/* TODO: We probably want to delete the key if setting the nickname fails. */
		rv = PRIVLY_CRYPTO_LIBRARY_ERROR;
		goto cleanup;
	}
	
cleanup:
	if( slot ) {
		PK11_FreeSlot( slot );
	}
	if( public_key ) {
		SECKEY_DestroyPublicKey( public_key );
	}
	if( private_key ) {
		SECKEY_DestroyPrivateKey( private_key );
	}
	
	return rv;
}

/* ---------------------------------------------------------------------------
 * Macro cleanup
 * -------------------------------------------------------------------------*/

#undef privly_HASH_ALGORITHM
#undef privly_HASH_LENGTH
#undef privly_RSA_KEYGEN_PE
