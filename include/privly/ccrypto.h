/**
 * privly/ccrypto.h
 *
 * Defines the C interface implemented by Privly cryptographic backends.
 *
 * A backend takes the form of a shared library exporting the functions in
 * this interface. Backends conforming to the interface can be used as
 * drop-in replacements for the reference implementation.
 *
 * TODO: 
 * [2012/04/09:jhostetler] Add keypair generation functions.
 */

#ifndef PRIVLY_CCRYPTO_H_
#define PRIVLY_CCRYPTO_H_

#include "privly/compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Error codes
 * -------------------------------------------------------------------------*/

/** Everything's alright. */
#define PRIVLY_CRYPTO_SUCCESS 				0
/** The function was called in order to determine correct parameters. */
#define PRIVLY_CRYPTO_ENQ 					1
/** An error occurred in non-Privly code, and it does not correspond to any other error code. */
#define PRIVLY_CRYPTO_LIBRARY_ERROR 		2
/** An error caused by an unsuitable execution environment. */
#define PRIVLY_CRYPTO_ENVIRONMENT_ERROR 	3
/** Out of memory. */
#define PRIVLY_CRYPTO_OUT_OF_MEMORY 		4
/** Bad parameter value. */
#define PRIVLY_CRYPTO_BAD_PARAM 			5

/** Function not implemented. Not for use in production code. */
#define PRIVLY_CRYPTO_NOT_IMPLEMENTED 		10
/** The provided session handle does not identify a valid session. */
#define PRIVLY_CRYPTO_INVALID_SESSION 		11
/** Username does not correspond to any registered user. */
#define PRIVLY_CRYPTO_NO_SUCH_USER 			12
/** Specified post ID already has associated key. */
#define PRIVLY_CRYPTO_DUPLICATE_POST_ID 	13
/** Attempted an operation requiring a post key, but one does not exist. */
#define PRIVLY_CRYPTO_NO_POST_KEY 			14

/** Initialization failed. */
#define PRIVLY_CRYPTO_INIT_FAIL 			20
/** Shutdown failed. */
#define PRIVLY_CRYPTO_SHUTDOWN_FAIL 		21

/** The named certificate does not exist in the database. */
#define PRIVLY_CRYPTO_NO_SUCH_CERTIFICATE 	30

/** The certificate has no attached public key. */
#define PRIVLY_CRYPTO_NO_PUBLIC_KEY 		40
/** The public key was mal-formed. */
#define PRIVLY_CRYPTO_BAD_PUBLIC_KEY 		41

/** The certificate has no attached private key. */
#define PRIVLY_CRYPTO_NO_PRIVATE_KEY 		50
/** The private key was mal-formed. */
#define PRIVLY_CRYPTO_BAD_PRIVATE_KEY 		51

/** The specified encryption algorithm is not supported by the backend. */
#define PRIVLY_CRYPTO_UNSUPPORTED_ALGORITHM 60
/** Public key wrapping failed. */
#define PRIVLY_CRYPTO_PK_WRAP_FAIL 			61
/** Private key unwrapping failed. */
#define PRIVLY_CRYPTO_PK_UNWRAP_FAIL 		62
/** Failure in key derivation. */
#define PRIVLY_CRYPTO_KDF_FAIL 				63

/** Reserved post ID representing NULL. */
#define PRIVLY_POSTID_NULL_POST 	(privly_postid_t) 0
/** Minimum user-defined post ID. */
#define PRIVLY_POSTID_MIN 			(privly_postid_t) 1

/* ---------------------------------------------------------------------------
 * Types
 * -------------------------------------------------------------------------*/

/**
 * A numeric type large enough to store the post ids. 
 * Guaranteed at least 64 bits.
 */
typedef unsigned long long privly_postid_t;

/**
 * Enumeration of available symmetric cipher algorithms.
 */
enum PRIVLY_EXPORT privly_CipherAlgorithm
{
	/** AES in CBC mode (default). */
	PRIVLY_CRYPTO_CIPHER_AES_CBC			= 0
};

/**
 * Enumeration of post key types.
 */
enum PRIVLY_EXPORT privly_PostKeyType
{
	/** Post key derived from passphrase. */
	PRIVLY_CRYPTO_POSTKEY_DERIVED			= 0,
	/** Random post key wrapped with receiver's public key. */
	PRIVLY_CRYPTO_POSTKEY_WITH_PUBLIC_KEY	= 1
};

/**
 * Descriptor of a generic encryption algorithm.
 */
struct PRIVLY_EXPORT privly_AlgorithmDescriptor
{
	/** The symmetric cipher algorithm. */
	enum privly_CipherAlgorithm cipher;
	
	/** 
	 * Block size for cipher algorithm. Note that some algorithms (such as AES)
	 * have fixed block sizes.
	 */
	int block_bits;
	
	/**
	 * Key size for cipher algorithm.
	 */
	int key_bits;
};

/**
 * POD type holding everything you might need to know to decrypt a post.
 */
struct PRIVLY_EXPORT privly_PostKeyData
{
	/** Post key type. */
	enum privly_PostKeyType type;
	/** Key bits. */
	unsigned char* key_data;
	/** Length of 'key_data' */
	int key_data_len;
	/** Symmetric cipher algorithm. */
	enum privly_CipherAlgorithm cipher;
	/** Size of cipher key in bits. */
	int key_bits;
	/** Size of cipher block in bits. */
	int block_bits;
	/** Initialization vector for CBC mode ciphers. */
	unsigned char* iv;
	/** Length of 'iv' */
	int iv_len;
	/** Number of iterations for key derivation function. */
	int kdf_iterations;
	/** Salt bits for key derivation function. */
	unsigned char* kdf_salt;
	/** Length of 'kdf_salt' */
	int kdf_salt_len;
};

/* ---------------------------------------------------------------------------
 * API Functions
 * -------------------------------------------------------------------------*/

/**
 * Create a new Privly session. The backend retrieves all cryptographic
 * objects needed to implement the Privly protocol. Any necessary state
 * information is written to 'session'. Implementations must *not* store
 * any state data, except in 'session'. 
 *
 * @param config_dir The directory where cryptographic objects are stored.
 * @param username The user's nickname, supplied during login.
 * @param passphrase The user's passphrase, supplied during login.
 * @param session If session creation is successful, this pointer will be set
 * to an implementation-specific session descriptor containing any state
 * information needed by other interface functions. Clients should treat this
 * object as an opaque handle.
 *
 * @return
 *		PRIVLY_CRYPTO_SUCCESS -- Success
 *		PRIVLY_CRYPTO_INIT_FAIL -- Unrecoverable failure
 *		PRIVLY_CRYPTO_NO_SUCH_USER -- The named user is not registered. Create
 *			a user account and retry.
 */
int PRIVLY_EXPORT 
privly_CreateSession( char const* config_dir, char const* username, 
					  char const* passphrase, void** session );

/**
 * Destroys a Privly session. The backend performs any necessary cleanup and 
 * persistence operations. Any memory allocated for 'session' in CreateSession
 * is freed. Subsequent calls to interface functions using the destroyed
 * 'session' object must fail with error code PRIVLY_CRYPTO_INVALID_SESSION.
 *
 * @param session A session handle allocated by CreateSession().
 * @return
 *		PRIVLY_CRYPTO_SUCCESS -- Success
 *		PRIVLY_CRYPTO_INVALID_SESSION -- 'session' is not a valid session
 *			handle.
 */
int PRIVLY_EXPORT 
privly_DestroySession( void* session );

/**
 * Creates a random symmetric key for the post with id 'post_id' and stores
 * it in 'session'. Functions that require the key obtain it via the post id.
 *
 * If 'cipher' is NULL, then the cipher algorithm must be AES with a 256-bit
 * key size.
 */
int PRIVLY_EXPORT
privly_CreatePostKey( void* session, privly_postid_t post_id, 
					  struct privly_AlgorithmDescriptor* cipher );

/**
 * Derives a symmetric key from 'passphrase' for the post with id 'post_id' and 
 * stores it in 'session'. Functions that require the key obtain it via the 
 * post id.
 *
 * The key derivation function is a PKCS5v2 function with a salt of size 
 * 'kdf_salt_bytes' and a number of iterations equal to 'kdf_iterations'.
 * The HMAC algorithm must be HMAC-SHA1. If 'cipher' is NULL, the cipher 
 * algorithm must be AES-256.
 */
int PRIVLY_EXPORT
privly_DerivePostKey( void* session, privly_postid_t post_id, 
					  struct privly_AlgorithmDescriptor* cipher,
					  char const* passphrase, int const kdf_iterations, 
					  int const kdf_salt_bytes );

/**
 * Encrypts 'post_data' using the post key associated with 'post_id'. The
 * key must exist in 'session' already.
 *
 * If 'ciphertext' is NULL, the maximum required length for the output buffer
 * is stored in 'cipher_len', and the function returns PRIVLY_CRYPTO_ENQ.
 *
 * If 'ciphertext' is not NULL, encryption is performed, and 'cipher_len' is
 * set to the number of bytes actually encrypted. Note that this may be shorter
 * than the value of 'cipher_len' returned by the ENQ operation.
 */
int PRIVLY_EXPORT
privly_EncryptPost( void* session, privly_postid_t post_id, 
					unsigned char* plaintext, int plain_len,
					unsigned char* ciphertext, int* cipher_len );

/**
 * Exports the post key associated with 'post_id' to 'data'. 
 *
 * If 'data' is NULL, the function sets the relevant "length" fields in
 * 'data' and returns PRIVLY_CRYPTO_ENQ.
 *
 * If 'data' is not NULL, the post key is returned in 'data'.
 *
 * The following fields of 'data' are always initialized:
 *		.type
 *		.cipher
 *		.key_bits
 *		.block_bits
 *		.iv
 *		.iv_len
 *
 * If the post key is of type POSTKEY_DERIVED, the following fields of 'data'
 * are initialized:
 *		.kdf_iterations
 *		.kdf_salt
 *		.kdf_salt_len
 *
 * If the post key is of type POSTKEY_WITH_PUBLIC_KEY, the following fields
 * of 'data' are initialized:
 *		.key_data
 *		.key_data_len
 *
 * If type is POSTKEY_WITH_PUBLIC_KEY, 'user_name' must identify a user to
 * share the post key with. Exporting a key of type POSTKEY_WITH_PUBLIC_KEY 
 * may require communicating with the server to retrieve the appropriate 
 * public keys. The export must be repeated for each recipient separately.
 */
int PRIVLY_EXPORT
privly_ExportPostKey( void* session, privly_postid_t post_id, 
					  char const* user_name, struct privly_PostKeyData* data );
					  
/**
 * Imports the post key contained in 'data' and associates it with 'post_id'.
 *
 * 'data' must have the following fields set for all post key types:
 *		.type
 *		.cipher
 *		.key_bits
 *		.block_bits
 *		.iv
 *		.iv_len
 *
 * If 'data.type' is POSTKEY_WITH_PUBLIC_KEY, 'user_name' must not be NULL.
 * The decryption operation entails accessing the user's private key from the 
 * client-side database. 'passphrase' is ignored and should be NULL. 'data'
 * must have the following fields set:
 *		.kdf_iterations
 *		.kdf_salt
 *		.kdf_salt_len
 *
 * If 'data.type' is POSTKEY_DERIVED, 'passphrase' must not be NULL. The key
 * is re-derived from the data in 'data' and the passphrase. 'user_name' is
 * ignored and should be NULL. 'data' must have the following fields set:
 *		.key_data
 *		.key_data_len
 */
int PRIVLY_EXPORT
privly_ImportPostKey( void* session, privly_postid_t post_id, 
					  char const* user_name, char const* passphrase,
					  struct privly_PostKeyData* data );

/**
 * Decrypts the post identified by 'post_id'. The key must already exist in
 * 'session'.
 *
 * If 'plaintext' is NULL, the maximum required length for the output buffer
 * is stored in 'plain_len', and the function returns PRIVLY_CRYPTO_ENQ.
 *
 * If 'plaintext' is not NULL, decryption is performed, and 'plain_len' is
 * set to the number of bytes actually decrypted. Note that this may be shorter
 * than the value of 'plain_len' returned by the ENQ operation.
 */				  
int PRIVLY_EXPORT
privly_DecryptPost( void* session, privly_postid_t post_id,
					unsigned char* ciphertext, int cipher_len,
					unsigned char* plaintext, int* plain_len );

/**
 * Removes key material associated with 'post_id' from the 'session' object.
 */
int PRIVLY_EXPORT
privly_ForgetPostKey( void* session, privly_postid_t post_id );


#ifdef __cplusplus
}
#endif

#endif /* PRIVLY_CCRYPTO_H_ */
