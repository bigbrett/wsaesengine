#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "wsaescbc.h"

// Turn off this annoying warning that we don't care about 
#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"

#define FAIL 0
#define SUCCESS 1


static const char *engine_id = "wsaescbc";
static const char *engine_name = "A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000";
static int wsaescbc_digest_ids[] = {NID_aescbc,0};

static int wsaescbcengine_aescbc_init_key(CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int wsaescbcengine_aescbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int wsaescbcengine_aescbc_cleanup(EVP_MD_CTX *ctx);
static int wsaescbcengine_aescbc_ctrl (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
//static int wsaescbcengine_aescbc_set_asn1_parameters (EVP_CIPHER_CTX *, ASN1_TYPE *);
//static int wsaescbcengine_aescbc_get_asn1_parameters (EVP_CIPHER_CTX *, ASN1_TYPE *);


// Create our own evp cipher declaration matching that of the generic cipher 
// structure (struct evp_cipher_st) defined in openssl/include/internal/evp_int.h
//struct evp_cipher_st {
//    int nid;
//    int block_size;
//    /* Default value for variable length ciphers */
//    int key_len;
//    int iv_len;
//    /* Various flags */
//    unsigned long flags; 
//    /* init key */
//    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
//    /* encrypt/decrypt data */
//    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
//    /* cleanup ctx */
//    int (*cleanup) (EVP_CIPHER_CTX *);
//    /* how big ctx->cipher_data needs to be */
//    int ctx_size;
//    /* Populate a ASN1_TYPE with parameters */
//    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
//    /* Get parameters from a ASN1_TYPE */
//    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
//    /* Miscellaneous operations */
//    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
//    /* Application data */
//    void *app_data;
//} /* EVP_CIPHER */ ;
static const EVP_CIPHER wsaescbcengine_aescbc_method = 
{
	NID_aescbc, // openSSL algorithm numerical ID
	AESBLKSIZE, // block size
	AESKEYSIZE, // key length
	AESIVSIZE,  // iv length 
	0 | EVP_CIPH_CBC_MODE, // flags...TODO this should change
	wsaescbcengine_aescbc_init_key, // key initialization function pointer
	wsaescbcengine_aescbc_do_cipher, // do_cipher (encrypt/decrypt data)
	wsaescbcengine_aescbc_cleanup, // cleanup (cleanup ctx)
	AESMAXDATASIZE, // ctx_size (how large cipher data needs to be)
	EVP_CIPHER_set_asn1_iv, // set_asn1_parameters Pupulate a ASN1_type with parameters
	EVP_CIPHER_set_asn1_iv, // get_asn1_parameters get ASN1_TYPE parameters
	wsaescbcengine_aescbc_ctrl, // ctrl: misc. operations
	NULL // pointer to application data to encrypt
}; 

//{NID_undef, NID_undef, 0,0,0}, // required pkey type 

//struct evp_cipher_ctx_st {
//    const EVP_CIPHER *cipher;
//    ENGINE *engine;             /* functional reference if 'cipher' is ENGINE-provided */
//    int encrypt;                /* encrypt or decrypt */
//    int buf_len;                /* number we have left */
//    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
//    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
//    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
//    int num;                    /* used by cfb/ofb/ctr mode */
//    /* FIXME: Should this even exist? It appears unused */
//    void *app_data;             /* application stuff */
//    int key_len;                /* May change for variable length cipher */
//    unsigned long flags;        /* Various flags */
//    void *cipher_data;          /* per EVP data */
//    int final_used;
//    int block_mask;
//    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
//} /* EVP_CIPHER_CTX */ ;

/*
 * Digest initialization function
 */
static int wsaescbcengine_aescbc_init_key(CIPHER_CTX *ctx, const unsigned char *key, 
										  const unsigned char *iv, int enc);
{

	// call API initialization function
	if (aescbc_init() < 0)
	{
		fprintf(stderr,"ERROR: SHA256 algorithm context could not be initialized\n");
		return FAIL;
	}
	return SUCCESS;
}


/*
 * SHA256 EVP_MD_CTX cleanup function: sets all fields to zero
 */
static int wsaescbcengine_aescbc_cleanup(EVP_MD_CTX *ctx) 
{
	if (ctx->cipher_data)
		memset(ctx->cipher_data, 0, 32);
	return SUCCESS;
}


/* 
 * Digest selection function: tells openSSL that whenever a SHA256 digest is 
 * reauested to use our engine implementation 
 * 
 * OpenSSL calls this function in the following ways:
 *   1. with digest being NULL. In this case, *nids is expected to be assigned a 
 *		  zero-terminated array of NIDs and the call returns with the number of available NIDs. 
 * 			OpenSSL uses this to determine what digests are supported by this engine.
 * 	 2. with digest being non-NULL. In this case, *digest is expected to be assigned the pointer 
 * 			to the EVP_MD structure corresponding to the NID given by nid. The call returns with 1 if 
 * 			the request NID was one supported by this engine, otherwise returns 0.
 */
static int wsaescbcengine_digest_selector(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	// if digest is null, return 0-terminated array of supported NIDs
	if (!digest)
	{
		*nids = wsaescbc_digest_ids;
		int retnids = sizeof(wsaescbc_digest_ids - 1) / sizeof(wsaescbc_digest_ids[0]);
		return retnids;
	}

	// if digest is supported, select our implementation, otherwise set to null and fail 
	if (nid == NID_aescbc)
	{ // select our hardware digest implementation 
		*digest = &wsaescbcengine_aescbc_method; 
		return SUCCESS;
	}
	else
	{
		*digest = NULL;
		return FAIL;
	}
}

/*
 * Engine Initialization 
 */
int wsaescbc_init(ENGINE *e)
{
	return aescbc_init();
}


/*
 *  Engine binding function
 */
static int bind(ENGINE *e, const char *id)
{
	int ret = FAIL;

	if (!ENGINE_set_id(e, engine_id))
	{
		fprintf(stderr, "ENGINE_set_id failed\n");
		goto end;
	}
	if (!ENGINE_set_name(e, engine_name))
	{
		fprintf(stderr,"ENGINE_set_name failed\n"); 
		goto end;
	}
	if (!ENGINE_set_init_function(e, wsaescbc_init))
	{
		fprintf(stderr,"ENGINE_set_init_function failed\n"); 
		goto end;
	}
	if (!ENGINE_set_digests(e, wsaescbcengine_digest_selector)) 
	{
		fprintf(stderr,"ENGINE_set_digests failed\n");
		goto end;
	}
	ret = SUCCESS; 
end: 
	return ret; 
}

	IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
