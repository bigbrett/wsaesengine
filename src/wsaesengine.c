#include <openssl/engine.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "wsaes.h"
#include "wsaeskern.h"


#include "wsaes.h"

// Turn off this annoying warning that we don't care about 
#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"

// TODO we need to sort out proper return values
#define FAIL -1
#define SUCCESS 1

static const char *engine_id = "wsaes";
static const char *engine_name = "A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000";
static int wsaes_nids[] = {NID_aes_256_cbc};

static int wsaesengine_aescbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int wsaesengine_aescbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int wsaesengine_aescbc_cleanup(EVP_CIPHER_CTX *ctx);
//tatic int wsaesengine_aescbc_ctrl (EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
//static int wsaesengine_aescbc_set_asn1_parameters (EVP_CIPHER_CTX *, ASN1_TYPE *);
//static int wsaesengine_aescbc_get_asn1_parameters (EVP_CIPHER_CTX *, ASN1_TYPE *);


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
static const EVP_CIPHER wsaesengine_aescbc_method = 
{
	NID_aes_256_cbc, // openSSL algorithm numerical ID
	AESBLKSIZE, // block size
	AESKEYSIZE, // key length
	AESIVSIZE,  // iv length 
	0 | EVP_CIPH_CBC_MODE, // flags...TODO this should not be hardcoded
	wsaesengine_aescbc_init_key, // key initialization function pointer
	wsaesengine_aescbc_do_cipher, // do_cipher (encrypt/decrypt data)
	wsaesengine_aescbc_cleanup, // cleanup (cleanup ctx)
	AESMAXDATASIZE, // ctx_size (how large cipher data needs to be)
	EVP_CIPHER_set_asn1_iv, // set_asn1_parameters Pupulate a ASN1_type with parameters
	EVP_CIPHER_set_asn1_iv, // get_asn1_parameters get ASN1_TYPE parameters
	NULL,//wsaesengine_aescbc_ctrl, // ctrl: misc. operations
	NULL // pointer to application data to encrypt
}; 


/*
 * Digest initialization function
 */
static int wsaesengine_aescbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, 
										  const unsigned char *iv, int enc)
{
    int ret; 
    //printf("** wsaesengine_aescbc_init_key()\n");

    ret = aes256init();
	if (0 != ret)
	{
		fprintf(stderr,"ERROR: AES block could not be initialized in ngine init_key\n");
		return FAIL;
	}
    
    ret = aes256setkey((uint8_t*)key);
    if (0 != ret)
	{
		fprintf(stderr,"ERROR: failed to set key in engine init_key()\n");
        return FAIL;
	}
    
    ret = aes256setiv((uint8_t*)iv);
    if (0 != ret)
	{
		fprintf(stderr,"ERROR: failed to set iv in engine init_key\n");
        return FAIL;
	}

    ret = aes256reset();
    if (0 != ret)
	{
		fprintf(stderr,"ERROR: failed to reset in engine init_key()\n");
        return FAIL;
	}

	return SUCCESS;
}


/*
 * Cipher computation
 */
static int wsaesengine_aescbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    //printf("wsaesengine_aescbc_do_cipher()\n");

    int status;
    uint32_t outlen;

    ciphermode_t mode = (!ctx->encrypt) ? DECRYPT : ENCRYPT; 
    //printf("calling aes256 with args:\n\tmode = %d\n\tin = ",mode);
    //for (int i=0; i<inl; i++)
    //    printf("0x%02X ",in[i]);
    //printf("\n\tinlen = %d\n",inl);

    status = aes256(mode, (uint8_t*)in, (uint32_t)inl, (uint8_t*)out, &outlen);
    //printf("aes256 completed with status = %d\n\tout = ",status);
    //for (int i=0; i<outlen; i++)
    //    printf("0x%02X ",out[i]);
    //printf("\n\toutlen= %d\n",outlen);

    if (status != 0)
        return FAIL;
    else
        return SUCCESS;

}



/*
 * AES EVP_CIPHER_CTX cleanup function: sets all fields to zero
 */
static int wsaesengine_aescbc_cleanup(EVP_CIPHER_CTX *ctx) 
{

    //printf("** wsaesengine_aescbc_cleanup()\n");
	if (ctx->cipher_data)
		memset(ctx->cipher_data, 0, 32);
	return SUCCESS;
}


/* 
 * Cipher selection function: tells openSSL that whenever a evp cypher is 
 * reauested to use our engine implementation 
 * 
 * OpenSSL calls this function in the following ways:
 *   1. with cipher argument being NULL. In this case, *nids is expected to be assigned a 
 *		  zero-terminated array of NIDs and the call returns with the number of available NIDs. 
 * 		  OpenSSL uses this to determine what ciphers supported by this engine.
 * 	 2. with cipher argument being non-NULL. In this case, *cipher is expected to be assigned the pointer 
 * 			to the EVP_CIPHER structure corresponding to the NID given by nid. The call returns with 1 if 
 * 			the request NID was one supported by this engine, otherwise returns 0.
 */
static int wsaesengine_cipher_selector(ENGINE *e, const EVP_CIPHER**cipher, const int **nids, int nid)
{
    //printf("** wsaesengine_cipher_selector()\n");
    // if cipher is null, return 0-terminated array of supported NIDs
    if (!cipher)
    {
        *nids = wsaes_nids;
        int retnids = sizeof(wsaes_nids - 1) / sizeof(wsaes_nids[0]);
        return retnids;
    }

    // if cipher is supported, select our implementation, otherwise set to null and fail 
    switch (nid) 
    {
        case NID_aes_256_cbc:
            *cipher = &wsaesengine_aescbc_method; 
            break;
        // other cases tdb
       default:
            *cipher = NULL;
            return FAIL; 
    }
    return SUCCESS;
}
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



//static int wsaesengine_aescbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
//{
//    printf("**wsaesengine_aescbc_ctrl()\n");
//    return SUCCESS;
//}


/*
 * Engine Initialization 
 */
int wsaes_init(ENGINE *e)
{
    //printf("** wsaes_init()\n");
    if (aes256init() < 0)
        return FAIL;
    return SUCCESS;
}


int wsaes_finish(ENGINE *e)
{
    //printf("** wsaes_finish()\n");
    return SUCCESS;
}


/*
 *  Engine binding function
 */
static int bind(ENGINE *e, const char *id)
{
    //printf("**bind()\n");
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
	if (!ENGINE_set_init_function(e, wsaes_init))
	{
		fprintf(stderr,"ENGINE_set_init_function failed\n"); 
		goto end;
	}
    if (!ENGINE_set_finish_function(e, wsaes_finish))
	{
		fprintf(stderr,"ENGINE_set_finish_function failed\n"); 
		goto end;
	}
	if (!ENGINE_set_ciphers(e, wsaesengine_cipher_selector)) 
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
