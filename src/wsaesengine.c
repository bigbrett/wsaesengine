#include <openssl/engine.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "wsaescbc.h"
#include "wsaeskern.h"


#include "wsaescbc.h"

// Turn off this annoying warning that we don't care about 
#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"

// TODO we need to sort out proper return values
#define FAIL 0
#define SUCCESS 1

#define SIMPLEPRINT 1

static const char *engine_id = "wsaescbc";
static const char *engine_name = "A test engine for the ws aescbc hardware encryption module, on the Xilinx ZYNQ7000";
static int wsaescbc_nids[] = {NID_aes_256_cbc};

static int wsaescbcengine_aescbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int wsaescbcengine_aescbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int wsaescbcengine_aescbc_cleanup(EVP_CIPHER_CTX *ctx);
static int wsaescbcengine_aescbc_ctrl (EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
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
	NID_aes_256_cbc, // openSSL algorithm numerical ID
	AESBLKSIZE, // block size
	AESKEYSIZE, // key length
	AESIVSIZE,  // iv length 
	0 | EVP_CIPH_CBC_MODE, // flags...TODO this should not be hardcoded
	wsaescbcengine_aescbc_init_key, // key initialization function pointer
	wsaescbcengine_aescbc_do_cipher, // do_cipher (encrypt/decrypt data)
	wsaescbcengine_aescbc_cleanup, // cleanup (cleanup ctx)
	AESMAXDATASIZE, // ctx_size (how large cipher data needs to be)
	EVP_CIPHER_set_asn1_iv, // set_asn1_parameters Pupulate a ASN1_type with parameters
	EVP_CIPHER_set_asn1_iv, // get_asn1_parameters get ASN1_TYPE parameters
	wsaescbcengine_aescbc_ctrl, // ctrl: misc. operations
	NULL // pointer to application data to encrypt
}; 


/*
 * Digest initialization function
 */
static int wsaescbcengine_aescbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, 
										  const unsigned char *iv, int enc)
{
    int ret; 
    printf("** wsaescbcengine_aescbc_init_key()\n");

//#if SIMPLEPRINT != 1
    ret = aes256init();
	if (0 != ret)
	{
		fprintf(stderr,"ERROR: AES block could not be initialized\n");
		return FAIL;
	}
    
    ret = aes256setkey((uint8_t*)key);
    if (0 != ret)
	{
		fprintf(stderr,"ERROR: failed to set key in aes256setkey()\n");
        return FAIL;
	}
    
    ret = aes256setiv((uint8_t*)iv);
    if (0 != ret)
	{
		fprintf(stderr,"ERROR: failed to set iv in aes256setkey()\n");
        return FAIL;
	}
//#endif  
	return SUCCESS;
}


/*
 * Cipher computation
 */
static int wsaescbcengine_aescbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    printf("wsaescbcengine_aescbc_do_cipher()");
#if SIMPLEPRINT != 1
    int status, fd;
    uint32_t outlen;
    ciphermode_t mode = (!ctx->encrypt) ? DECRYPT : ENCRYPT; 

    //aes256(mode, (uint8_t*)in, (uint32_t)inl, (uint8_t*)out, &outlen);

    return 0;
    // check bounds against max length 
    if (inl > AESMAXDATASIZE)
    {
        fprintf(stderr, "ERROR: Provided data length (%d) too large, must be less than %d bytes\n",
                inl, AESMAXDATASIZE);
        return -1;
    }
    else if (0 >= inl)
    {
        fprintf(stderr, "ERROR: Provided data length (%d) too small, must be at least 1 bytes\n",
                inl);
        return -1;
    }

    // Open the device with read/write access
    fd = open("/dev/wsaeschar", O_RDWR);             
    if (fd < 0){
        perror("ERROR: Failed to open the device...");
        return errno;
    }

    // Reset block 
    int ret = ioctl(fd, IOCTL_SET_MODE, RESET); 
    if (ret < 0) {
        perror("ERROR: failed to reset AES block... \n");
        return errno;
    }

    // Set mode to ENCRYPT/DECRYPT
    if (mode != ENCRYPT && mode != DECRYPT)
    {
        fprintf(stderr, "ERROR: invalid mode. Must be either ENCRYPT or DECRYPT\n");
        return -1;
    }
    else
    {
        ret = ioctl(fd, IOCTL_SET_MODE, (ciphermode_t)mode); 
        if (ret < 0) {
            perror("ERROR: failed to set mode, ioctl returns errno \n");
            return errno;
        }
    }

    int orignumbytes; // The original number of bytes in the input data
    int olen; // output length
    uint8_t lastblock[AESBLKSIZE]; // the last block to send if we are encrypting ONLY.  

    // if we are encrypting the data, we must deal with padding the data to encrypt
    if (mode == ENCRYPT)
    {
        int modlen = inl % AESBLKSIZE;     // number of data bytes in last block
        int numpadbytes = AESBLKSIZE-modlen; // number of padding bytes in last block

        // set outut length to the nearest non-zero multiple of the block size
        olen = inl + numpadbytes; 

        // loop boundary for looping through the blocks
        orignumbytes = olen - AESBLKSIZE;

        // Construct the "last block" of data to send, composed of the last straggling bytes that don't fit evenly into the 
        // 16-byte block size. This "last block" is padded out to the block size with a number of "padding bytes", whose values 
        // are all set to the number of padding bits required. So there will be X bytes with a value of X. The value of the 
        // padding bytes are all the same, and is just the number of padding bytes required to fill out the last 16-byte block. 
        // So if there are 4 data bytes (0xBE 0xEE 0xEE 0xEF) left to send in the last block, we then need 12 padding bytes, each
        // with the value of value 0x0C (or 12, in base 10). If the data length is an integer multiple of the block size, then 
        // we just send the message, and the "last block" is 16 bytes of just padding bits (0x10, decimal 16)
        for (int i=0; i<AESBLKSIZE; i++)
            lastblock[i] = (i < modlen) ? in[orignumbytes + i] : numpadbytes;
    }     
    else 
    { // we are not incrypting, so don't need to pad data. Data length is unmodified, just loop through the input data
        olen = inl;
        orignumbytes = inl;
    }

    // initialize outut memory to all zeros
    memset((void*)out,0,olen);
   
    // MAIN DATA SENDING LOOP: 
    // send each complete 16-byte block of data to the LKM for processing and read back the result
    for (int i=0; i<orignumbytes; i+=AESBLKSIZE)
    {
        // send 16 byte block from caller to AES block
        ret = write(fd, &(in[i]), AESBLKSIZE); 
        if (ret < 0) {
            perror("ERROR: Failed to write data to the AES block... ");   
            return errno;                                                      
        }

        // read back processed 16 byte block into caller memory from AES block
        ret = read(fd, &(out[i]), AESBLKSIZE);
        if (ret < 0){
            perror("Failed to read data back from the AES block... ");
            return errno;
        }
    }    

    // if we are encrypting the data, deal with the extra padding bytes
    if (mode == ENCRYPT)
    {
        // send final padded block
        ret = write(fd, lastblock, AESBLKSIZE); 
        if (ret < 0) {
            perror("ERROR: Failed to write data to the AES block... ");   
            return errno;                                                      
        }
        // read back processed final padded block
        ret = read(fd, &(out[orignumbytes]), AESBLKSIZE);
        if (ret < 0){
            perror("Failed to read data back from the AES block... ");
            return errno;
        }
    }

    // close and exit
    if(close(fd)<0)
    {
        perror("aescbc: Error closing file");
        return errno;
    }
#endif
    return SUCCESS;
}



/*
 * AES EVP_CIPHER_CTX cleanup function: sets all fields to zero
 */
static int wsaescbcengine_aescbc_cleanup(EVP_CIPHER_CTX *ctx) 
{

    printf("** wsaescbcengine_aescbc_cleanup()\n");
#if SIMPLEPRINT != 1
	if (ctx->cipher_data)
		memset(ctx->cipher_data, 0, 32);
#endif
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
static int wsaescbcengine_cipher_selector(ENGINE *e, const EVP_CIPHER**cipher, const int **nids, int nid)
{
    printf("** wsaescbcengine_cipher_selector()\n");
    // if cipher is null, return 0-terminated array of supported NIDs
    if (!cipher)
    {
        *nids = wsaescbc_nids;
        int retnids = sizeof(wsaescbc_nids - 1) / sizeof(wsaescbc_nids[0]);
        return retnids;
    }

    // if cipher is supported, select our implementation, otherwise set to null and fail 
    switch (nid) 
    {
        case NID_aes_256_cbc:
            *cipher = &wsaescbcengine_aescbc_method; 
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



static int wsaescbcengine_aescbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    printf("**wsaescbcengine_aescbc_ctrl()\n");
    return SUCCESS;
}


/*
 * Engine Initialization 
 */
int wsaescbc_init(ENGINE *e)
{
    printf("** wsaescbc_init()\n");
#if SIMPLEPRINT != 1
    int status = aes256init();
#endif  
	return SUCCESS;
}


/*
 *  Engine binding function
 */
static int bind(ENGINE *e, const char *id)
{
    printf("**bind()\n");
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
	if (!ENGINE_set_ciphers(e, wsaescbcengine_cipher_selector)) 
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
