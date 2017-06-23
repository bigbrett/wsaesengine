#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "wsaescbc.h"

#define LOAD_ENGINE 0

#define HWSUCCESS 0
#define MAXBYTES 1048576

static const char* engine_id = "wsaescbcengine";
const char* devstr = "/dev/wsaeschar";

const uint8_t key[AESKEYSIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
const uint8_t iv[AESIVSIZE] =   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
// string to encrypt
const char teststr[] = "The Quick Brown Fox Jumped Over The Lazy Dog!"; 

static void aesErr(char *msg) {
    char *err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("[ERROR %s] %s\n",msg, err);
    free(err);
}

static int32_t wsencrypt(uint8_t *plaintext, uint32_t plaintext_len,
        uint8_t *key,uint8_t *iv,
        uint8_t *ciphertext,uint32_t *ciphertext_lenp) {
    EVP_CIPHER_CTX *ctx;
    int len;
    uint32_t ciphertext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        aesErr("wsencrypt new ctx");
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                (unsigned char*)key, (unsigned char*)iv))
        aesErr("wsencrypt init");
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &len,
                (unsigned char*)plaintext, (int)plaintext_len))
        aesErr("wsencrypt update");
    ciphertext_len = (uint32_t)len;
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.  */
    if(1 != EVP_EncryptFinal_ex(ctx, ((unsigned char*)ciphertext) + len, &len))
        aesErr("wsencrypt final");
    ciphertext_len += (uint32_t)len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    *ciphertext_lenp = ciphertext_len;
    return HWSUCCESS;
}


static int32_t wsdecrypt(uint8_t *ciphertext,uint32_t ciphertext_len,
        uint8_t *key,uint8_t *iv,
        uint8_t *plaintext,uint32_t *plaintext_lenp) {
    EVP_CIPHER_CTX *ctx;
    int len;
    uint32_t plaintext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        aesErr("wsdecrypt new ctx");
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                (unsigned char*)key, (unsigned char*)iv))
        aesErr("wsdecrypt init");
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &len,
                (unsigned char*)ciphertext, (int)ciphertext_len))
        aesErr("wsdecrypt update");
    plaintext_len = (uint32_t)len;
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, ((unsigned char*)plaintext + len), &len)) 
        aesErr("wsdecrypt final");
    plaintext_len += (uint32_t)len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    *plaintext_lenp = plaintext_len;
    return HWSUCCESS;
}


int main(int argc, char* argv[])
{
    printf("Entering engine test program...\n");

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    int status = 0;

#ifdef LOAD_ENGINE
    // store path to engine shared object
    const char* engine_so_path = argv[1];

    // load dynamic engine support
    ENGINE_load_dynamic(); 

    // (copy of the) instance of a generic "dynamic" engine that will magically morph into an instance of our
    // shared library engine once it is loaded by the LOAD command string 
    ENGINE *eng = ENGINE_by_id("dynamic");
    if (eng == NULL)
    {
        fprintf(stderr,"ERROR: Could not load engine \"dynamic\", ENGINE_by_id(\"dynamic\") == NULL\n");
        exit(1);
    }

    // BRIEF: Specify the path to our shared library engine, set the ID, and load it.
    // 
    // The "SO_PATH" control command should be used to identify the
    // shared-library that contains the ENGINE implementation, and "NO_VCHECK"
    // might possibly be useful if there is a minor version conflict and you
    // (or a vendor helpdesk) is convinced you can safely ignore it.
    // "ID" is probably only needed if a shared-library implements
    // multiple ENGINEs, but if you know the engine id you expect to be using,
    // it doesn't hurt to specify it (and this provides a sanity check if
    // nothing else). "LIST_ADD" is only required if you actually wish the
    // loaded ENGINE to be discoverable by application code later on using the
    // ENGINE's "id". For most applications, this isn't necessary - but some
    // application authors may have nifty reasons for using it
    // The "LOAD" command is the only one that takes no parameters and is the command
    // that uses the settings from any previous commands to actually *load*
    // the shared-library ENGINE implementation. If this command succeeds, the
    // (copy of the) 'dynamic' ENGINE will magically morph into the ENGINE
    // that has been loaded from the shared-library. As such, any control
    // commands supported by the loaded ENGINE could then be executed as per
    // normal. Eg. if ENGINE "foo" is implemented in the shared-library
    // "libfoo.so" and it supports some special control command "CMD_FOO", the
    // following code would load and use it (NB: obviously this code has no error checking);
    // 		ENGINE *e = ENGINE_by_id("dynamic");
    // 		ENGINE_ctrl_cmd_string(e, "SO_PATH", "/lib/libfoo.so", 0);
    // 		ENGINE_ctrl_cmd_string(e, "ID", "foo", 0);
    // 		ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
    // 		ENGINE_ctrl_cmd_string(e, "CMD_FOO", "some input data", 0);
    ENGINE_ctrl_cmd_string(eng, "SO_PATH", engine_so_path, 0);
    ENGINE_ctrl_cmd_string(eng, "ID", engine_id, 0);
    ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0);
    if (eng == NULL)
    {
        fprintf(stderr,"*TEST: ERROR, COULD NOT LOAD ENGINE:\n\tSO_PATH = %s\n\tID = %s\n", engine_so_path, engine_id);
        exit(1);
    }
    printf("wsaescbcEngine successfully loaded:\n\tSO_PATH = %s\n\tID = %s\n", engine_so_path, engine_id);

    // initialize engine 
    status = ENGINE_init(eng); 
    if (status < 0)
    {
        fprintf(stderr,"*TEST: ERROR, COULD NOT INITIALIZE ENGINE\n\tENGINE_init(eng) == %d\n",status);
        exit(1);
    }
    printf("*TEST: Initialized engine [%s]\n\tinit result = %d\n",ENGINE_get_name(eng), status);
#endif

   	uint8_t data[MAXBYTES];
	int datalen = strlen(teststr);

	uint8_t encrypted[MAXBYTES+1024];
	uint8_t decrypted[MAXBYTES+1024];
	uint32_t encrypted_length, decrypted_length;
		
    memcpy(data, teststr, datalen);

	status = wsencrypt( (uint8_t*)teststr, (uint32_t)strlen(teststr), (uint8_t*)key, 
                        (uint8_t*)iv, (uint8_t*)encrypted, &encrypted_length);
	if(0 != status || encrypted_length == 0) {
		printf("\nEncrypt failed");
		exit(EXIT_FAILURE);
    }

    status = wsdecrypt( (uint8_t*)encrypted, encrypted_length, (uint8_t*)key, 
                        (uint8_t*)iv, (uint8_t*)decrypted, &decrypted_length);
	if(0 != status || decrypted_length == 0) {
		printf("\nDecrypt failed");
		exit(EXIT_FAILURE);
    }

    int errcnt=0;
    for (int i=0; i < datalen; i++)
    {
        if (decrypted[i] != teststr[i])
        {
            errcnt++;
            printf("\t****Error, incorrect digest value at element %i!\n",i);
        }
    }

    // report erroneous values
    if (errcnt == 0)
        printf("****Test status: SUCCESS\n\n");
    else 
    {
        printf("****Test vector status: FAILED\n\n");
        return -1; 
    }  

    return HWSUCCESS;
}
