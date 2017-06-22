#pragma once

//typedef int int32_t;
//typedef unsigned char uint8_t;

/* AES-256 -- returns a status value */

#define AESMAXDATASIZE 256
#define AESBLKSIZE 16
#define AESIVSIZE 16
#define AESKEYSIZE 32

typedef enum { RESET = 0, ENCRYPT, DECRYPT, SET_IV, SET_KEY } ciphermode_t;

int32_t aes256init(void);
int32_t aes256setkey(uint8_t *keyp);
int32_t aes256setiv(uint8_t *keyp); 
int32_t aes256(int mode,uint8_t *inp, uint32_t inlen,uint8_t *outp,uint32_t *outlenp);
