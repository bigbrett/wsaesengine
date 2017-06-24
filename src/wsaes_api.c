/**
 * @file   testwsaescbckern.c
 * @author Derek Molloy
 * @date   7 April 2015
 * @version 0.1
 * @brief  A Linux user space program that communicates with the wsaescbckern.c LKM. It passes a
 * string to the LKM and reads the response from the LKM. For this example to work the device
 * must be called /dev/wsaeschar.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
 */
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

static const char *devicefname = "/dev/wsaeschar";

/*
 *
 */
int32_t aes256init(void)
{
    printf("Checking for kernel module...\n");
    if( access( devicefname, F_OK ) != -1 ) 
    {
        printf("Found device!\n");
        return 0;
    } 
    else 
    {
        fprintf(stderr, "ERROR: Couldn't find device %s\n", devicefname);
        return -1; 
    }
}


/*
 *
 */
int32_t aes256setkey(uint8_t *keyp)
{
    int fd, ret = 0;
    
    // Open the device with read/write access
    fd = open("/dev/wsaeschar", O_RDWR);             
    if (fd < 0){
        perror("ERROR: Failed to open the device...");
        return errno;
    }

    //printf("setting key\n");
    ret = ioctl(fd, IOCTL_SET_MODE, SET_KEY); // switch mode 
    if (ret < 0) {
        perror("Failed to set mode.");
        return errno;
    }
    ret = write(fd, keyp, AESKEYSIZE); // write key 
    if (ret < 0) {
        perror("Failed to write KEY to the device.");
        return errno;
    }

    // close and exit
    if(close(fd)<0)
        perror("aescbc: Error closing file");

    return 0;
}


/*
 *
 */
int32_t aes256setiv(uint8_t *ivp)
{
    int fd, ret = 0;
    // Open the device with read/write access
    fd = open("/dev/wsaeschar", O_RDWR);             
    if (fd < 0){
        perror("ERROR: Failed to open the device...");
        return errno;
    }

    //printf("setting IV\n");
    ret = ioctl(fd, IOCTL_SET_MODE, SET_IV); // switch mode 
    if (ret < 0) {
        perror("Failed to set mode.");
        return errno;
    }
    ret = write(fd, ivp, AESIVSIZE); // write IV
    if (ret < 0) {
        perror("Failed to write IV to the device.");
        return errno;
    }
    
    // close and exit
    if(close(fd)<0)
        perror("aescbc: Error closing file");

    return 0;
}


/*
 * 
 */
int32_t aes256(int mode, uint8_t *inp, uint32_t inlen, uint8_t *outp, uint32_t *lenp) 
{
    int32_t fd, ret;

    // check bounds against max length 
    if (inlen > AESMAXDATASIZE)
    {
        fprintf(stderr, "ERROR: Provided data length (%d) too large, must be less than %d bytes\n",
                inlen, AESMAXDATASIZE);
        return -1;
    }
    else if (0 >= inlen)
    {
        fprintf(stderr, "ERROR: Provided data length (%d) too small, must be at least 1 bytes\n",
                inlen);
        return -1;
    }

    // Open the device with read/write access
    fd = open("/dev/wsaeschar", O_RDWR);             
    if (fd < 0){
        perror("ERROR: Failed to open the device...");
        return errno;
    }

    // Reset block 
    ret = ioctl(fd, IOCTL_SET_MODE, RESET); 
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
    uint8_t lastblock[AESBLKSIZE]; // the last block to send if we are encrypting ONLY.  

    // if we are encrypting the data, we must deal with padding the data to encrypt
    if (mode == ENCRYPT)
    {
        int modlen = inlen % AESBLKSIZE;     // number of data bytes in last block
        int numpadbytes = AESBLKSIZE-modlen; // number of padding bytes in last block

        // set output length to the nearest non-zero multiple of the block size
        *lenp = inlen + numpadbytes; 

        // loop boundary for looping through the blocks
        orignumbytes = *lenp - AESBLKSIZE;

        // Construct the "last block" of data to send, composed of the last straggling bytes that don't fit evenly into the 
        // 16-byte block size. This "last block" is padded out to the block size with a number of "padding bytes", whose values 
        // are all set to the number of padding bits required. So there will be X bytes with a value of X. The value of the 
        // padding bytes are all the same, and is just the number of padding bytes required to fill out the last 16-byte block. 
        // So if there are 4 data bytes (0xBE 0xEE 0xEE 0xEF) left to send in the last block, we then need 12 padding bytes, each
        // with the value of value 0x0C (or 12, in base 10). If the data length is an integer multiple of the block size, then 
        // we just send the message, and the "last block" is 16 bytes of just padding bits (0x10, decimal 16)
        for (int i=0; i<AESBLKSIZE; i++)
            lastblock[i] = (i < modlen) ? inp[orignumbytes + i] : numpadbytes;
    }     
    else 
    { // we are not incrypting, so don't need to pad data. Data length is unmodified, just loop through the input data
        *lenp = inlen;
        orignumbytes = inlen;
    }

    // initialize output memory to all zeros
    memset((void*)outp,0,*lenp);
   
    // MAIN DATA SENDING LOOP: 
    // send each complete 16-byte block of data to the LKM for processing and read back the result
    for (int i=0; i<orignumbytes; i+=AESBLKSIZE)
    {
        // send 16 byte block from caller to AES block
        ret = write(fd, &(inp[i]), AESBLKSIZE); 
        if (ret < 0) {
            perror("ERROR: Failed to write data to the AES block... ");   
            return errno;                                                      
        }

        // read back processed 16 byte block into caller memory from AES block
        ret = read(fd, &(outp[i]), AESBLKSIZE);
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
        ret = read(fd, &(outp[orignumbytes]), AESBLKSIZE);
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

    return 0;
}

