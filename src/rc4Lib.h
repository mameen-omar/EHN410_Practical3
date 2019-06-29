/**
 * @file rc4Lib.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief RC4 library function prototype file. This file is used to perform encryption/decryption using the rc4 stream cipher.
 * First an RC4 context is created using the constructRc4Context function.
 * rc4 is then initialised with the rc4Init - by passing in the init key + key length and indicating if the key is hex or not.
 * A byte of the key stream is received using the rc4GetByte (with the rc4 context) or encrypted/decrypted by using the appropriate function with the input and output file passed in.
 * 
 * @version 0.1
 * @date 2019-05-22
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#ifndef RC4LIB_H
#define RC4LIB_H

#include <stdio.h> 
#include <gmp.h> // for mpz_t
#include <stdarg.h>  // for mpz_t
#include <obstack.h>  // for mpz_t
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h> 
#include "textConverter.h"

#define RC4_STATE_SIZE 256 //256 bytes for the state

typedef unsigned char U8; // for the spec

/**
 * @brief struct rc4ctx_t - Structure used to retain the context of the RC4 key stream generator.
 * 
 */
typedef struct {
    U8 state[RC4_STATE_SIZE];
    uint16_t index1; // i
    uint16_t index2; // j
    
} rc4ctx_t;

/**
 * @brief constructRc4Context - Function to construct the RC4 context structure
 * and construct the state vector used for RC4 byte generation.
 * The user must use the function in order to initialize the RC4 state. The caller must also ensure that 
 * they use the member function destroyRc4Context in order to deallocate all memory once the RC4 structure is no longer
 * needed. 
 * 
 * @return rc4ctx_t* - a pointer to the rc4 context object created. 
 */
rc4ctx_t * constructRc4Context();

/**
 * @brief destroyRc4Context - Function used to deallocate all memory allocated for the 
 * rc4 context structure passed in as @param rc4Ctx. Sets the parameter @param rc4Ctx to NULL. 
 * 
 * @param rc4Ctx - The RC4 context structure to deallocate and clean. 
 */
void destroyRc4Context(rc4ctx_t * rc4Ctx); 

/**
 * @brief rc4Init - Function used to initialize the state of the RC4 context and the state vector used for the
 * RC4 byte generate. Requires the use of the function constructRc4Context in order to generate a RC4 context.
 *  If the initialization key provided in @param key is a hex string, it is converted to ascii string before initialization.
 * 
 * @param rc4Ctx - rc4ctx_t* - a pointer to the RC4 context structure to initialize. 
 * @param key - uint8_t* - a pointer to the initialization key to be used.  
 * @param keylen - int - the length of the key provided @param key.  
 * @param isKeyHex - uint8_t - a flag to determine if the key passed in as @param key is a hex string or ascii string.
 */
void rc4Init(rc4ctx_t* rc4Ctx, U8* key, int keylen, uint8_t isKeyHex); 

/**
 * @brief rc4GetByte - Function used to generate a single byte of the RC4 key stream for the RC4 context 
 * passed in as @param rc4Ctx. Returns the single byte as a single uint8_t.
 * 
 * @param rc4Ctx - rc4ctx_t* - a pointer to the RC4 context from which to generate the single byte. 
 * @return uint8_t - A single byte in the RC4 key stream. 
 */
U8 rc4GetByte(rc4ctx_t* rc4Ctx); 

/**
 * @brief swapStateElements - Function to swap the contents of the uint8_t pointers passed in as parameters
 * @param val1 and @param val2.
 * 
 * @param val1 - uint8_t* - pointer to a uint8_t variable whose contents to switch with @param val2. 
 * @param val2 - uint8_t* - pointer to a uint8_t variable whose contents to switch with @param val1. 
 */
void swapStateElements(U8* val1, U8* val2);

/**
 * @brief performRc4 - Function used to encrypt or decrypt the contents of the file @param inputFileName and write the result to the 
 * file @param outputFileName. The encryption or decryption is done using RC4 encryption or decryption. Each character in the input file is read in and a single byte 
 * for the RC4 key stream is generated. A single byte for the plaintext or Ciphertext and XOR'ed with a single byte from the RC4 key stream to generate
 * a the corresponding ciphertext or plaintext. The bytes used during the RC4 encryption or decryption are generated from the RC4 context passed in as @param rc4Ctx.
 * RC4 encryption 
 * 
 * @param inputFileName - unsigned char* - pointer to a string containing the path to the input file. 
 * @param outputFileName - unsigned char* - pointer to a string containing the path to the output file. 
 * @param rc4Ctx - rc4ctx_t* - a pointer to the RC4 context to use during encryption or decryption.
 * @param isTextHex - flag used to determine if the input is encoded using ascii or hex encoding. 
 */
void performRc4(unsigned char* inputFileName, unsigned char* outputFileName, rc4ctx_t* rc4Ctx, int isTextHex); 

#endif