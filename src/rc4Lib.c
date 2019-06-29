/**
 * @file rc4Lib.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief RC4 library implementation file. This file is used to perform encryption/decryption using the rc4 stream cipher.
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
#include "rc4Lib.h"

/**
 * @brief constructRc4Context - Function to construct the RC4 context structure
 * and construct the state vector used for RC4 byte generation.
 * The user must use the function in order to initialize the RC4 state. The caller must also ensure that 
 * they use the member function destroyRc4Context in order to deallocate all memory once the RC4 structure is no longer
 * needed. 
 * 
 * @return rc4ctx_t* - a pointer to the rc4 context object created. 
 */
rc4ctx_t * constructRc4Context() 
{
    printf("Constructing RC4 Context\n");
    rc4ctx_t* rc4Ctx = malloc(sizeof(rc4ctx_t));

    for(size_t x = 0; x < RC4_STATE_SIZE; x++) {
        rc4Ctx->state[x] = 0;
    }
    rc4Ctx->index1 = 0;     
    rc4Ctx->index2 = 0; 

    return rc4Ctx; 
}


/**
 * @brief destroyRc4Context - Function used to deallocate all memory allocated for the 
 * rc4 context structure passed in as @param rc4Ctx. Sets the parameter @param rc4Ctx to NULL. 
 * 
 * @param rc4Ctx - The RC4 context structure to deallocate and clean. 
 */
void destroyRc4Context(rc4ctx_t * rc4Ctx)
{
    if(rc4Ctx == NULL) {
        return; 
    }
    free(rc4Ctx); 
    rc4Ctx = NULL;
}

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
void rc4Init(rc4ctx_t* rc4Ctx, U8* key, int keylen, uint8_t isKeyHex)
{
    unsigned char* asciiKey; 
    // if hex convert to ascii
    if(isKeyHex) {
        asciiKey = keyHexToAscii(key,keylen);
        keylen = keylen/2;
    } else {
        asciiKey = key;
    }

    for(rc4Ctx->index1 = 0; rc4Ctx->index1 < RC4_STATE_SIZE; rc4Ctx->index1++) {
        rc4Ctx->state[rc4Ctx->index1] =  rc4Ctx->index1;
    }

    rc4Ctx->index2 = 0;

    for(rc4Ctx->index1 = 0; rc4Ctx->index1 < RC4_STATE_SIZE; rc4Ctx->index1++) {
        rc4Ctx->index2 = (rc4Ctx->index2 + rc4Ctx->state[rc4Ctx->index1] + asciiKey[rc4Ctx->index1 % keylen]) % 256;
        swapStateElements(&rc4Ctx->state[rc4Ctx->index1], &rc4Ctx->state[rc4Ctx->index2]);
    }
    
    rc4Ctx->index2 = 0;
    rc4Ctx->index1 = 0;    

    if(isKeyHex) {
        free(asciiKey);
    }
}

/**
 * @brief rc4GetByte - Function used to generate a single byte of the RC4 key stream for the RC4 context 
 * passed in as @param rc4Ctx. Returns the single byte as a single uint8_t.
 * 
 * @param rc4Ctx - rc4ctx_t* - a pointer to the RC4 context from which to generate the single byte. 
 * @return uint8_t - A single byte in the RC4 key stream. 
 */
uint8_t rc4GetByte(rc4ctx_t* rc4Ctx) 
{
    rc4Ctx->index1 = (rc4Ctx->index1 + 1) % 256; 
    rc4Ctx->index2 = (rc4Ctx->index2 + rc4Ctx->state[rc4Ctx->index1]) % 256;
    swapStateElements(&rc4Ctx->state[rc4Ctx->index1], &rc4Ctx->state[rc4Ctx->index2]); 
    return (U8) rc4Ctx->state[(rc4Ctx->state[rc4Ctx->index1] + rc4Ctx->state[rc4Ctx->index2]) % 256]; 
}

/**
 * @brief swapStateElements - Function to swap the contents of the uint8_t pointers passed in as parameters
 * @param val1 and @param val2.
 * 
 * @param val1 - uint8_t* - pointer to a uint8_t variable whose contents to switch with @param val2. 
 * @param val2 - uint8_t* - pointer to a uint8_t variable whose contents to switch with @param val1. 
 */
void swapStateElements(U8* val1, U8* val2)
{
    uint8_t temp = *val1; 
    *val1 = *val2;
    *val2 = temp;
}


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
void performRc4(unsigned char* inputFileName, unsigned char* outputFileName, rc4ctx_t* rc4Ctx, int isTextHex)
{
    printf("Start RC4 File Encryption or decryption\n");
    
    FILE *inputFilePointer;
    inputFilePointer = fopen(inputFileName, "rb"); //read as a binary file

    if(inputFilePointer == NULL) {
        printf("Error: Inputfile not found, exiting\n");
        exit(EXIT_FAILURE);
    }

    FILE *outputFilePointer;
    outputFilePointer = fopen(outputFileName, "wb"); // open file
    
     if(outputFilePointer == NULL) {
        printf("Error: Could not create output file, exiting\n");
        exit(EXIT_FAILURE);
    }

    unsigned char* plainTextBlock;
    size_t readBufferLength; 
    

    if(isTextHex) {
        unsigned char* tempText = calloc(2, sizeof(char));
        readBufferLength = fread(tempText, sizeof(char), 2, inputFilePointer); // read 2 hex vals at a time
        plainTextBlock = calloc(1, sizeof(char));
        readBufferLength = readBufferLength/2;
        hexToAsciiString(tempText,plainTextBlock,readBufferLength*2);
        free(tempText);
    } else {
        plainTextBlock = calloc(1, sizeof(char));
        readBufferLength = fread(plainTextBlock, sizeof(char), 1, inputFilePointer); // read 1 chars at a time - 128 bits
    }
    
    unsigned char cipherTextBlock;
    int counter = 0; 
    while(readBufferLength > 0) {
        
        // encrypt result
        uint8_t tempKey = rc4GetByte(rc4Ctx); 
        cipherTextBlock = *plainTextBlock ^ tempKey;
        printf("------------------------------------------------\n");
        printf("Encrypting/Decrypting Block number : %d\n", counter+1);
        printf("Block to be encrypted/decrypted (hex): %X\n", plainTextBlock[0]); 
        printf("Key to use for current block(hex): %X\n", tempKey);
        printf("Result of encryption/decryption (in hex): %X\n", cipherTextBlock);
        counter++; 
        printf("------------------------------------------------\n");
        // write only the ascii
        int temp = fwrite(&cipherTextBlock,sizeof(unsigned char),1, outputFilePointer); // write one char at a time 
        free(plainTextBlock); 

        // read next plaintext block
        if(isTextHex) {
            unsigned char* tempText = calloc(2, sizeof(char));
            readBufferLength = fread(tempText, sizeof(char), 2, inputFilePointer); // read 2 hex vals at a time
            plainTextBlock = calloc(1, sizeof(char));
            readBufferLength = readBufferLength/2;
            hexToAsciiString(tempText,plainTextBlock,readBufferLength*2);
            free(tempText);
        } else {
            plainTextBlock = calloc(1, sizeof(char));
            readBufferLength = fread(plainTextBlock, sizeof(char), 1, inputFilePointer); // read 1 chars at a time
        }    
    }
    
    printf("End RC4 File Encryption or decryption\n");
    free(plainTextBlock); 
    fclose(outputFilePointer); 
    fclose(inputFilePointer); 
}   