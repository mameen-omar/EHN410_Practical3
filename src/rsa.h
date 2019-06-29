/**
 * @file rsa.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief RSA library function prototype file. This file contains the necessary functionality to perform RSA key generation as well as encryption/decryption.
 * The functions in this file consist of RSA key generation, RSA encryption, RSA decryption, Getting prime numbers and writing the keys to a file.
 * 
 * @version 0.1
 * @date 2019-05-22
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#ifndef RSA_H
#define RSA_H

#include "randomNumberGenerator.h"
#include <math.h>
typedef struct {
    mpz_t p;    // prime
    mpz_t q; // prime
    mpz_t e; // e parameter
    mpz_t d; // d parameter
    mpz_t qn; // Q(n) - Euler's totient
    mpz_t n; // n= pq
    uint16_t numBits; // number of bits for the key to generate (public and private keys)
    unsigned char* initKey; 
    uint8_t initKeyLength; // length of RNG key
    mpz_t KU[2]; //e,n - Public 
    mpz_t KR[2]; //d,n - Private
} rsactx_t;

/**
 * @brief  rsaInit - Function used to initialize the RSA context state structure passed in as @param rsaCtx. Used as a helper function for 
 * the constructRSAContext function. Does not need to be explicitly called by the user. Initializes all mpz library variables used as required. 
 * 
 * @param rsaCtx - rsactx_t* - A pointer to the RSA context state structure to initialize. 
 */
void rsaInit(rsactx_t* rsaCtx); 

/**
 * @brief constructRSAContext - Function used to construct the RSA context structure used for RSA key-pair 
 * generation. The function allocates all memory required. In addition, the function initializes the random number generator (RC4 key stream) using the key passed in as 
 * @param initKey, used for the generation of the RSA key-pairs. The function calls rsaInit function to aid in initialization. The caller must 
 * use cleanRSA in order to deallocate all memory once the key-pair has been generated. 
 * 
 * @param unsigned char* - initKey - The key used to initialize the random number generator. 
 * @param initKeyLength - uint8_t - The length of the key passed in as @param initKey. 
 * @param isKeyHex - int - a flag indicating whether the key @param initKey is a hex string or ascii encoded string. 
 * @param numBits - int - the number of bits required for the public and private RSA key pair to be generated. 
 * @return rsactx_t* - A pointer to the RSA context structure used to store the state of the RSA key generation.
 */
rsactx_t* constructRSAContext(unsigned char* initKey, uint8_t initKeyLength, int isKeyHex, int numBits); 


/**
 * @brief rsaWriteKeysToFile - Function used to write the public and private keys store in the RSA Context passed in as @param rsaCtx, 
 * to the @param publicKeyFileName and @param privateKeyFileName respectively. The RSA private and public keys are written to the files in accordance with the practical specification. 
 * With the n paramter followed by a newline character, followed by d/e and finally a newline character.
 * 
 * @param rsaCtx - rsactx_t* - The RSA context containing the public and private key pair to be written. 
 * @param publicKeyFileName - unsigned char* - The file to write the RSA public key to. 
 * @param privateKeyFileName - unsigned char* - The file to write the RSA private key to.  
 */
void rsaWriteKeysToFile(rsactx_t* rsaCtx, unsigned char* publicKeyFileName, unsigned char* privateKeyFileName); 

/**
 * @brief generateRsaKeys - Function used to generate the RSA public and private key-pair according to the specifications within the 
 * RSA state passed in as @param rsaCtx. Makes use of the mpz libraries in order to compute the prime numbers used for the p and q variables used during 
 * RSA key generation. The function does check for negative values for the "d" parameter as a result of under and overflows and makes the required adjustments. 
 * Stores the RSA key pair and the parameters used during RSA key generation in the RSA state structure. 
 * 
 * @param rsaCtx - rsactx_t* - The RSA context state to use for the RSA key-pair generation. 
 */
void generateRsaKeys(rsactx_t* rsaCtx); 

/**
 * @brief rsaEncrypt - Function used to encrypt the plaintext passed in as @param plainText using RSA encryption and write the 
 * resulting ciphertext to the file @param outputFile in decimal. Function treats the entire plainText as the a single decimal value and performs
 * the RSA encryption. The function reads in the public key and writes the result to the output file. 
 * 
 * @param outputFile - unsigned char* - File to write the ciphertext to. 
 * @param publicKeyFile - unsigned char* - The file containing the public key to use during RSA encryption. The "n" paramter should be on the first
 *                          line, followed by the newline character thereafter the "e" paramter should be placed in the public key file. 
 * @param plainText - unsigned char*  - The plaintext to encrypt. 
 * @param isPlaintextHex - size_t - a flag used to indicate if the plaintext is encoded using ascii or hex encoding. 
 */
void rsaEncrypt(unsigned char* outputFile, unsigned char* publicKeyFile, unsigned char* plainText, size_t isPlaintextHex);

/**
 * @brief rsaDecrypt - Function used to decrypt the ciphertext passed in as @param cipherText using RSA decryption and write the 
 * resulting plaintext to the file @param outputFile as a string using ascii plaintext encoding. Function treats the entire cipherText as the a single decimal value and performs
 * the RSA decryption. The function reads in the private key and writes the result to the output file. 
 * 
 * @param outputFile - unsigned char* - File to write the plaintext to. 
 * @param privateKeyFile - unsigned char* - The file containing the private key to use during RSA decryption. The "n" paramter should be on the first
 *                          line, followed by the newline character thereafter the "d" paramter should be placed in the private key file. 
 * @param cipherText - unsigned char*  - The ciphertext to decrypt. 
 */
void rsaDecrypt(unsigned char* outputFile, unsigned char* privateKeyFile, unsigned char* cipherText);

/**
 * @brief getPrime - Function used to generate a prime number of length @param bits and store it in @param p. Used for 
 * RSA key-pair generation. @param bits should be half the length of the total length of the key required for the RSA keys. 
 * The function  generates @param bits - 1 random numbers using the RC4 random key stream generator
 * and uses the LSB of each random number generated as a bit in the in the final prime number. 
 * Once the random number of bits length is generated, the mpz_nextprime is used to get the closest prime number to the random 
 * number generated and store it in @param p. 
 * 
 * @param p 
 * @param bits 
 */
void getPrime(mpz_t p, int bits);

/**
 * @brief rsaClean - Function used to deallocate all memory allocated for the RSA context state structure in @param rsaCtx. 
 * In addition deallocates all memory used for the random number generator. 
 * @param rsaCtx - rsactx_t*  - The RSA context state to deallocate. 
 */
void rsaClean(rsactx_t* rsaCtx);

#endif