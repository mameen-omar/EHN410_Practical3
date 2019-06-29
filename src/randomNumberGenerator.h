/**
 * @file randomNumberGenerator.h
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief Random number generator function prototype file. This file is used to generate random numbers
 * to be used in the RSA generation. The random number generator takes in a specified seed value.
 * rseed is used to initialise. The rrand is used to retrieve a single byte from the random number generator.
 * After completion, the destroyRNG function must be executed.
 * 
 * @version 0.1
 * @date 2019-05-22
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "rc4Lib.h"

/**
 * @brief var - rngContext - The RC4 context state used for random number generation. 
 */
rc4ctx_t* rngContext; 

/**
 * @brief rseed - Function used to create a random number generator object and set the seed for the
 * random number generator. 
 * 
 * @param key - uint8_t* - The key used to seed the random number generator. 
 * @param keylen - The length of the key @param key. 
 * @param isKeyHex - flag used to indicate if the key @param key is hex or ascii encoded. 
 */
void rseed(U8* key, int keylen, int isKeyHex);

/**
 * @brief rrand - Function used to generate a random number of a single byte long. 
 * @return U8 - A random number of 8 bits long. 
 */
U8 rrand(); 

/**
 * @brief destroyRNG - Function used to deallocate all memory allocated for the random number generator, 
 * specifically the RC4 key stream state context structure. 
 * 
 */
void destroyRNG(); 