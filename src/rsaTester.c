/**
 * @file rsaTester.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief 
 * @version 0.1
 * @date 2019-05-22
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "rsa.h"

int main(int argc, char * argv[]) 
{
    printf("Testing RSA KEY GEN for p and q from spec - Example 1\n");
    
    unsigned char* key = "0123456789ABCDEF"; 
    int numBits = 18; // number of bits for the generated key    
    rsactx_t* rsaCtx = constructRSAContext(key,strlen(key),1,numBits);
    generateRsaKeys(rsaCtx);
    rsaWriteKeysToFile(rsaCtx,"public", "private");
    rsaClean(rsaCtx); 

    printf("\nTesting RSA KEY GEN for p and q from spec - Example 2\n");
    key = "99775533"; 
    numBits = 512; // number of bits for the generated key
    rsaCtx = constructRSAContext(key,strlen(key),1,numBits);
    generateRsaKeys(rsaCtx);
    rsaWriteKeysToFile(rsaCtx,"public2.txt", "private2.txt");
    rsaClean(rsaCtx); 

    unsigned char * publickeyfile = "public2.txt";
    unsigned char* privatekeyfile = "private2.txt"; 
    unsigned char* keyToEncrypt = calloc(16,sizeof(char));
    strncpy(keyToEncrypt,"ABCDE", 16);
    int isKeyHex = 0; // not hex
    rsaEncrypt("outputfileName", publickeyfile, keyToEncrypt, isKeyHex); 


    char* cipherText = "1393958342843770964882857715243865576338215821071691339527132793070324115118981938752399997903965951290697100436145009528254792521401395109712542266237964";
    free(keyToEncrypt);
    rsaDecrypt("outputFile",privatekeyfile, cipherText);
    return 0; 
}