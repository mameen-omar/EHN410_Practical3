/**
 * @file rngTester.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief 
 * @version 0.1
 * @date 2019-05-23
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "randomNumberGenerator.h"


// valgrind --leak-check=full --show-leak-kinds=all -v ./rngTester
int main(int argc, char * argv[]) 
{

    printf("Random number generator\n");
    printf("Testing with input key 64 bits\n"); 

    unsigned char* key = "0123456789ABCDEF";
    uint8_t keylength = strlen(key) ;

    rseed(key, keylength,1); // is hex
    
    for(int x =0; x<10; x++) {
      U8 randomByte = rrand(); 
      printf("Byte %d is %02X\n", x+1, randomByte);
    }

    destroyRNG();

    printf("\nTesting with input key 128 bits\n"); 

    key = "0102030405060708090a0b0c0d0e0f10";
    keylength = strlen(key) ;

    rseed(key, keylength,1); // is hex
    
    for(int x =0; x<12; x++) {
      U8 randomByte = rrand(); 
      printf("Byte %d is %02X\n", x+1, randomByte);
    }

    destroyRNG();
    return 0; 
}