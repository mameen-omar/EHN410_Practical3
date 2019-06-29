/**
 * @file rc4LibTester.c
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
#include "rc4Lib.h" 
#include "stdio.h"

void print16Bytes(rc4ctx_t* rc4Ctx)
{
    for(int x = 0; x< 16 ;x++) {
        if(x%4 == 0){
            printf("  "); 
        }
        printf("%02x\t", rc4GetByte(rc4Ctx)); 
    }
}

void printTestOutput(rc4ctx_t* rc4Ctx)
{
    for(int x = 0; x< 4112 ;x+=16)
    {
        printf("Byte: %d:\t", x); 
        print16Bytes(rc4Ctx);
        printf("\n");
    }    
}

// valgrind --leak-check=full --show-leak-kinds=all -v ./rc4Tester


int main(int argc, char * argv[]) 
{
    // printf("RC4 Tester\n\n");

    // /***** https://tools.ietf.org/html/rfc6229 **/ // -- Tester file
    
    rc4ctx_t* rc4Ctx = constructRc4Context();
    unsigned char* tempKey = "0102030405"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 40 bits.\nkey: 0102030405\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);
    
    /*
        Key length: 56 bits.
        key: 0x01020304050607
    */
    rc4Ctx = constructRc4Context();
    tempKey = "01020304050607"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 56 bits.\nkey: 0x0102030405\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 64 bits.
        key: 0x0102030405060708
    */
    rc4Ctx = constructRc4Context();
    tempKey = "0102030405060708"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 64 bits.\nkey: 0102030405060708\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
         Key length: 80 bits.
        key: 0x0102030405060708090a
    */
    rc4Ctx = constructRc4Context();
    tempKey = "0102030405060708090a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 80 bits.\nkey: 0102030405060708090a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);


    /*
        Key length: 128 bits.
        key: 0x0102030405060708090a0b0c0d0e0f10
    */
    rc4Ctx = constructRc4Context();
    tempKey = "0102030405060708090a0b0c0d0e0f10"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 128  bits.\nkey: 0102030405060708090a0b0c0d0e0f10\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
         Key length: 192 bits.
        key: 0x0102030405060708090a0b0c0d0e0f101112131415161718
    */
    rc4Ctx = constructRc4Context();
    tempKey = "0102030405060708090a0b0c0d0e0f101112131415161718"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 192  bits.\nkey: 0102030405060708090a0b0c0d0e0f101112131415161718\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 256 bits.
        key: 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
    */
    rc4Ctx = constructRc4Context();
    tempKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 256  bits.\nkey: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
         Key length: 40 bits.
        key: 0x833222772a
    */

    rc4Ctx = constructRc4Context();
    tempKey = "833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1);
    printf("Key length: 40 bits.\nkey: 833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 56 bits.
        key: 0x1910833222772a
    */

    rc4Ctx = constructRc4Context();
    tempKey = "1910833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1); // is hex
    printf("Key length: 56 bits.\nkey: 1910833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*

        Key length: 64 bits.
        key: 0x641910833222772a
    */

    rc4Ctx = constructRc4Context();
    tempKey = "641910833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1); // is hex
    printf("Key length: 64 bits.\nkey: 641910833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 80 bits.
        key: 0x8b37641910833222772a
    */

    rc4Ctx = constructRc4Context();
    tempKey = "8b37641910833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1); // is hex
    printf("Key length: 80 bits.\nkey: 8b37641910833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 128 bits.
        key: 0xebb46227c6cc8b37641910833222772a

    */

    rc4Ctx = constructRc4Context();
    tempKey = "ebb46227c6cc8b37641910833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1); // is hex
    printf("Key length: 128 bits.\nkey: ebb46227c6cc8b37641910833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 192 bits.
        key: 0xc109163908ebe51debb46227c6cc8b37641910833222772a
    */

    rc4Ctx = constructRc4Context();
    tempKey = "c109163908ebe51debb46227c6cc8b37641910833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1); // is hex
    printf("Key length: 192 bits.\nkey: c109163908ebe51debb46227c6cc8b37641910833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);

    /*
        Key length: 256 bits.
        key: 0x1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a
    */

    rc4Ctx = constructRc4Context();
    tempKey = "1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a"; 
    rc4Init(rc4Ctx,tempKey,strlen(tempKey),1); // is hex
    printf("Key length: 192 bits.\nkey: 1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a\n");
    printTestOutput(rc4Ctx); 
    printf("\n");
    destroyRc4Context(rc4Ctx);
    // rc4ctx_t* rc4Ctx = constructRc4Context();
    // unsigned char* tempKey = "Hello"; 
    // rc4Init(rc4Ctx,tempKey, strlen(tempKey), 0); 
    // //rc4EncryptFile("hello.txt", "encrypted",  rc4Ctx,1); 
    // printf("%d\n",rc4GetByte(rc4Ctx));
    // destroyRc4Context(rc4Ctx);
    return 0; 
}