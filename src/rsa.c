/**
 * @file rsa.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief RSA library implementation file. This file contains the necessary functionality to perform RSA key generation as well as encryption/decryption.
 * The functions in this file consist of RSA key generation, RSA encryption, RSA decryption, Getting prime numbers and writing the keys to a file.
 * 
 * @version 0.1
 * @date 2019-05-22
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "rsa.h"

/**
 * @brief @var CONSTANTE - The "e" parameter to use for RSA key generation.
 * 
 */
const int64_t CONSTANTE = 65537; 

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
rsactx_t* constructRSAContext(unsigned char* initKey, uint8_t initKeyLength, int isKeyHex, int numBits)
{
    rsactx_t* rsaCtx = malloc(sizeof(rsactx_t));
    rsaCtx->initKey = calloc(initKeyLength,sizeof(char));
    memcpy(rsaCtx->initKey,initKey,initKeyLength); 
    rsaCtx->initKeyLength = initKeyLength;
    // rng
    rseed(rsaCtx->initKey, rsaCtx->initKeyLength, isKeyHex); 
    rsaCtx->numBits = numBits;
    rsaInit(rsaCtx); 
    return rsaCtx; 
}

/**
 * @brief  rsaInit - Function used to initialize the RSA context state structure passed in as @param rsaCtx. Used as a helper function for 
 * the constructRSAContext function. Does not need to be explicitly called by the user. Initializes all mpz library variables used as required. 
 * 
 * @param rsaCtx - rsactx_t* - A pointer to the RSA context state structure to initialize. 
 */
void rsaInit(rsactx_t* rsaCtx)
{
    // init all for rsaCtX
    mpz_init(rsaCtx->p);    // prime - randomly generated
    mpz_init(rsaCtx->q); // prime - randomly generated
    mpz_init(rsaCtx->e); // e parameter
    mpz_init(rsaCtx->d); // d parameter
    mpz_init(rsaCtx->qn);  // Q(n) 
    mpz_init(rsaCtx->n);  // n 
    for(size_t x = 0; x<2;x++) {
        mpz_init(rsaCtx->KU[x]);
        mpz_init(rsaCtx->KR[x]);
    }     
}

/**
 * @brief generateRsaKeys - Function used to generate the RSA public and private key-pair according to the specifications within the 
 * RSA state passed in as @param rsaCtx. Makes use of the mpz libraries in order to compute the prime numbers used for the p and q variables used during 
 * RSA key generation. The function does check for negative values for the "d" parameter as a result of under and overflows and makes the required adjustments. 
 * Stores the RSA key pair and the parameters used during RSA key generation in the RSA state structure. 
 * 
 * @param rsaCtx - rsactx_t* - The RSA context state to use for the RSA key-pair generation. 
 */
void generateRsaKeys(rsactx_t* rsaCtx)
{
    printf("Generating RSA Public and Private Keys\n");
    if(rsaCtx == NULL) {
        printf("Error: The RSA context is empty.\nCannot Generate keys.\nExiting.");
        exit(EXIT_FAILURE);
    }

    // generate primes half the size of the number of bits required for the key
    getPrime(rsaCtx->p, rsaCtx->numBits/2); 
    getPrime(rsaCtx->q, rsaCtx->numBits/2);

    mpz_mul(rsaCtx->n, rsaCtx->p, rsaCtx->q); // n = pq

    mpz_t qTemp; 
    mpz_t pTemp; 
    mpz_init(qTemp); // used for q-1
    mpz_init(pTemp);  // used for p-1
    mpz_sub_ui(qTemp, rsaCtx->q, 1); // q-1
    mpz_sub_ui(pTemp, rsaCtx->p, 1); // p-1

    mpz_mul(rsaCtx->qn, qTemp, pTemp); // q(n) = (p-1)(q-1)
    mpz_clear(qTemp); 
    mpz_clear(pTemp); 
    mpz_set_ui(rsaCtx->e, CONSTANTE); // set static as per practical spec
    mpz_invert(rsaCtx->d,rsaCtx->e,rsaCtx->qn); // calc d

    if(mpz_sgn(rsaCtx->d) < 0) {
        mpz_add(rsaCtx->d, rsaCtx->d,rsaCtx->qn);
    }
    // set private and public 
    mpz_set(rsaCtx->KU[0], rsaCtx->e); 
    mpz_set(rsaCtx->KU[1], rsaCtx->n); 
    mpz_set(rsaCtx->KR[0], rsaCtx->d); 
    mpz_set(rsaCtx->KR[1], rsaCtx->n);
    
    gmp_printf("p: %Zd\n",rsaCtx->p);
    gmp_printf("q: %Zd\n",rsaCtx->q);
    gmp_printf("n: %Zd\n",rsaCtx->n);
    gmp_printf("qn: %Zd\n",rsaCtx->qn);    
    gmp_printf("e: %Zd\n",rsaCtx->e);
    gmp_printf("d: %Zd\n",rsaCtx->d);
    printf("End of RSA Public and Private Key generation\n");
} 

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
void getPrime(mpz_t p, int bits)
{
    unsigned char* binary = calloc(bits+1,sizeof(char));

    binary[0] = '1'; // set MSB to 1 to ensure that the generated prime is not too small

    for(size_t x = 1; x < bits; x++) {
        // generate a random number
        uint8_t randomByte = rrand();
        mpz_t placeholder; // used to convert the randomByte value to a binary string and extract the lsb
        mpz_init(placeholder);
        mpz_set_ui(placeholder,randomByte);
        printf("Random (hex): %X\n", randomByte);
        unsigned char* randomBinString = calloc(mpz_sizeinbase(placeholder, 2) + 2,sizeof(char));
        // convert the value in place holder to a binary string 
        mpz_get_str(randomBinString,2,placeholder);
        // store the LSB of the random number
        binary[x] = randomBinString[strlen(randomBinString)-1];
        // cleanup 
        free(randomBinString); 
        mpz_clear(placeholder); 
    }

    mpz_set_str(p,binary,2);
    printf("Random number in binary is: %s \n",binary);
    gmp_printf("The random number (base 10): %Zd\n",p);
    free(binary);
    mpz_nextprime(p,p);
    gmp_printf("The prime number (base10): %Zd \n\n",p);
}

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
void rsaEncrypt(unsigned char* outputFile, unsigned char* publicKeyFile, unsigned char* plainText, size_t isPlaintextHex)
{
    printf("Starting RSA Encryption\n");
    // read in the public key 
    FILE *outputFilePtr = NULL;
    FILE *publicKeyFilePtr = NULL;
    outputFilePtr = fopen(outputFile, "w");

    if(outputFilePtr == NULL) {
        printf("Error: Could not open output file : %s\n", outputFile);
        exit(EXIT_FAILURE); 
    }

    publicKeyFilePtr = fopen(publicKeyFile, "r");

    if(publicKeyFilePtr == NULL) {
        printf("Error: Could not open public key file: %s\n", publicKeyFile);
        fclose(outputFilePtr); 
        exit(EXIT_FAILURE); 
    }

    mpz_t n;
    mpz_init(n);
    mpz_t encrypted;
    mpz_init(encrypted);
    mpz_t e;
    mpz_init(e);

    size_t keyCount = 0; 
    while(gmp_fscanf(publicKeyFilePtr, "%Zd", encrypted)!= EOF && keyCount < 2)
    {    
        if(keyCount==0) {
            mpz_set(n,encrypted);
            gmp_printf("n (in decimal) = %Zd\n",n);
        } 
        if(keyCount==1) {
            mpz_set(e,encrypted);
            gmp_printf("e (in decimal) = %Zd\n",e);
        }	
        keyCount++;
    }
    // WE HAVE N AND E HERE
    // we have plaintext here as well in ascii 
    mpz_t toEncrypt;
    mpz_init(toEncrypt);
    printf("Plaintext to encrypt: %s\n", plainText);

    // import the string in ascii as a single integer 
    mpz_import(toEncrypt, 16, 1, sizeof(char), 1, 0, plainText);
    gmp_printf("Imported plaintext in base 10: %Zd\n", toEncrypt);
    // do encryption
    mpz_powm(encrypted,toEncrypt,e,n);
    gmp_fprintf(outputFilePtr, "%Zd", encrypted); // written to the file in base 10
    gmp_printf("Encrypted in base 10: %Zd\n", encrypted);

    mpz_clear(n);
    mpz_clear(encrypted);
    mpz_clear(e);
    mpz_clear(toEncrypt);

    if(publicKeyFilePtr != NULL) {
        fclose(publicKeyFilePtr);
    }

    if(outputFilePtr != NULL) {
        fclose(outputFilePtr);
    }

    printf("End RSA Encryption\n");
}

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
void rsaDecrypt(unsigned char* outputFile, unsigned char* privateKeyFile, unsigned char* cipherText)
{
    printf("Start RSA Decryption\n");
    // read in the private key 
    FILE *outputFilePtr = NULL;
    FILE *privateKeyFilePtr = NULL;
    outputFilePtr = fopen(outputFile, "w");

    if(outputFilePtr == NULL) {
        printf("Error: Could not open output file : %s\n", outputFile);
        exit(EXIT_FAILURE); 
    }

    privateKeyFilePtr = fopen(privateKeyFile, "r");

    if(privateKeyFilePtr == NULL) {
        printf("Error: Could not open public key file: %s\n", privateKeyFile);
        fclose(outputFilePtr); 
        exit(EXIT_FAILURE); 
    }

    mpz_t n;
    mpz_init(n);
    mpz_t decrypted;
    mpz_init(decrypted);
    mpz_t d;
    mpz_init(d);

    size_t keyCount = 0; 
    while(gmp_fscanf(privateKeyFilePtr, "%Zd", decrypted)!= EOF && keyCount < 2)
    {
        
        if(keyCount==0) {
            mpz_set(n,decrypted);
            gmp_printf("n = %Zd\n",n);
        } 
        if(keyCount==1) {
            mpz_set(d,decrypted);
            gmp_printf("d = %Zd\n",d);
        }	
        keyCount++;
    }
    // we have d, n and the ciphertext 

    mpz_t toDecrypt;
    mpz_init(toDecrypt);
    printf("Ciphertext to decrypt: %s\n", cipherText);
    mpz_set_str(toDecrypt,cipherText,10);
    gmp_printf("Imported ciphertext in base 10: %Zd\n", toDecrypt);   
    mpz_powm(decrypted,toDecrypt,d,n);
    gmp_printf("Decrypted ciphertext (plaintext) is (Base 10) %Zd\n",decrypted);

    char* decryptedText = NULL;
    size_t sizeofDecryptedText;
    decryptedText = (char*) mpz_export(NULL,&sizeofDecryptedText, 1, sizeof(char), 1, 0, decrypted);
    printf("Size of decrypted text is: %ld\n", sizeofDecryptedText);
    printf("Decrypted ciphertext (plaintext) in ascii is: %s\n",decryptedText);
    int bytesToWrite = 0;
    for(; bytesToWrite<sizeofDecryptedText;bytesToWrite++) {
        if((int) decryptedText[bytesToWrite] == 0)
            break;
    }
    fwrite(decryptedText, sizeof(char), bytesToWrite, outputFilePtr);
    mpz_clear(n);
    mpz_clear(decrypted);
    mpz_clear(d);
    mpz_clear(toDecrypt);
    free(decryptedText);

    if(privateKeyFilePtr != NULL) {
        fclose(privateKeyFilePtr);
    }

    if(outputFilePtr != NULL) {
        fclose(outputFilePtr);
    }

    printf("End RSA Decryption\n");
}

/**
 * @brief rsaWriteKeysToFile - Function used to write the public and private keys store in the RSA Context passed in as @param rsaCtx, 
 * to the @param publicKeyFileName and @param privateKeyFileName respectively. The RSA private and public keys are written to the files in accordance with the practical specification. 
 * With the n paramter followed by a newline character, followed by d/e and finally a newline character.
 * 
 * @param rsaCtx - rsactx_t* - The RSA context containing the public and private key pair to be written. 
 * @param publicKeyFileName - unsigned char* - The file to write the RSA public key to. 
 * @param privateKeyFileName - unsigned char* - The file to write the RSA private key to.  
 */
void rsaWriteKeysToFile(rsactx_t* rsaCtx, unsigned char* publicKeyFileName, unsigned char* privateKeyFileName)
{
    if(rsaCtx == NULL) {
        printf("Error RSA Conext is NULL.\nCannot write keys to file.\nExiting.\n"); 
        exit(EXIT_FAILURE);
    }

    FILE *publicKeyFilePtr;
    publicKeyFilePtr = fopen(publicKeyFileName, "w"); //read as a binary file
    if(publicKeyFilePtr == NULL) {
        printf("Error - Could not open public key file.\nCannot write keys to file.\nExiting.\n"); 
        exit(EXIT_FAILURE);
    }

    FILE *privateKeyFilePtr;
    privateKeyFilePtr = fopen(privateKeyFileName, "w"); //read as a binary file
    if(privateKeyFilePtr == NULL) {
        printf("Error - Could not open private key file.\nCannot write keys to file.\nExiting.\n"); 
        exit(EXIT_FAILURE);
    }

    // write public
    gmp_fprintf(publicKeyFilePtr,"%Zd\n%Zd\n",rsaCtx->KU[1],rsaCtx->KU[0]);

    // Write private
    gmp_fprintf(privateKeyFilePtr,"%Zd\n%Zd\n",rsaCtx->KR[1],rsaCtx->KR[0]);

    // close all files
    fclose(publicKeyFilePtr); 
    fclose(privateKeyFilePtr);
}

/**
 * @brief rsaClean - Function used to deallocate all memory allocated for the RSA context state structure in @param rsaCtx. 
 * In addition deallocates all memory used for the random number generator. 
 * @param rsaCtx - rsactx_t*  - The RSA context state to deallocate. 
 */
void rsaClean(rsactx_t* rsaCtx)
{
    if(rsaCtx == NULL) {
        return; 
    }
    mpz_clear(rsaCtx->p);    // prime
    mpz_clear(rsaCtx->q); // prime
    mpz_clear(rsaCtx->e); // e parameter
    mpz_clear(rsaCtx->d); // d parameter
    mpz_clear(rsaCtx->qn);  // Q(n)  
    mpz_clear(rsaCtx->n);   
    for(size_t x = 0; x<2;x++) {
        mpz_clear(rsaCtx->KU[x]);
        mpz_clear(rsaCtx->KR[x]);
    }
    if(rsaCtx->initKey != NULL) {
        free(rsaCtx->initKey); 
        rsaCtx->initKey = NULL;
        rsaCtx->initKeyLength = 0;
    }
    // destroy the rng
    destroyRNG(); 
    rsaCtx->numBits = 0;
    free(rsaCtx); 
    rsaCtx = NULL;
}