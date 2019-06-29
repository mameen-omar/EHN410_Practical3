/**
 * @file rsakeygen.c
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
#include "rsakeygen.h"

int main(int argc, char * argv[]) 
{   
     if(argc <= 1) {
        printHelp();
        exit(EXIT_FAILURE);
    }
    const size_t RC4KEYLENGTH = 16; 
    uint8_t isKeyHex = 1; // default is hex
    unsigned char* publickeyfile = NULL; 
    unsigned char* privatekeyfile = NULL; 
    unsigned char* keyFile = NULL; 
    unsigned char* key = NULL; 
    size_t bits = 0; 
    size_t keyLen = 0;

    for(int x = 1; x < argc;) {
        if(strcmp(argv[x], "-b") == 0) {
            verifyArgument(x,argc,"number of bits");
            unsigned char* numBitsString = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(numBitsString,argv[x+1], strlen(argv[x+1]));
            for(size_t counter = 0; counter <strlen(numBitsString); counter++) {
                if(isdigit(numBitsString[counter]) == 0 ) {
                    printf("Error, bits specified is not a digit\n");
                    printHelp();
                    clearMemory(publickeyfile,privatekeyfile,keyFile,key);
                    free(numBitsString); 
                    exit(EXIT_FAILURE);
                }
            }
            bits = atoi(numBitsString);
            printf("Number of bits specified as %d\n", (int)bits);    
            free(numBitsString);         
            x+=2;
        } else if(strcmp(argv[x], "-KU") == 0) {
            verifyArgument(x,argc,"public key file");
            publickeyfile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(publickeyfile,argv[x+1],strlen(argv[x+1]));
            printf("public key file specified as %s\n", publickeyfile);
            x+=2;
        } else if(strcmp(argv[x], "-KR") == 0) {
            verifyArgument(x,argc,"private key file");
            privatekeyfile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(privatekeyfile,argv[x+1],strlen(argv[x+1]));
            printf("private key file specified as %s\n", privatekeyfile);
            x+=2;
        } else if(strcmp(argv[x], "-key") == 0) {
            verifyArgument(x,argc,"key");
            key = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(key,argv[x+1],strlen(argv[x+1]));
            printf("key specified as %s\n", key);
            keyLen = strlen(key);
            x+=2;
        } else if(strcmp(argv[x], "-kf") == 0) {
            verifyArgument(x,argc,"key file");
            keyFile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(keyFile,argv[x+1],strlen(argv[x+1]));
            printf("key file specified as %s\n", keyFile);
            x+=2;
        } else if(strcmp(argv[x], "-ascii") == 0) {
            isKeyHex = 0; 
            printf("Key is specified as ascii\n");
            x+=2;
        } else if(strcmp(argv[x], "-h") == 0) {
            printf("Help menu requested\n");
            printHelp();
            clearMemory(publickeyfile,privatekeyfile,keyFile,key);
            exit(EXIT_SUCCESS); 
        } else {
            printf("Argument %s is not recognized\n", argv[x]);
            printHelp();
            clearMemory(publickeyfile,privatekeyfile,keyFile,key);
            exit(EXIT_FAILURE);
        }
    }
    
    if(bits <= 0) {
        printf("Error number of bits for RSA key is not specified or is invalid\n"); 
        printHelp();
        clearMemory(publickeyfile,privatekeyfile,keyFile,key);
        exit(EXIT_FAILURE);
    }

    if(publickeyfile == NULL || strlen(publickeyfile) <= 0) {
        printf("Error public key file has not been specified\n"); 
        printHelp();
        clearMemory(publickeyfile,privatekeyfile,keyFile,key);
        exit(EXIT_FAILURE);
    }

    if(privatekeyfile == NULL || strlen(privatekeyfile) <= 0) {
        printf("Error private key file has not been specified\n"); 
        printHelp();
        clearMemory(publickeyfile,privatekeyfile,keyFile,key);
        exit(EXIT_FAILURE);
    }

    if(key != NULL && keyFile != NULL) {
        printf("Error both the key and a keyfile have been specified\n"); 
        printHelp();
        clearMemory(publickeyfile,privatekeyfile,keyFile,key);
        exit(EXIT_FAILURE);
    }

    if(key != NULL && strlen(key) <= 0) {
        printf("Error the key specified is not valid\n"); 
        printHelp();
        clearMemory(publickeyfile,privatekeyfile,keyFile,key);
        exit(EXIT_FAILURE);
    }


    FILE *keyFilePtr = NULL;
    // if no key, open the key file
    if(key == NULL) {
        if(keyFile == NULL) {
            printf("No key file has been specified\n");
            printHelp();
            exit(EXIT_FAILURE);
        } else {
            keyFilePtr = fopen(keyFile, "r"); //read as a binary file
            if(keyFilePtr == NULL) {
                printf("Error - Could not open the key file specified as %s.\nExiting.\n", keyFile); 
                clearMemory(publickeyfile,privatekeyfile,keyFile,key);
                exit(EXIT_FAILURE);
            }   
            // read the file
            fseek(keyFilePtr,0,SEEK_END);
            keyLen = ftell(keyFilePtr);
            // size_t maxKeyLength = isKeyHex == 0 ? RC4KEYLENGTH : RC4KEYLENGTH*2; // if the key is not hex (0) then key length will be 16 bytes else double 
            // if(keyLen > maxKeyLength) {
            //     printf("Error, the key in file %s is %ld bytes long which is greater than the maximum supported key length of %ld bytes.\n", keyFile, keyLen,RC4KEYLENGTH);
            //     printHelp();
            //     clearMemory(publickeyfile,privatekeyfile,keyFile,key);
            //     exit(EXIT_FAILURE);
            //     return 0;
            // }
            fseek(keyFilePtr,0,SEEK_SET);
            key = calloc(RC4KEYLENGTH+1,sizeof(char)); // padded with nulls, always 16 bytes
            char c; 
            size_t counter = 0; 
            while ((c = fgetc(keyFilePtr)) != EOF) {
                key[counter] = (unsigned char)c;
                counter++;
            }
            keyLen = counter;
        }
    }

    // summary of crap
    printf("Public key file specified is %s\n", publickeyfile);
    printf("Private key file specified is %s\n", privatekeyfile);
    printf("key specified as %s\n", key);
    printf("Key length is %ld\n", keyLen);
    printf("Number of bits specified as %d\n\n", (int)bits);

    // Generate keys and write to file
    rsactx_t* rsaCtx = constructRSAContext(key,keyLen,isKeyHex,bits);
    generateRsaKeys(rsaCtx);
    rsaWriteKeysToFile(rsaCtx,publickeyfile, privatekeyfile);
    rsaClean(rsaCtx); 

    if(keyFilePtr != NULL) {
        fclose(keyFilePtr); 
    }
    clearMemory(publickeyfile,privatekeyfile,keyFile,key);
    return 0; 
}

/**
 * @brief printHelp - Function used to print the help menu for the rsa kegen utility
 * 
 */
void printHelp()
{
    printf("RSA Key Generation Utility\n");
	printf("\nUsage ./rsakeygen <paramters> <arguments> \nIf no arguments are specified the default parameter values are used.\n\n");
    printf("Example usage: ./rsakeygen -b bits -KU public_key_file -KR private_key_file -key key\n");
	printf("-h or --help\t \t Prints out the help menu \n");
    printf("-b          \t \t Specifies the number of bits for the public and private keys to be generated\t Default: None\n");
    printf("-KU         \t \t Specifies the file to write the public key                                  \t Default: None\n");
    printf("-KR         \t \t Specifies the file to write the private key                                 \t Default: None\n");
    printf("-key        \t \t Specifies the key for initialization of the RNG (in hex by default)         \t Default: None\n");
    printf("-kf         \t \t Specifies the path to the key for initialization of the RNG (hex by default)\t Default: None\n");
    printf("-ascii      \t \t Specifies that the key used is in ascii instead of hex                      \t Default: Hex\n");
    printf("** There is no restriction on the key length used to initialize the RNG\n");
}

/**
 * @brief clearMemory - Function used to deallocate all memory allocated for the rsa keygen utility.
 */
void clearMemory(unsigned char* publickeyfile, unsigned char* privatekeyfile, unsigned char* keyFile, unsigned char* key )
{
    if(publickeyfile != NULL) {
        free(publickeyfile);
        publickeyfile = NULL;
    }

    if(privatekeyfile != NULL) {
        free(privatekeyfile);
        privatekeyfile = NULL;
    }

    if(keyFile != NULL) {
        free(keyFile);
        keyFile = NULL;
    }

    if(key != NULL) {
        free(key);
        key = NULL;
    }
}

/**
 * @brief verifyArgument - Function used to verify if a paramter has an argument or not.
 * 
 * @param argCounter - The current index being verified for the commandline paramters.
 * @param argc - The total number of commandline arguments. 
 * @param parameter - The parameter whose argument is being verified. 
 */
void verifyArgument(size_t argCounter, size_t argc, char* parameter)
{
    if(argCounter+1 >= argc) {
        printf("Error no %s specified\n", parameter);
        printHelp();
        exit(EXIT_FAILURE); 
    }
}