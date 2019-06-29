/**
 * @file rsaencrypt.c
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
#include "rsaencrypt.h"

// valgrind --leak-check=full --show-leak-kinds=all -v

int main(int argc, char * argv[]) 
{
    if(argc <= 1) {
        printHelp();
        exit(EXIT_FAILURE);
    }
    const size_t RC4KEYLENGTH = 16; 
    uint8_t isKeyHex = 0; // default is not hex
    unsigned char* publickeyfile = NULL; 
    unsigned char* outputfileName = NULL;
    unsigned char* keyFile = NULL; 
    unsigned char* key = NULL; 
    size_t keyLen = 0;

// usage ./rsaencrypt -key key -fo outputfile -KU public_key_file optionally -kf for the key file -hex if key is hex (that is the input plaintext )
// ** key is what is being encrypted
    for(int x = 1; x < argc;) {

        if(strcmp(argv[x], "-key") == 0) {
            verifyArgument(x,argc,"key");
            key = calloc(RC4KEYLENGTH+1,sizeof(char)); // always padded
            strncpy(key,argv[x+1],strlen(argv[x+1]));
            printf("key specified as %s\n", key);
            keyLen = strlen(key);
            x+=2;
        } else if(strcmp(argv[x], "-fo") == 0) {
            verifyArgument(x,argc,"output file name");
            outputfileName = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(outputfileName,argv[x+1],strlen(argv[x+1]));
            printf("outputfile specified as %s\n", outputfileName);
            x+=2;
        } else if(strcmp(argv[x], "-KU") == 0) {
            verifyArgument(x,argc,"public key file");
            publickeyfile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(publickeyfile,argv[x+1],strlen(argv[x+1]));
            printf("public key file specified as %s\n", publickeyfile);
            x+=2;
        } else if(strcmp(argv[x], "-kf") == 0) {
            verifyArgument(x,argc,"key file");
            keyFile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(keyFile,argv[x+1],strlen(argv[x+1]));
            printf("key file specified as %s\n", keyFile);
            x+=2;
        } else if(strcmp(argv[x], "-hex") == 0) {
            isKeyHex = 1; 
            printf("Key (plaintext) is specified as hex\n");
            x+=2;
        } else if(strcmp(argv[x], "-h") == 0) {
            printf("Help menu requested\n");
            printHelp();
            clearMemory(publickeyfile, outputfileName, keyFile, key );
            exit(EXIT_SUCCESS); 
        } else {
            printf("Argument %s is not recognized\n", argv[x]);
            printHelp();
            clearMemory(publickeyfile, outputfileName, keyFile, key );
            exit(EXIT_FAILURE);
        }
    }

    // verify if all required parameters have been specified
    if(publickeyfile == NULL || strlen(publickeyfile) <= 0) {
        printf("Error public key file has not been specified\n"); 
        printHelp();
        clearMemory(publickeyfile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    if(outputfileName == NULL || strlen(outputfileName) <= 0) {
        printf("Error outputfile has not been specified\n"); 
        printHelp();
        clearMemory(publickeyfile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    if(key == NULL && keyFile == NULL) {
        printf("Error both key and a key file have been specified\n"); 
        printHelp();
        clearMemory(publickeyfile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    if(key != NULL && strlen(key) <= 0) {
        printf("Error invalid key has been specified\n"); 
        printHelp();
        clearMemory(publickeyfile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    FILE *keyFilePtr = NULL;
    // check 
    if(key == NULL) {
        if(keyFile == NULL) {
            printf("No key file and no key has been specified\n");
            printHelp();
            exit(EXIT_FAILURE);
        } else {
            keyFilePtr = fopen(keyFile, "r"); //read as a binary file
            if(keyFilePtr == NULL) {
                printf("Error - Could not open the key file specified as %s.\nExiting.\n", keyFile); 
                clearMemory(publickeyfile, outputfileName, keyFile, key ); 
                exit(EXIT_FAILURE);
            }   
            // read the file
            fseek(keyFilePtr,0,SEEK_END);
            keyLen = ftell(keyFilePtr);
            size_t maxKeyLength = isKeyHex == 0 ? RC4KEYLENGTH : RC4KEYLENGTH*2; // if the key is not hex (0) then key length will be 16 bytes else double 
            if(keyLen > maxKeyLength) {
                printf("Error, the key in file %s is %ld bytes long which is greater than the maximum supported key length of %ld bytes.\n", keyFile, keyLen,RC4KEYLENGTH);
                printHelp();
                clearMemory(publickeyfile, outputfileName, keyFile, key ); 
                exit(EXIT_FAILURE);
                return 0;
            }

            fseek(keyFilePtr,0,SEEK_SET);
            key = calloc(RC4KEYLENGTH+1,sizeof(char)); // always padded to null chars 
            char c; 
            size_t counter = 0; 
            while ((c = fgetc(keyFilePtr)) != EOF) {
                key[counter] = (unsigned char)c;
                counter++;
            }            
        }
    }
    
    keyLen = RC4KEYLENGTH; // input key is always padded 
    // summary of crap
    printf("Public key file specified is %s\n", publickeyfile);
    printf("Output specified is %s\n", outputfileName);
    printf("key specified as %s\n", key);
    printf("Key length is %ld\n", keyLen);
    printf("Key file specified as: %s\n", keyFile);
    printf("Is key (plaintext) hex: %d\n", isKeyHex);
    rsaEncrypt(outputfileName, publickeyfile, key, isKeyHex); 
    // temp
    clearMemory(publickeyfile,outputfileName,keyFile,key);
    if(keyFilePtr != NULL) {
        fclose(keyFilePtr); 
    }
    return 0;
}

/**
 * @brief printHelp - Function used to print the help menu for the rsa encrypt utility
 * 
 */
void printHelp()
{
    printf("RSA Encryption Utility\n");
	printf("\nUsage ./rsaencrypt <paramters> <arguments> \nIf no arguments are specified the default parameter values are used.\n\n");
    printf("Example usage: ./rsaencrypt -key key -fo outputfile -KU public_key_file\n");
	printf("-h   \t \t Prints out the help menu \n");
    printf("-key \t \t Specifies the RC4 key to encrypt or decrypt                                              \t Default: None\n");
    printf("-fo  \t \t Specifies the file to write the encrypted result                                         \t Default: None\n");
    printf("-KU  \t \t Specifies the RSA public key file to use for encryption                                  \t Default: None\n");
    printf("-kf  \t \t Specifies the path to the RC4 key to encrypt or decrypt                                  \t Default: None\n");
    printf("-hex \t \t Specifies that the key used is in hex instead of ascii                                   \t Default: ascii\n");
    printf("** All keys must have a maximum size of 16 bytes (16 characters of plaintext) \n");
}

/**
 * @brief clearMemory - Function used to deallocate all memory allocated for the rsa encryption utility.
 */
void clearMemory(unsigned char* publickeyfile, unsigned char* outputfileName, unsigned char* keyFile, unsigned char* key )
{
    if(publickeyfile != NULL) {
        free(publickeyfile);
        publickeyfile = NULL;
    }

    if(outputfileName != NULL) {
        free(outputfileName);
        outputfileName = NULL;
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