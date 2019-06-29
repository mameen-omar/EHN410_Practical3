/**
 * @file rc4.c
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

#include "rc4.h"

const size_t RC4KEYLENGTH = 16; 

int main(int argc, char * argv[]) 
{   

    /*
            Supports both raw input and file input for key 
    */ 

     if(argc <= 1) {
        printHelp();
        exit(EXIT_FAILURE);
    }

    uint8_t isKeyHex = 0; // default not hex - practical guide
    unsigned char* inputFileName = NULL; 
    unsigned char* outputFileName = NULL; 
    unsigned char* keyFile = NULL; 
    unsigned char* key = NULL; 

   // usage ./rc4 -fi inputfile -fo outputfile -kf keyfile -hex (to specify if the key is hex or not)
    for(int x = 1; x < argc;) {
        if(strcmp(argv[x], "-fi") == 0) {
            verifyArgument(x,argc,"inputfile");
            inputFileName = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(inputFileName,argv[x+1], strlen(argv[x+1]));
            printf("Input file specified as %s\n", inputFileName);
            x+=2;
        } else if(strcmp(argv[x], "-fo") == 0) {
            verifyArgument(x,argc,"outputfile");
            outputFileName = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(outputFileName,argv[x+1],strlen(argv[x+1]));
            printf("Output file specified as %s\n", outputFileName);
            x+=2;
        } else if(strcmp(argv[x], "-kf") == 0) {
            verifyArgument(x,argc,"keyfile");
            keyFile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(keyFile,argv[x+1],strlen(argv[x+1]));
            printf("key file specified as %s\n", keyFile);
            x+=2;
        } else if(strcmp(argv[x], "-hex") == 0) {
            isKeyHex = 1; 
            printf("Key is specified as hex\n");
            x+=2;
        } else if(strcmp(argv[x], "-h") == 0) {
            printf("Help menu requested\n");
            printHelp();
            clearMemory(inputFileName,outputFileName,keyFile,key);
            exit(EXIT_SUCCESS); 
        } else {
            printf("Argument %s is not recognized\n", argv[x]);
            printHelp();
            clearMemory(inputFileName,outputFileName,keyFile,key);
            exit(EXIT_FAILURE);
        }
    }
    FILE *keyFilePtr = NULL;
    size_t keyLen; // length of the key

    if(keyFile == NULL) {
        key = calloc(RC4KEYLENGTH*5,sizeof(char));
        printf("No key file has been specified, please enter the RC4 key in ascii (plaintext)\n");
        size_t valid = scanf("%s",key);
        keyLen = strlen(key);
        printf("KeyLength is %ld\n", keyLen);
        while(keyLen > 16 || valid < 0) {
            printf("Error the inputted key is %ld bytes long, which is greater than the maximum supported key length of %ld bytes.\n", keyLen, RC4KEYLENGTH);
            printf("Please enter the RC4 key in ascii (plaintext)\n");
            valid = scanf("%s",key);
            keyLen = strlen(key);
        }

        isKeyHex = 0; 

    } else {
        keyFilePtr = fopen(keyFile, "r"); //read as a binary file
        if(keyFilePtr == NULL) {
            printf("Error - Could not open the key file specified as %s.\nExiting.\n", keyFile); 
            printHelp();
            clearMemory(inputFileName,outputFileName,keyFile,key);
            exit(EXIT_FAILURE);
        }

        // read the file
        fseek(keyFilePtr,0,SEEK_END);
        keyLen = ftell(keyFilePtr);
        size_t maxKeyLength = isKeyHex == 0 ? RC4KEYLENGTH : RC4KEYLENGTH*2; // if the key is not hex (0) then key length will be 16 bytes else double 
        if(keyLen > maxKeyLength) {
            printf("Error, the key in file %s is %ld bytes long which is greater than the maximum supported key length of %ld bytes.\n", keyFile, keyLen,RC4KEYLENGTH);
            printHelp();
            clearMemory(inputFileName,outputFileName,keyFile,key);
            exit(EXIT_FAILURE);
            return 0;
        }

        fseek(keyFilePtr,0,SEEK_SET);
        key = calloc(keyLen+1,sizeof(char));
        char c; 
        size_t counter = 0; 
        while ((c = fgetc(keyFilePtr)) != EOF) {
            key[counter] = (unsigned char)c;
            counter++;
        }
        keyLen = counter;        
    }
    keyLen = strlen(key);
    printf("Summary of input:\n");
    printf("The inputfile is: %s\n", inputFileName);
    printf("The outputfile is: %s\n", outputFileName); 
    printf("The key is: _%s_\n", key); 
    printf("The key length is: %ld\n\n", keyLen); 
    printf("Is key hex %d\n", isKeyHex); 

    uint8_t isTextHex = 0; // text is not hex
    // start the encryption
    rc4ctx_t* rc4Ctx = constructRc4Context();
    rc4Init(rc4Ctx,key,keyLen,isKeyHex);
    performRc4(inputFileName, outputFileName, rc4Ctx, isTextHex); // text is not hex

    destroyRc4Context(rc4Ctx);

    // cleanup
    if(keyFilePtr != NULL) {
        fclose(keyFilePtr); 
    }    
    clearMemory(inputFileName,outputFileName,keyFile,key);
    return 0; 
}
/**
 * @brief printHelp - Function used to print the help menu for the rc4 utility
 * 
 */
void printHelp()
{
    printf("RC4 Encryption and Decryption Utility\n");
	printf("\nUsage ./rc4 <paramters> <arguments> \nIf no arguments are specified the default parameter values are used.\n\n");
    printf("Example usage: ./rc4 -fi inputfile -fo outputfile -kf keyfile\n");
	printf("-h   \t \t Prints out the help menu \n");
    printf("-fi  \t \t Specifies the file to encrypt or decrypt                                                 \t Default: None\n");
    printf("-fo  \t \t Specifies the file to write the encrypted or decrypted result                            \t Default: None\n");
    printf("-kf  \t \t Specifies the path to the encryption key for initialization of the RNG (ascii by default)\t Default: None\n");
    printf("-hex \t \t Specifies that the key used is in hex instead of ascii                                   \t Default: ascii\n");
    printf("** If no key is specified the user will be prompted for a key\n");
    printf("** All keys must have a maximum size of 16 bytes\n");
}

/**
 * @brief clearMemory - Function used to deallocate all memory allocated for the rc4 utility.
 */
void clearMemory(unsigned char* inputFileName, unsigned char* outputFileName, unsigned char* keyFile, unsigned char* key )
{
    if(inputFileName != NULL) {
        free(inputFileName);
        inputFileName = NULL;
    }

    if(outputFileName != NULL) {
        free(outputFileName);
        outputFileName = NULL;
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