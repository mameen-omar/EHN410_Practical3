/**
 * @file rsadecrypt.c
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
#include "rsadecrypt.h"


int main(int argc, char * argv[]) 
{
    if(argc <= 1) {
        printHelp();
        exit(EXIT_FAILURE);
    }

    unsigned char* privateKeyFile = NULL;  // RSA private key (n,d)
    unsigned char* outputfileName = NULL; // where to write the decrypted result to
    unsigned char* keyFile = NULL; // file contents to decrypt
    unsigned char* key = NULL; // key to decrypt
    size_t keyLen = 0;
    
    for(int x = 1; x < argc;) {

        if(strcmp(argv[x], "-key") == 0) {
            verifyArgument(x,argc,"key");
            key = calloc(strlen(argv[x+1])+1,sizeof(char));
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
        } else if(strcmp(argv[x], "-KR") == 0) {
            verifyArgument(x,argc,"private key file");
            privateKeyFile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(privateKeyFile,argv[x+1],strlen(argv[x+1]));
            printf("private key file specified as %s\n", privateKeyFile);
            x+=2;
        } else if(strcmp(argv[x], "-fi") == 0) {
            verifyArgument(x,argc,"input key file");
            keyFile = calloc(strlen(argv[x+1])+1,sizeof(char));
            strncpy(keyFile,argv[x+1],strlen(argv[x+1]));
            printf("input key file specified as %s\n", keyFile);
            x+=2;
        } else if(strcmp(argv[x], "-h") == 0) {
            printf("Help menu requested\n");
            printHelp();
            clearMemory(privateKeyFile, outputfileName, keyFile, key );
            exit(EXIT_SUCCESS); 
        } else {
            printf("Argument %s is not recognized\n", argv[x]);
            printHelp();
            clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
            exit(EXIT_FAILURE);
        }
    }

    // verify if all required parameters have been specified
    if(privateKeyFile == NULL || strlen(privateKeyFile) <= 0) {
        printf("Error private key file has not been specified\n"); 
        printHelp();
        clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    if(outputfileName == NULL || strlen(outputfileName) <= 0 ) {
        printf("Error outputfile has not been specified\n"); 
        printHelp();
        clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    if(key != NULL && keyFile != NULL) {
        printf("Error both key and a key file have been specified\n"); 
        printHelp();
        clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
        exit(EXIT_FAILURE);
    }

    if(key != NULL && strlen(key) <= 0) {
        printf("Error invalid key has been specified\n"); 
        printHelp();
        clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
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
                clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
                exit(EXIT_FAILURE);
            }   
            // read the file
            fseek(keyFilePtr,0,SEEK_END);
            keyLen = ftell(keyFilePtr);
            // size_t maxKeyLength = isKeyHex == 0 ? RC4KEYLENGTH : RC4KEYLENGTH*2; // if the key is not hex (0) then key length will be 16 bytes else double 
            // if(keyLen > maxKeyLength) {
            //     printf("Error, the key in file %s is %ld bytes long which is greater than the maximum supported key length of %ld bytes.\n", keyFile, keyLen,RC4KEYLENGTH);
            //     printHelp();
            //     clearMemory(publickeyfile, outputfileName, keyFile, key ); 
            //     exit(EXIT_FAILURE);
            //     return 0;
            // }

            fseek(keyFilePtr,0,SEEK_SET);
            key = calloc(keyLen+1,sizeof(char)); 
            char c; 
            size_t counter = 0; 
            while ((c = fgetc(keyFilePtr)) != EOF) {
                key[counter] = (unsigned char)c;
                counter++;
            }           
        }
    }

    keyLen = strlen(key); 
    // summary
    printf("private key file specified is %s\n", privateKeyFile);
    printf("Output specified is %s\n", outputfileName);
    printf("key specified as %s\n", key);
    printf("Key length is %ld\n", keyLen);
    printf("Key file specified as: %s\n", keyFile);

    rsaDecrypt(outputfileName, privateKeyFile, key); 

    clearMemory(privateKeyFile, outputfileName, keyFile, key ); 
    if(keyFilePtr != NULL) {
        fclose(keyFilePtr); 
    }
    return 0;
}

/**
 * @brief printHelp - Function used to print the help menu for the rsa decrypt utility
 * 
 */
void printHelp()
{
    printf("RSA Decryption Utility\n");
	printf("\nUsage ./rsadecrypt <paramters> <arguments> \nIf no arguments are specified the default parameter values are used.\n\n");
    printf("Example usage: rsadecrypt -fi inputfile -KR private_key_file -fo outputfile\n");
	printf("-h    \t \t Prints out the help menu \n");
    printf("-fi   \t \t Specifies the path to the key to decrypt                                                 \t Default: None\n");
    printf("-key  \t \t Specifies the key to decrypt                                                             \t Default: None\n");
    printf("-KR   \t \t Specifies the RSA private key file to use for decryption                                 \t Default: None\n");
    printf("-fo   \t \t Specifies the file to write the decrypted result                                         \t Default: None\n");
}
/**
 * @brief clearMemory - Function used to deallocate all memory allocated for the rsa decryption utility.
 */
void clearMemory(unsigned char* privateKeyFile, unsigned char* outputfileName, unsigned char* keyFile, unsigned char* key )
{
    if(privateKeyFile != NULL) {
        free(privateKeyFile);
        privateKeyFile = NULL;
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