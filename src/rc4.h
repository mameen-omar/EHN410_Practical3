/**
 * @file rc4.h
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
#if !defined(RC4_H)
#define RC4_H
#include "rc4Lib.h"
#include <unistd.h>
#include <getopt.h>

extern const size_t RC4KEYLENGTH; 
/**
 * @brief printHelp - Function used to print the help menu for the rc4 utility
 * 
 */
void printHelp(); 
/**
 * @brief clearMemory - Function used to deallocate all memory allocated for the rc4 utility.
 */
void clearMemory(unsigned char* inputFileName, unsigned char* outputFileName, unsigned char* keyFile, unsigned char* key ); 
/**
 * @brief verifyArgument - Function used to verify if a paramter has an argument or not.
 * 
 * @param argCounter - The current index being verified for the commandline paramters.
 * @param argc - The total number of commandline arguments. 
 * @param parameter - The parameter whose argument is being verified. 
 */
void verifyArgument(size_t argCounter, size_t argc, char* parameter); 

#endif // RC4_H

