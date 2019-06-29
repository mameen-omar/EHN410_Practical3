/**
 * @file rsaencrypt.h
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
#ifndef RSAENCRYPT_H
#define RSAENCRYPT_H
#include "rsa.h"

/**
 * @brief printHelp - Function used to print the help menu for the rsa encrypt utility
 * 
 */
void printHelp(); 
/**
 * @brief clearMemory - Function used to deallocate all memory allocated for the rsa encryption utility.
 */
void clearMemory(unsigned char* publickeyfile, unsigned char* outputfileName, unsigned char* keyFile, unsigned char* key ); 
/**
 * @brief verifyArgument - Function used to verify if a paramter has an argument or not.
 * 
 * @param argCounter - The current index being verified for the commandline paramters.
 * @param argc - The total number of commandline arguments. 
 * @param parameter - The parameter whose argument is being verified. 
 */
void verifyArgument(size_t argCounter, size_t argc, char* parameter);

#endif