/**
 * @file textConverter.c
 * @authors Mohamed Ameen Omar (u16055323)
 * @authors Douglas Healy (u16018100)
 * @authors Llewellyn Moyse (u15100708)
 * @brief The text converter libary implementation file. This file contains functions used to convert between different bases of text.
 * Such as conversion from ascii to hex, hex to ascii, hex to int. This is used for encryption when a certian base is required, different from the one provided.
 * 
 * @version 0.1
 * @date 2019-05-22
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "textConverter.h"


/**
 * @brief hexToInt -  Function that converts a given hex value into an integer. 
 * @param ch - hex value that wil be converted to int. 
 * @return uint8_t the converted int value. 
 */
uint8_t hexToInt(char ch) 
{ 
    if(ch >=97) {
        ch = ch - 32;
    } 
    uint8_t first = (ch / 16) - 3;
    uint8_t second = ch % 16;
    uint8_t asciiChar = (first*10) + second;
    if(asciiChar > 9) {
        asciiChar--;
    }
    return asciiChar;
}

/**
 * @brief hexToAscii - Function that converts a given hex value to its ASCII equivalent.  
 * @param ch1 - char value of the first hex value.
 * @param ch2 - char value of the second hex value.
 */
uint8_t hexToAscii(char ch1, char ch2) 
{
        uint8_t highByte = hexToInt(ch1) * 16;
        uint8_t lowByte = hexToInt(ch2);
        return highByte + lowByte;
}

/**
 * @brief hexToAsciiString - Function that converts a given string of hex values into its ASCII equivalent.
 * A hex string contains hex chars and is "encoded" in ascii
 * In order to encrypt it, it must be converted to the equivalent ascii plain text string
 * plaintext string is half the size of hex, since two hex chars = 1 ascii char
 * if hex string is "4A" it will be converted to "J" in ascii which will have a hex representation of "4a"
 * The original hex string converted to hex staright or printed in hex straight rather will print or have the value "0x34", "0x31"
 * BASICALLY THE HEX STRING FF IS INTERPRETED AS THE CHARS FF, whereas when using this function we intend it to be "J", ie the char "J"
 * @param char* hexString - The string of hex values to be converted.
 * @param char* asciiString - The output of the converted hex string.
 * @param int hexStringLength - The length of parameter hexString.
 */
void hexToAsciiString(char* hexString, char* asciiString, int hexStringLength) 
{
	size_t asciiIndex = 0;
	char tempChar = 0;

	for (size_t x = 0; x < hexStringLength; x++) {
		if(x % 2 != 0) {
            asciiString[asciiIndex] = hexToAscii(tempChar, hexString[x]);
            asciiIndex++;
        } else {
            tempChar = hexString[x];
        }
	}
}

/**
 * @brief Function name: asciiToHexString - convert an ascii String to an ascii string. 
 * @param asciiString - unsigned char* pointing to the ASCII String to be converted. 
 * @param hexString  - unsigned char* pointing to a memory where the converted Hex string should be stored. 
 * @param asciiStringLen - size_t containing the length of the ASCII String to be converted. 
 * @return unsigned char* asciiToHexString - pointer to the converted Hex String, pointing to the same memory location
 * as @param hexString. 
 */
unsigned char* asciiToHexString(unsigned char *asciiString, unsigned char* hexString, size_t asciiStringLen)
{	
	if(asciiString == NULL || asciiStringLen == 0)
		return NULL;

	for(size_t x = 0; x < asciiStringLen; x++) {
        hexString[x*2]   = "0123456789abcdef"[asciiString[x] >> 4];
        hexString[x*2+1] = "0123456789abcdef"[asciiString[x] & 0x0F];
	}

    return hexString; 
}

/**
 * @brief keyHexToAscii - Function to convert a hex encoded key to an ascii string. The caller must ensure they 
 * deallocate the memory allocated for the returned ascii encoded string. 
 * @param hexKey - unsigned char* - the hexadecimal encoded key to convert. 
 * @param keyLength - int - the length of the key @param hexKey.
 * @return unsigned char* - The resulting ascii encoded string. 
 */
unsigned char* keyHexToAscii(unsigned char* hexKey, int keyLength) 
{
    keyLength = keyLength/2;
    unsigned char* tempKey = calloc(keyLength,sizeof(char));
    // convert to ascii store in temp key
    hexToAsciiString(hexKey,tempKey,keyLength*2);
    return tempKey;
}