#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "strtohex.h"

/**
 * Converts a character to its hexadecimal representation.
 */
static char char_to_hex_digit(unsigned char value) {
    return (value < 10) ? ('0' + value) : ('A' + (value - 10));
}

/**
 * Converts a single hexadecimal digit to its numeric value.
 */
static unsigned char hex_digit_to_char(char hex) {
    if (hex >= '0' && hex <= '9') return hex - '0';
    if (hex >= 'A' && hex <= 'F') return hex - 'A' + 10;
    if (hex >= 'a' && hex <= 'f') return hex - 'a' + 10;
    return 0; // Undefined behavior for invalid input
}

char *str_to_hex(const char *str, size_t size) {
    if (!str || size == 0) return NULL;

    // Allocate memory for the hexadecimal string (2 chars per byte + null terminator)
    char *hex_str = (char *)malloc(size * 2 + 1);
    if (!hex_str) return NULL;

    for (size_t i = 0; i < size; ++i) {
        unsigned char byte = (unsigned char)str[i];
        hex_str[i * 2] = char_to_hex_digit(byte >> 4);
        hex_str[i * 2 + 1] = char_to_hex_digit(byte & 0x0F);
    }

    hex_str[size * 2] = '\0'; // Null-terminate the string
    return hex_str;
}

char *hex_to_str(const char *hex_str, size_t size) {
    if (!hex_str || size == 0 || size % 2 != 0) return NULL;

    // Allocate memory for the original string (half the size of the hex string + null terminator)
    size_t str_size = size / 2;
    char *str = (char *)malloc(str_size + 1);
    if (!str) return NULL;

    for (size_t i = 0; i < str_size; ++i) {
        unsigned char high_nibble = hex_digit_to_char(hex_str[i * 2]);
        unsigned char low_nibble = hex_digit_to_char(hex_str[i * 2 + 1]);
        str[i] = (high_nibble << 4) | low_nibble;
    }

    str[str_size] = '\0'; // Null-terminate the string
    return str;
}
