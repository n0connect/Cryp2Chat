#ifndef STRTOHEX_H
#define STRTOHEX_H

#include <stddef.h> // for size_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Converts a string to its hexadecimal representation.
 * 
 * @param str Input string to be converted.
 * @param size Size of the input string.
 * @return char* Hexadecimal representation of the input string.
 *         The caller is responsible for freeing the allocated memory.
 */
char *str_to_hex(const char *str, size_t size);

/**
 * @brief Converts a hexadecimal representation back to its original string.
 * 
 * @param hex_str Input hexadecimal string.
 * @param size Size of the input hexadecimal string.
 * @return char* Original string decoded from the hexadecimal input.
 *         The caller is responsible for freeing the allocated memory.
 */
char *hex_to_str(const char *hex_str, size_t size);

#ifdef __cplusplus
}
#endif

#endif // STRTOHEX_H

