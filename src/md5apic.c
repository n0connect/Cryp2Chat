/**
 * @file md5apic.c
 * @author Devran Iskanoglu (devraniskanoglu@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-11-25
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#include "md5apic.h"

// Dosyanın MD5 hash'ini hesaplayan fonksiyon
char* calculate_file_md5(const char* file_path) {
    unsigned char buffer[BUFFER_SIZE];
    unsigned char digest[MD5_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    FILE* file = fopen(file_path, "rb");
    
    if (file == NULL) {
        printf("Could not open file: %s\n", file_path);
        return NULL;
    }

    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    char* md5_string = (char*)malloc(MD5_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(&md5_string[i * 2], "%02x", digest[i]);
    }
    md5_string[MD5_DIGEST_LENGTH * 2] = '\0'; // Null terminate the string
    return md5_string;
}

// Herhangi bir metnin MD5 hash'ini hesaplayan fonksiyon
char* calculate_text_md5(const char* text) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, text, strlen(text));
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);

    char* md5_string = (char*)malloc(MD5_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(&md5_string[i * 2], "%02x", digest[i]);
    }
    md5_string[MD5_DIGEST_LENGTH * 2] = '\0'; // Null terminate the string
    return md5_string;
}

// MD5 sonucunu bir dosyaya yazan fonksiyon
void write_md5_to_file(const char* input, const char* md5_hash, int is_text) {
    FILE* file = fopen("md5_results.txt", "a"); // Sonuçları "md5_results.txt" dosyasına ekler
    if (file == NULL) {
        printf("Could not open output file.\n");
        return;
    }

    if (is_text) {
        fprintf(file, "Text: %s\nMD5: %s\n\n", input, md5_hash);
    } else {
        fprintf(file, "File: %s\nMD5: %s\n\n", input, md5_hash);
    }

    fclose(file);
}

// Dosya veya metin için MD5 hash hesaplama ve kaydetme işlevi
void process_md5(const char* input, int is_text) {
    char* md5_hash;

    if (is_text) {
        md5_hash = calculate_text_md5(input);
        if (md5_hash) {
            printf("MD5 (text) = %s\n", md5_hash);
            write_md5_to_file(input, md5_hash, 1);
            free(md5_hash);
        }
    } else {
        md5_hash = calculate_file_md5(input);
        if (md5_hash) {
            printf("MD5 (%s) = %s\n", input, md5_hash);
            write_md5_to_file(input, md5_hash, 0);
            free(md5_hash);
        }
    }
}

