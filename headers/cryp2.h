#ifndef CRYP2_H
#define CRYP2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// RSA şifreleme için kullanılan parametreler
#ifdef __cplusplus
constexpr int RSA_KEY_BITS = 2048;
constexpr int PADDING = RSA_PKCS1_OAEP_PADDING;
#else

#define RSA_KEY_BITS 2048
#define PADDING RSA_PKCS1_OAEP_PADDING

#endif

// Fonksiyon prototipleri
RSA* load_public_key(const char* public_key_path);
RSA* load_private_key(const char* private_key_path);
void handle_openssl_error();
char* encrypt_message(const char* plaintext, const char* public_key_path);
char* decrypt_message(const char* ciphertext, int ciphertext_len, const char* private_key_path);

#ifdef __cplusplus
}
#endif

#endif // CRYP2_H
