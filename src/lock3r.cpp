/**
 * @file lock3r.cpp
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-11-25
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace std;

constexpr int RSA_KEY_BITS = 2048;
constexpr int PADDING = RSA_PKCS1_OAEP_PADDING;
constexpr int AES_KEY_LENGTH = 32; // 256 bit AES anahtarı

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

bool file_exists(const string &filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

void generate_keys(const string &public_key_file, const string &private_key_file) {
    RSA *rsa_keypair = RSA_new();
    BIGNUM *bn = BN_new();
    if (!BN_set_word(bn, RSA_F4)) handle_openssl_error();

    if (RSA_generate_key_ex(rsa_keypair, RSA_KEY_BITS, bn, nullptr) != 1)
        handle_openssl_error();

    // Public key dosyasını kaydet
    BIO *pub_key_bio = BIO_new_file(public_key_file.c_str(), "w");
    if (!PEM_write_bio_RSAPublicKey(pub_key_bio, rsa_keypair))
        handle_openssl_error();
    BIO_free(pub_key_bio);

    // Private key dosyasını kaydet
    BIO *priv_key_bio = BIO_new_file(private_key_file.c_str(), "w");
    if (!PEM_write_bio_RSAPrivateKey(priv_key_bio, rsa_keypair, nullptr, nullptr, 0, nullptr, nullptr))
        handle_openssl_error();
    BIO_free(priv_key_bio);

    RSA_free(rsa_keypair);
    BN_free(bn);

    cout << "[LOG][LOCK3R] RSA anahtarları oluşturuldu ve kaydedildi: " << public_key_file << ", " << private_key_file << endl;
}

RSA* load_key_from_file(const string &filename, bool is_public) {
    ifstream file(filename, ios::in | ios::binary);
    if (!file) {
        cerr << "[LOG][LOCK3R] Anahtar dosyası açılamadı: " << filename << endl;
        exit(EXIT_FAILURE);
    }

    string key_data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    BIO *key_bio = BIO_new_mem_buf(key_data.data(), key_data.size());
    if (!key_bio) handle_openssl_error();

    RSA *key = is_public ? PEM_read_bio_RSAPublicKey(key_bio, nullptr, nullptr, nullptr)
                         : PEM_read_bio_RSAPrivateKey(key_bio, nullptr, nullptr, nullptr);

    if (!key) handle_openssl_error();
    BIO_free(key_bio);

    return key;
}

void encrypt_file(const string &input_filename, const string &output_filename, RSA *public_key) {
    unsigned char aes_key[AES_KEY_LENGTH];
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1) handle_openssl_error();

    size_t rsa_size = RSA_size(public_key);
    unsigned char *encrypted_key = new unsigned char[rsa_size];
    int encrypted_key_length = RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_key, public_key, PADDING);
    if (encrypted_key_length == -1) handle_openssl_error();

    ifstream input_file(input_filename, ios::in | ios::binary);
    if (!input_file) {
        cerr << "[LOG][LOCK3R] Girdi dosyası açılamadı: " << input_filename << endl;
        exit(EXIT_FAILURE);
    }

    ofstream output_file(output_filename, ios::out | ios::binary);
    if (!output_file) {
        cerr << "[LOG][LOCK3R] Çıktı dosyası açılamadı: " << output_filename << endl;
        exit(EXIT_FAILURE);
    }

    output_file.write((char *)encrypted_key, encrypted_key_length);

    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) handle_openssl_error();
    output_file.write((char *)iv, AES_BLOCK_SIZE);

    AES_KEY aes_encrypt_key;
    AES_set_encrypt_key(aes_key, AES_KEY_LENGTH * 8, &aes_encrypt_key);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char encrypted_buffer[AES_BLOCK_SIZE];
    while (input_file.read((char *)buffer, AES_BLOCK_SIZE)) {
        AES_encrypt(buffer, encrypted_buffer, &aes_encrypt_key);
        output_file.write((char *)encrypted_buffer, AES_BLOCK_SIZE);
    }

    int remaining = input_file.gcount();
    if (remaining > 0) {
        memset(buffer + remaining, 0, AES_BLOCK_SIZE - remaining);
        AES_encrypt(buffer, encrypted_buffer, &aes_encrypt_key);
        output_file.write((char *)encrypted_buffer, AES_BLOCK_SIZE);
    }

    input_file.close();
    output_file.close();
    delete[] encrypted_key;

    cout << "[LOG][LOCK3R] Dosya şifrelendi: " << output_filename << endl;
}

void decrypt_file(const string &input_filename, const string &output_filename, RSA *private_key) {
    ifstream input_file(input_filename, ios::in | ios::binary);
    if (!input_file) {
        cerr << "Şifrelenmiş dosya açılamadı: " << input_filename << endl;
        exit(EXIT_FAILURE);
    }

    ofstream output_file(output_filename, ios::out | ios::binary);
    if (!output_file) {
        cerr << "Çıktı dosyası açılamadı: " << output_filename << endl;
        exit(EXIT_FAILURE);
    }

    size_t rsa_size = RSA_size(private_key);
    unsigned char *encrypted_key = new unsigned char[rsa_size];
    input_file.read((char *)encrypted_key, rsa_size);

    unsigned char aes_key[AES_KEY_LENGTH];
    int decrypted_key_length = RSA_private_decrypt(rsa_size, encrypted_key, aes_key, private_key, PADDING);
    if (decrypted_key_length == -1) handle_openssl_error();

    unsigned char iv[AES_BLOCK_SIZE];
    input_file.read((char *)iv, AES_BLOCK_SIZE);

    AES_KEY aes_decrypt_key;
    AES_set_decrypt_key(aes_key, AES_KEY_LENGTH * 8, &aes_decrypt_key);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char decrypted_buffer[AES_BLOCK_SIZE];
    while (input_file.read((char *)buffer, AES_BLOCK_SIZE)) {
        AES_decrypt(buffer, decrypted_buffer, &aes_decrypt_key);
        output_file.write((char *)decrypted_buffer, AES_BLOCK_SIZE);
    }

    input_file.close();
    output_file.close();
    delete[] encrypted_key;

    cout << "Dosya çözüldü: " << output_filename << endl;
}

void arg_start(int argc, char *argv[]) {
    // --lock: Lock the file
    // --unlock: Unlock the file
    // -f: File path
    // -o: Output File path

    cout << "argc: " << argc << endl;

    for(size_t i = 0; i < argc; i++){
        cout << "argv["<< i <<"]: " << argv[i] << "\n";
    }
}

int main(int argc, char *argv[]) {
    
    //arg_start(argc, argv);

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    const string public_key_file = "public_key.pem";
    const string private_key_file = "private_key.pem";

    // Anahtar dosyalarını kontrol et ve yoksa oluştur
    if (!file_exists(public_key_file) || !file_exists(private_key_file)) {
        generate_keys(public_key_file, private_key_file);
    } else {
        cout << "RSA anahtarları mevcut: " << public_key_file << ", " << private_key_file << endl;
    }

    cout << "1. Dosya şifrele\n2. Dosya çöz\nSeçiminiz: ";
    int choice;
    cin >> choice;

    string input_file, output_file;
    if (choice == 1) {
        cout << "Şifrelenecek dosya: ";
        cin >> input_file;
        cout << "Şifrelenmiş dosya adı: ";
        cin >> output_file;

        RSA *public_key = load_key_from_file(public_key_file, true);
        encrypt_file(input_file, output_file, public_key);
        RSA_free(public_key);
    } else if (choice == 2) {
        cout << "Şifrelenmiş dosya: ";
        cin >> input_file;
        cout << "Çözülmüş dosya adı: ";
        cin >> output_file;

        RSA *private_key = load_key_from_file(private_key_file, false);
        decrypt_file(input_file, output_file, private_key);
        RSA_free(private_key);
    } else {
        cout << "Geçersiz seçim!" << endl;
    }

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}