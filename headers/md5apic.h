#ifndef MD5APIC_H
#define MD5APIC_H

#define BUFFER_SIZE 1024

// Dosyanın MD5 hash'ini hesaplayan fonksiyon
char* calculate_file_md5(const char* file_path);

// Herhangi bir metnin MD5 hash'ini hesaplayan fonksiyon
char* calculate_text_md5(const char* text);

// MD5 sonucunu bir dosyaya yazan fonksiyon
void write_md5_to_file(const char* input, const char* md5_hash, int is_text);

// Dosya veya metin için MD5 hash hesaplama ve kaydetme işlevi
void process_md5(const char* input, int is_text);

#if 0

if (argc < 2) {
        printf("Usage: %s <file_path or text> [-t for text]\n", argv[0]);
        return 1;
    }

    if (argc == 3 && strcmp(argv[2], "-t") == 0) {
        process_md5(argv[1], 1); // Metin için MD5 hesapla
    } else {
        process_md5(argv[1], 0); // Dosya için MD5 hesapla
    }

    return 0;

#endif

#endif