#ifndef LOGMACRO_H
#define LOGMACRO_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "colorcodes.h"

#define online 1
#define offline 0

// Log bağlamlarını temsil eden enum
typedef enum {
    server,
    client,
    auth,
    database,
    rsa,
    unknown // Varsayılan için
} LogContext;

// Bağlamı string'e dönüştüren yardımcı makro
#define CONTEXT_TO_STRING(context) \
    (context == server ? "SERVER" : \
     context == client ? "CLIENT" : \
     context == auth ? "AUTH" : \
     context == database ? "DATABASE" : \
     context == rsa ? "RSA" : "UNKNOWN")

// Yardımcı fonksiyon: Tarih ve saat bilgisi al
static inline char* get_timestamp() {
    static char buffer[32];
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", t);
    return buffer;
}

// Log dosyasını aç (sabit isimde dosya)
static inline FILE* get_log_file() {
    return fopen("client_log.log", "a");
}

// Log bilgi makrosu
#define LOG_LOOPINFO(context, fmt, ...) \
    fprintf(stdout, RESET BWHT"[LOG][%s][INFO] " YEL fmt RESET "\n", CONTEXT_TO_STRING(context), ##__VA_ARGS__)

// Log bilgi makrosu
// Log bilgi makrosu
#define LOG_MSG(client_name, status) \
    fprintf(stdout, RESET BWHT"[%s][%s]: ", \
            (status == online ? "ONLINE" : "OFFLINE"), client_name); \
    fflush(stdout)

// Log başarı makrosu
#define LOG_SUCCESS(context, fmt, ...) \
    do { \
        if (context != server) { \
            FILE* log_file = get_log_file(); \
            if (log_file) { \
                fprintf(log_file, "[%s] [LOG][%s][SUCCESS] " fmt "\n", get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__); \
                fclose(log_file); \
            } else { \
                fprintf(stderr, RESET BRED"[%s] [LOG][%s][ERROR] Failed to open log file\n", get_timestamp(), CONTEXT_TO_STRING(context)); \
            } \
        } else { \
            fprintf(stdout, RESET BWHT"[%s] [LOG][%s][SUCCESS] " BGRN fmt RESET "\n", get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__); \
        } \
    } while (0)

// Log bilgi makrosu
#define LOG_INFO(context, fmt, ...) \
    do { \
        if (context != server) { \
            FILE* log_file = get_log_file(); \
            if (log_file) { \
                fprintf(log_file, "[%s] [LOG][%s][INFO] " fmt "\n", get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__); \
                fclose(log_file); \
            } else { \
                fprintf(stderr, RESET BRED"[%s] [LOG][%s][ERROR] Failed to open log file\n", get_timestamp(), CONTEXT_TO_STRING(context)); \
            } \
        } else { \
            fprintf(stdout, RESET BWHT"[%s] [LOG][%s][INFO] " fmt "\n", get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__); \
        } \
    } while (0)

// Log hata makrosu
#define LOG_ERROR(context, fmt, ...) \
    do { \
        if (context != server) { \
            FILE* log_file = get_log_file(); \
            if (errno && log_file) { \
                fprintf(log_file, "[%s] [LOG][%s][ERROR] " fmt ": %s\n", get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__, strerror(errno)); \
                fclose(log_file); \
            } else if (log_file) { \
                fprintf(log_file, "[%s] [LOG][%s][ERROR] " fmt "\n", get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__); \
                fclose(log_file); \
            } else { \
                fprintf(stderr, RESET BRED"[%s] [LOG][%s][ERROR] Failed to open log file\n", get_timestamp(), CONTEXT_TO_STRING(context)); \
            } \
        } else { \
            if (errno) { \
                fprintf(stderr, RESET BWHT"[%s] [LOG][%s][ERROR] " BRED fmt ": %s\n" RESET, get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__, strerror(errno)); \
            } else { \
                fprintf(stderr, RESET BWHT"[%s] [LOG][%s][ERROR] " BRED fmt "\n" RESET, get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__); \
            } \
        } \
    } while (0)

#endif // LOGMACRO_H
