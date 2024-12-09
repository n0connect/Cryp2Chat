#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include "logmacro.h"

// Kullanıcı adı ve şifre doğrulama fonksiyonu
bool check_credentials(const char *username, const char *password);

// Şifre hash'leme ve kullanıcı ekleme fonksiyonu
// bool add_user(const char *username, const char *password);

#endif