/**
 * @file database.c
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-11-25
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "database.h"

// Sabit kullanıcı adı ve şifre listesi
const char *usernames[] = {"n0n0", "z0z0", "root", "admin"};
const char *passwords[] = {"n0n0", "z0z0", "root", "admin"};
const int user_count = 4;

// Kullanıcı adı ve şifre doğrulama fonksiyonu
bool check_credentials(const char *username, const char *password)
{
    for (int i = 0; i < user_count; i++)
    {
        LOG_LOOPINFO(database, "Nickname: [%s (??) %s]  || Password: [%s (??) %s]\n", usernames[i], username,
                passwords[i], password);
        if (strcmp(usernames[i], username) == 0 && strcmp(passwords[i], password) == 0)
        {
            return true; // Giriş bilgileri doğru
        }
    }
    return false; // Giriş bilgileri yanlış
}
