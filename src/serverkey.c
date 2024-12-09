#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // getcwd için
#include <limits.h> // PATH_MAX için

#include "serverkey.h"

// Çalışma dizinine göre dinamik olarak dosya yolunu oluştur
const char* getPublicKeyPath() {
    static char path[PATH_MAX];
    if (getcwd(path, sizeof(path)) == NULL) {
        perror("getcwd() error");
        exit(EXIT_FAILURE);
    }
    strcat(path, "/server-key/public_key.pem");
    return path;
}

const char* getPrivateKeyPath() {
    static char path[PATH_MAX];
    if (getcwd(path, sizeof(path)) == NULL) {
        perror("getcwd() error");
        exit(EXIT_FAILURE);
    }
    strcat(path, "/server-key/private_key.pem");
    return path;
}