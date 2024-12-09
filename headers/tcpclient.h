#ifndef TCPCLIENT_H
#define TCPCLIENT_H

//includes
#include "socketutil.h"
#include "colorcodes.h"
#include "logmacro.h"
#include "clientkey.h"
#include "strtohex.h"
#include "cryp2.h"

#define PORT 2000
#define MAX_CLIENTS 10 // Max 10 Client
#define MAX_SEND 5
#define BUFFER_SIZE 256

extern const char *address = "127.0.0.1";

#include <stdbool.h>

void newline_messagebox();
int get_terminal_width();
int get_terminal_height();
void *listening_messages_thread(void *arg);
void start_listening_messages_new_thread(int network_socket);

char *get_username();
char *get_password();

bool connect_the_adress(int network_socket, struct sockaddr *server_address);
bool send_the_buffer(int network_socket, char *buffer);
bool send_secure(int network_socket, const char *buffer);

// CRYP2
void encryped_user_login(int network_socket, struct sockaddr *server_address);
void secure_user_send_message(int network_socket, struct sockaddr *server_address, char *username);
void *secure_listening_messages_thread(void *arg);


#endif