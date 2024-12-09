#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "colorcodes.h"
#include "socketutil.h"
#include "logmacro.h"
#include "database.h"  
#include "socketutil.h"

#include "serverkey.h"
#include "cryp2.h"
#include "strtohex.h"

struct AcceptedSocket {
  int accepted_socket_fd;
  struct sockaddr_in address;
  int error;
  bool accepted_success;
};

#define PORT 2000
#define QUEUE 5
#define MAX_CLIENTS 10 // Max 10 Client
#define BUFFER_SIZE 256

// -------------------------------  //
struct AcceptedSocket *accepted_sockets = NULL;
unsigned int accepted_sockets_count = 0;
extern int errno;

void *server_address_ptr;

// Create Global Client ID counter
int global_client_id = 0;
pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER; // ID'yi thread-safe yapmak için mutex

// Mutex to protect access to the accepted_sockets array
pthread_mutex_t accepted_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;


void interrupt_handler(int sig);
struct AcceptedSocket *AcceptIncomingConnections(int server_socket);
void handle_client_communication(int client_socket_fd, int sthread_id);
void *recv_the_client(void *arg);
void recv_the_client_separate_threads(struct AcceptedSocket *client_socket);
void start_accept_connections(int server_socket);
void send_the_buffer_other_clients(int client_socket, char *buffer);
void __arg_options(int argc, char **argv);
int generate_client_id();

void socket_list_allocate();
void server_listen(int server_socket);
void server_bind(int server_socket, struct sockaddr *server_address);

bool secure_handle_login(int client_socket_fd, int sthread_id);
void secure_handle_client_communication(int client_socket_fd, int sthread_id);

//
void secure_send_the_buffer_other_clients(int client_socket, char *buffer);
void secure_handle_client_communication(int client_socket_fd, int sthread_id);


#endif

/**
 * @brief  handle_client_communication need to be encrypted
 * 
 */