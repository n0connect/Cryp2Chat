// SOCKET PROGRAMMING "TCP_SERVER" //
// -----------------------------  //
/**
 * @file TCPServer.c
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-11-25
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "tcpserver.h"

#define PUBLIC_KEY getPublicKeyPath()
#define PRIVATE_KEY getPrivateKeyPath()

/**
 * @brief Handle the CTRL+C Signal
 * 
 * @param sig <Signal type>
 */
void interrupt_handler(int sig) {
  int *fd = (int*)(server_address_ptr);
  
  LOG_ERROR(server, "Signal: Kill Server.");
  shutdown(*fd, SHUT_RDWR);
  free(accepted_sockets);
  free(server_address_ptr);
  exit(EXIT_SUCCESS); // KILL THE PROGRAM
}

/**
 * @brief Bind server socket
 * 
 * @param server_socket 
 * @param server_address 
 */
void server_bind(int server_socket, struct sockaddr *server_address){
  // Bind the socket to our specified IP ad PORT
  if (bind(server_socket, (struct sockaddr *)server_address,
           sizeof(*server_address)) < 0)
  {
    shutdown(server_socket, SHUT_RDWR);
    free(server_address);
    LOG_ERROR(server, "Server bind error");
    exit(EXIT_FAILURE);
  }
  else
  {
    LOG_SUCCESS(server, "Connection successfully.");
  }
}


/**
 * @brief Start Listen the current socket with a limit
 * 
 * @param server_socket 
 */
void server_listen(int server_socket){
  // Listen the server socket
  if (listen(server_socket, QUEUE) < 0)
  {
    LOG_ERROR(server, "Listening error");
    exit(EXIT_FAILURE);
  }
  else
  {
    LOG_INFO(server, "Listening the requests...");
  }
}

/**
 * @brief List socket allocate
 * 
 * @param void
 */
void socket_list_allocate(){
  // Allocate memory blocks for the accepted socket's {0}
  accepted_sockets = (struct AcceptedSocket *)calloc(MAX_CLIENTS, sizeof(struct AcceptedSocket));

  if(accepted_sockets == NULL){
    LOG_ERROR(server, "Socket List Allocate Error");
    exit(EXIT_FAILURE);
  }
  
}

/**
 * @brief Generate random client number
 * 
 * @return int 
 */
int generate_client_id() {
  pthread_mutex_lock(&id_mutex); // Thread-safe with Mutex.
  int new_id = global_client_id++;
  pthread_mutex_unlock(&id_mutex);
  return new_id;
}

/**
 * @brief Allocate and Accept client connection
 * 
 * @param server_socket 
 * @return struct AcceptedSocket* 
 */
struct AcceptedSocket *AcceptIncomingConnections(int server_socket) {
  struct sockaddr_in client_address;
  socklen_t client_address_size = sizeof(client_address);

  int client_socket = accept(server_socket, (struct sockaddr *)&client_address,
                             &client_address_size);

  struct AcceptedSocket *accepted_return = (struct AcceptedSocket *) malloc(sizeof(struct AcceptedSocket));

  if (accepted_return == NULL)
  {
    LOG_ERROR(server, "Memory allocation for AcceptedSocket failed");
    exit(EXIT_FAILURE);
  }

  accepted_return->accepted_socket_fd = client_socket;
  accepted_return->address = client_address;

  if (client_socket < 0)
  {
    accepted_return->accepted_success = false;
    accepted_return->error = client_socket;
    LOG_ERROR(server, "Accept error: %s",
            strerror(errno));
  }
  else
  {

    accepted_return->accepted_success = true;
    accepted_return->error = 0;
    LOG_SUCCESS(server, "Client connected successfully.");
  }

  return accepted_return;
}

/**
 * @brief Send client messages to other client's
 * 
 * @param client_socket 
 * @param buffer 
 */
void send_the_buffer_other_clients(int client_socket, char *buffer) {
  pthread_mutex_lock(&accepted_sockets_mutex); // Lock access to accepted_sockets
  for (size_t i = 0; i < accepted_sockets_count; i++)
  {
    // Skip the client that sent the message
    if (accepted_sockets[i].accepted_socket_fd != client_socket)
    {
      ssize_t send_result = send(accepted_sockets[i].accepted_socket_fd, buffer, strlen(buffer), 0);

      if (send_result < 0)
      {
        LOG_ERROR(server, "Message send error (Client[%d]).", accepted_sockets[i].accepted_socket_fd % 11);
      }
      else
      {
        LOG_SUCCESS(server, "Message sent successfully. (Client[%d])", accepted_sockets[i].accepted_socket_fd % 11);
      }
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex); // Unlock access after done
}

/**
 * @brief Thread's working this function for the recv.
 * 
 * @param arg 
 * @return void* 
 */
void *recv_the_client(void *arg) {
  struct AcceptedSocket *client_socket = (struct AcceptedSocket *)arg;
  int client_socket_fd = client_socket->accepted_socket_fd;

  // Create Unique ThreadID
  int client_id = generate_client_id();

  // Do the login
  if (!secure_handle_login(client_socket_fd, client_id))
  {
    LOG_ERROR(server, "Client[%d] failed to login. Shutting down connection", client_id);
    close(client_socket_fd);
    free(client_socket);

    pthread_mutex_lock(&accepted_sockets_mutex);
    accepted_sockets_count--;
    pthread_mutex_unlock(&accepted_sockets_mutex);

    return NULL;
  } else {
    LOG_SUCCESS(server, "Receiveing messages and starting communication");
  }

  // Receive messages and start communication
  secure_handle_client_communication(client_socket_fd, client_id);

  // Find and remove client from the accepted list
  pthread_mutex_lock(&accepted_sockets_mutex);
  for (size_t i = 0; i < accepted_sockets_count; i++)
  {
    if (accepted_sockets[i].accepted_socket_fd == client_socket_fd)
    {
      close(client_socket_fd);

      // Shift the remaining clients down to fill the gap
      for (size_t j = i; j < accepted_sockets_count - 1; j++)
      {
        accepted_sockets[j] = accepted_sockets[j + 1];
      }

      accepted_sockets_count--; // Update client count after removing
      break;
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);

  free(client_socket); // Serbest bırakılacak doğru pointer
  return NULL;
}

/**
 * @brief Recv the Client's different thread's.
 *        Thread listen function: recv_the_client
 * 
 * @param client_socket 
 */
void recv_the_client_separate_threads(struct AcceptedSocket *client_socket)
{
  pthread_t sthread_id;

  if (pthread_create(&sthread_id, NULL, recv_the_client, client_socket) != 0)
  {
    LOG_ERROR(server, "Failed to create client thread");
    free(client_socket);
    interrupt_handler(-1);
    exit(EXIT_FAILURE);
  }

  int detach_result = pthread_detach(sthread_id);
  if (detach_result != 0)
  {
    LOG_ERROR(server, "Failed to detach client thread");
    interrupt_handler(-1);
    exit(EXIT_FAILURE);
  }

  LOG_INFO(server, "Thread created and detached successfully for client.");
  return;
}

/**
 * @brief Server handle the Client first time.
 * 
 * @param server_socket
 */
void start_accept_connections(int server_socket)
{
  while (true)
  {
    if (accepted_sockets_count >= MAX_CLIENTS)
    {
      LOG_ERROR(server, "Maximum number of clients reached. Rejecting new connections.");
      sleep(1); // Add the shorttime sleep
      continue;
    }

    struct AcceptedSocket *client_socket = AcceptIncomingConnections(server_socket);

    if (client_socket->accepted_success)
    {
      pthread_mutex_lock(&accepted_sockets_mutex); // Lock the array
      if (accepted_sockets_count < MAX_CLIENTS)
      {
        accepted_sockets[accepted_sockets_count++] = *client_socket;
        pthread_mutex_unlock(&accepted_sockets_mutex); // Unlock the array
        recv_the_client_separate_threads(client_socket);
      }
      else
      {
        pthread_mutex_unlock(&accepted_sockets_mutex); // Unlock the array in case of max clients
        shutdown(client_socket->accepted_socket_fd, SHUT_RDWR);
        free(client_socket);
      }
    }
  }
}


int main(int argc, char **argv) {
  //.. Initiliaze the signal handler: CTRL+C
  signal(SIGINT, interrupt_handler);

  // Create the server socket
  int server_socket = createTCPIp4Socket();

  // Define the server address
  char *address = "127.0.0.1";
  struct sockaddr_in *server_address = createIPv4Address(address, PORT);
  server_address_ptr = (void *)server_address;

  server_bind(server_socket, (struct sockaddr *)server_address);
  server_listen(server_socket);
  socket_list_allocate();
  start_accept_connections(server_socket);

  shutdown(server_socket, SHUT_RDWR);
  exit(EXIT_SUCCESS);
}

/**
 * @brief 
 * 
 * @param client_socket_fd 
 * @param sthread_id 
 * @return true 
 * @return false 
 */
bool secure_handle_login(int client_socket_fd, int sthread_id) {
  
  LOG_INFO(server, "Secure Handle Login.");
  bool login_successful = false;
  
  while (!login_successful)
  {
    char buffer[BUFFER_SIZE];
    char secure_buffer[BUFFER_SIZE];
    char *recv_buffer;
    
    ssize_t amount_received = recv(client_socket_fd, buffer, BUFFER_SIZE, 0);
    if (amount_received <= 0) {
      LOG_ERROR(server, "Recv the data error. (%zu)", amount_received);
      return false;
    } else {
      char *hex_ret = str_to_hex((const char*)(buffer), BUFFER_SIZE);
      LOG_SUCCESS(server, "Succes Recv data. (%zu)", amount_received);
      LOG_SUCCESS(server, "Data (Hex): %s", hex_ret);
      free(hex_ret);
    }
    
    LOG_INFO(server, "Start Decrypt message.");
    char *decrypted_msg = decrypt_message(buffer, RSA_size(load_private_key(PRIVATE_KEY)), PRIVATE_KEY);
    LOG_INFO(server, "Decrypted message: %s", decrypted_msg);
    LOG_INFO(server, " Decrypted message lenght: %zu", strlen(decrypted_msg));

    strncpy(buffer, decrypted_msg, BUFFER_SIZE);
    LOG_INFO(server, "Client[%d] sent login credentials: %s", sthread_id, buffer);

    // buffer format: "username:password"
    char username[32];
    char password[64];

    //  The ':' character will stop at the first occurrence (username)
    //  and take the rest of the character in its entirety (password)
    sscanf(buffer, "%[^:]:%[^\n]", username, password);

    if (check_credentials(username, password))
    {
      // ADD HASH MATCH FEATURE
      const char *success_message = "Login:Successfully";

      char *secure_enc = encrypt_message(success_message, PUBLIC_KEY);
      size_t send_ammount = send(client_socket_fd, secure_enc, BUFFER_SIZE, 0);
      
      if(send_ammount < 0) {
        LOG_ERROR(server, "Login Succes but data cannot sending.");
      } else {
        LOG_SUCCESS(server, "Login Succes and data send the client.");
        LOG_INFO(server, "Data Size: [%zu]", send_ammount);
      }
      login_successful = true;
    }
    else
    {
      const char *fail_message = "Username or Password not correct, try again";
      char *secure_enc = encrypt_message(fail_message, PUBLIC_KEY);

      size_t send_ammount = send(client_socket_fd, secure_enc, BUFFER_SIZE, 0);
      
      if(send_ammount < 0) {
        LOG_ERROR(server, "Login Failed and data cannot sending.");
      } else {
        LOG_INFO(server, "Login Failed and data send the client.");
        LOG_INFO(server, "Data Size: [%zu]", send_ammount);
      }
      
    }
  }

  return true; // If login success.
}

/**
 * @brief (SERVER) Handle CLient COm.
 * 
 * @param client_socket_fd 
 * @param sthread_id 
 */
void secure_handle_client_communication(int client_socket_fd, int sthread_id) {
  //.. Alocate buffer for the bad luck: All client's send message same time
  char buffer[BUFFER_SIZE];
  while (true)
  {

    ssize_t amount_received = recv(client_socket_fd, buffer, BUFFER_SIZE, 0);
    if (amount_received <= 0) {
      LOG_ERROR(server, "Failed to receive and share response's.");
      return (void)(-1);
      //exit(EXIT_FAILURE);
    } else {
      LOG_INFO(server, "Recieved Data Size: %zu", amount_received);
    }

    char *decrypted_recv = decrypt_message(buffer, RSA_size(load_private_key(PRIVATE_KEY)), PRIVATE_KEY);
    LOG_SUCCESS(server, "Decrypted Buffer: %s", decrypted_recv);
    LOG_SUCCESS(server, "Decrypted Buffer Lenght: %zu", strlen(decrypted_recv));
    LOG_INFO(server, "Client[%d]: %s", sthread_id, decrypted_recv);

    free(decrypted_recv);

    // Diğer istemcilere mesajı ilet
    secure_send_the_buffer_other_clients(client_socket_fd, buffer);
  }
}

/**
 * @brief Encrypted message sending other client's
 * 
 * @param client_socket 
 * @param buffer 
 */
void secure_send_the_buffer_other_clients(int client_socket, char *buffer) {

  pthread_mutex_lock(&accepted_sockets_mutex); // Lock access to accepted_sockets
  for (size_t i = 0; i < accepted_sockets_count; i++)
  {
    // Skip the client that sent the message
    if (accepted_sockets[i].accepted_socket_fd != client_socket)
    {
      ssize_t send_result = send(accepted_sockets[i].accepted_socket_fd, buffer, BUFFER_SIZE, 0);

      if (send_result < 0)
      {
        LOG_ERROR(server, "Message send error (Client[%d])", accepted_sockets[i].accepted_socket_fd % 11);
      }
      else
      {
        LOG_SUCCESS(server, "Message sent successfully. (Client[%d])", accepted_sockets[i].accepted_socket_fd % 11);
      }
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex); // Unlock access after done
}

// TCP_SERVER