// SOCKET PROGRAMMING "TCP_CLIENT" //
// -----------------------------  //
/**
 * @file TCPClient.c
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
#include <errno.h>
#include <string.h>
#include <unistd.h>    // for the 'isatty' function
#include <sys/ioctl.h> // for the 'ioctl' function

#include "tcpclient.h"

#define PUBLIC_KEY getPublicKeyPath()
#define PRIVATE_KEY getPrivateKeyPath()
#define MAX_CHAR_LIMIT 256

char *username_ptr = NULL;

/**
 * @brief Adds a newline and logs the current user's online status.
 */
void newline_messagebox() {
    fprintf(stdout, "\n");
    if (username_ptr) {
        LOG_MSG(username_ptr, online);
    } else {
        LOG_MSG("unknown", online);
    }
    fflush(stdout); // Clear output buffer
}

/**
 * @brief Adds a newline and logs the current user's online status.
 */
void messagebox() {
    if (username_ptr) {
        LOG_MSG(username_ptr, online);
    } else {
        LOG_MSG("unknown", online);
    }
    fflush(stdout); // Clear output buffer
}


/**
 * @brief Get the width of the terminal.
 * 
 * @return int Terminal width or a default value (80)
 */
int get_terminal_width() {
    struct winsize ws; // Window size
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1) {
        return ws.ws_col;
    }
    return 80; // Default width
}


/**
 * @brief Get the height of the terminal.
 * 
 * @return int Terminal height or a default value (20)
 */
int get_terminal_height() {
    struct winsize ws; // Window size
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1) {
        return ws.ws_row;
    }
    return 20; // Default height
}


/**
 * @brief Create new thread for the listen another client messages.
 * 
 * @param network_socket
 */
void start_listening_messages_new_thread(int network_socket) {
    pthread_t thread_id;
    int *socket_copy = (int *)malloc(sizeof(int));
    *socket_copy = network_socket;

    int thread_result = pthread_create(&thread_id, NULL, secure_listening_messages_thread, socket_copy);

    if (thread_result != 0) {
        LOG_ERROR(client, "Failed to create thread");
        exit(EXIT_FAILURE);
    }
    pthread_detach(thread_id);
}

/**
 * @brief Server connect the spesified adress
 * 
 * @param network_socket 
 * @param server_address 
 * @return true 
 * @return false 
 */
bool connect_the_adress(int network_socket, struct sockaddr *server_address) {
  size_t server_size = sizeof(*server_address);

  if (connect(network_socket, server_address, server_size) < 0) {
    LOG_ERROR(client, "Connection error.");
    shutdown(network_socket, SHUT_RDWR);
    free(server_address);
    return false;
  }

  LOG_SUCCESS(client, "Connection successfully.");
  return true;
}

/**
 * @brief Get the username object
 * 
 * @return char* 
 */
char *get_username() {
    char *username = NULL;
    size_t username_size = 0;

    if (username_ptr == NULL) {
        username_ptr = (char *)malloc(32 * sizeof(char)); // Daha güvenli bellek ayırma
        if (username_ptr == NULL) {
            LOG_ERROR(client, "Failed to allocate memory for username_ptr");
            exit(EXIT_FAILURE);
        }
    }

    while (true) {
      fprintf(stdout, BCYN "  - Please enter your username: ");
      getline(&username, &username_size, stdin);
      if (username == NULL) {
          LOG_ERROR(client, "Failed to read username");
          exit(EXIT_FAILURE);
      }
      // Yeni satırı kaldır
      username[strcspn(username, "\n")] = '\0';
      if (strlen(username) > 3 && strlen(username) <= 32) {
          strncpy(username_ptr, username, 32);
          
          username_ptr[strcspn(username_ptr, "\n")] = '\0';
          if(username_ptr == NULL){
            LOG_ERROR(client, "User name cannot write memory -> (%s)", username_ptr);
          }
          free(username); // Bellek serbest bırakılır
          break;
      } else {
          LOG_ERROR(client, "Username must be between 4 and 32 characters");
          sleep(3);
          free(username);
          system("clear");
      }
    }

    system("clear");
    return username_ptr;
}

/**
 * @brief Get the password object
 * 
 * @return char* 
 */
char *get_password() {
  char *password = NULL;
  size_t password_size = 0;

  while (true) {
    fprintf(stdout, BCYN "  - Please enter your password: ");
    getline(&password, &password_size, stdin);

    if (strlen(password) >= 3 && strlen(password) <= 64) {
      break;
    } else {
      LOG_ERROR(client, "Password must be the min 4 and max 64 characters");
      sleep(3);
      free(password);
      system("clear");
    }
  }

  system("clear");
  return password;
}

/**
 * @brief 
 * 
 * @param network_socket 
 * @param buffer 
 * @return true 
 * @return false 
 */
bool send_the_buffer(int network_socket, char *buffer) {
  if (buffer == NULL || strlen(buffer) == 0) {
    LOG_ERROR(client, "Invalid buffer.");
    return false;
  }

  ssize_t amount_was_sent = send(network_socket, buffer, strlen(buffer), 0);
  if (amount_was_sent < 0) {
    LOG_ERROR(client, "Error sending message.");
    return false;
  }

  return true;
}

/**
 * @brief 
 * 
 * @param network_socket 
 * @param buffer 
 * @return true 
 * @return false 
 */
bool send_secure(int network_socket, const char *buffer) {
  if (buffer == NULL || strlen(buffer) == 0) {
    LOG_ERROR(client, "Invalid buffer.");
    return false;
  }

  ssize_t amount_was_sent = send(network_socket, buffer, BUFFER_SIZE, 0);
  if (amount_was_sent < 0) {
    LOG_ERROR(client, "Error sending message.");
    return false;
  }

  newline_messagebox();
  return true;
}


int main() {

  int network_socket = createTCPIp4Socket();
  struct sockaddr_in *server_address = createIPv4Address(address, PORT);
  bool connection_status = connect_the_adress(network_socket, (struct sockaddr *)server_address);

  if(!connection_status){
    exit(EXIT_FAILURE);
  }

  encryped_user_login(network_socket, (struct sockaddr *)server_address);
  start_listening_messages_new_thread(network_socket);
  secure_user_send_message(network_socket, (struct sockaddr *)server_address, username_ptr);

  shutdown(network_socket, SHUT_RDWR);
  free(server_address);
  exit(EXIT_SUCCESS);
}

/**
 * @brief RSA and AES using for the between client-server LOGIN communicitation.
 * 
 * @param network_socket
 * @param server_address 
 */
void encryped_user_login(int network_socket, struct sockaddr *server_address) {

  bool login_successful = false;

  while (!login_successful) {
      char *username = NULL, *password = NULL;
      char buffer[BUFFER_SIZE];
      char secure_recv[BUFFER_SIZE];
      
      username = get_username();
      username[strcspn(username, "\n")] = '\0';
      password = get_password();
      password[strcspn(password, "\n")] = '\0';

      int sn_ret = snprintf(buffer, sizeof(buffer), "%s:%s", username, password);
      if (sn_ret < 0 || (size_t)sn_ret >= sizeof(buffer)) {
          LOG_ERROR(client, "Buffer overflow in user login.");
          free(username);
          free(password);
          exit(EXIT_FAILURE);
      }

      char *secure_enc = encrypt_message(buffer, PUBLIC_KEY);
      if (!secure_enc) {
          LOG_ERROR(client, "Encryption failed.");
          free(password);
          exit(EXIT_FAILURE);
      } else {
          char *hex_ret = str_to_hex(secure_enc, BUFFER_SIZE);
          LOG_SUCCESS(client, "Encrypted message       : %s", hex_ret);
          LOG_SUCCESS(client, "Encrypted message lenght: %zu", strlen(secure_enc));   
      }

      if (send(network_socket, secure_enc, BUFFER_SIZE, 0) < 0) {
          LOG_ERROR(client, "Failed to send encrypted login data.");
          free(password);
          exit(EXIT_FAILURE);
      } else {
          LOG_SUCCESS(client, "Succes send encrypted login data");
      }

      LOG_SUCCESS(client, "Recv the data from server");
      ssize_t amount_received = recv(network_socket, secure_recv, BUFFER_SIZE, 0);
      if (amount_received <= 0) {
        LOG_ERROR(client, "Failed to receive server response.");
        exit(EXIT_FAILURE);
      } else {
        char *hex_ret = str_to_hex(secure_recv, BUFFER_SIZE);
        LOG_SUCCESS(client, "Recieved Data Size  : %zu", amount_received);
        LOG_SUCCESS(client, "Secure Buffer (hex) : %s", (const char *)hex_ret);
        LOG_SUCCESS(client, "Secure Buffer Lenght: %zu", strlen(secure_recv));
      }

      char *decrypted_recv = decrypt_message(secure_recv, RSA_size(load_private_key(PRIVATE_KEY)), PRIVATE_KEY);

      LOG_SUCCESS(client, "Decrypted Buffer       : %s", decrypted_recv);
      LOG_SUCCESS(client, "Decrypted Buffer Lenght: %zu", strlen(decrypted_recv));
      
      const char *success_message = "Login:Successfully";
      if (strncmp(decrypted_recv, success_message, sizeof(char[19])) == 0) {
          LOG_SUCCESS(client, "Login successful.");
          login_successful = true; 
      } else {
          LOG_INFO(client, "Login failed: %s", decrypted_recv);
      }
  }
}

/**
 * @brief Non Real-time controlled input and message sending to the server.
 * 
 * @param network_socket The client's network socket.
 * @param server_address Pointer to the server's address structure.
 * @param username The client's username.
 */
void secure_user_send_message(int network_socket, struct sockaddr *server_address, char *username) {
    char *terminal_line = NULL;     // Kullanıcı girişini tutar
    size_t terminal_line_size = 0;  // Giriş boyutunu tutar
    char stack_buffer[BUFFER_SIZE]; // Mesaj tamponu
    bool max_length_err = false;
    unsigned int err_count = 0;

    newline_messagebox(); // Mesaj kutusunu başlat

    while (true) {
        if (terminal_line != NULL) {
            free(terminal_line);
        }
        terminal_line = NULL;
        terminal_line_size = 0;

        printf("\033[s"); // Cursor pozisyonunu kaydet
        unsigned int return_char_count = getline(&terminal_line, &terminal_line_size, stdin);
        
        if (return_char_count == (unsigned int)(-1)) {
            LOG_ERROR(client, "Terminal line error [%u]", err_count);
            err_count++;
            continue;
        } else if (return_char_count == 1 && terminal_line[0] == '\n') {
            printf("\033[K"); // Satırı temizle
            printf("\033[u"); // Cursor pozisyonunu eski haline getir
            printf("\033[K"); // Satırı temizle
            printf("\r");
            messagebox();
            fflush(stdout);
            continue;
        }

        if ((size_t)256 < strlen(terminal_line)) {
            max_length_err = true;
            printf("\033[s"); // Cursor pozisyonunu kaydet
            int terminal_height = get_terminal_height();
            printf("\033[%d;1H", terminal_height); // En alt satıra git
            printf(RESET BLKHB HWHT "Error: Max character size is 256 (Current: %zu)" RESET, strlen(terminal_line));
            printf("\033[u"); // Cursor pozisyonunu eski haline getir
            fflush(stdout);
            continue;
        } else if (max_length_err) {
            // Hata mesajını temizle
            max_length_err = false;
            printf("\033[s"); // Cursor pozisyonunu kaydet
            int terminal_height = get_terminal_height();
            printf("\033[%d;1H", terminal_height); // En alt satıra git
            printf("\033[K"); // Satırı temizle
            printf("\033[u"); // Cursor pozisyonunu eski haline getir
            fflush(stdout);
        }

        terminal_line[strcspn(terminal_line, "\n")] = '\0';
        if (strcmp(terminal_line, "/exit") == 0 || strcmp(terminal_line, "/quit") == 0) {
            break;
        }

        snprintf(stack_buffer, sizeof(stack_buffer), "%s: %s", username, terminal_line);

        // Şifreleme ve mesaj gönderme
        char *return_encryption = encrypt_message(stack_buffer, PUBLIC_KEY);
        if (!return_encryption) {
            LOG_ERROR(client, "Encryption failed.");
            free(return_encryption);
            exit(EXIT_FAILURE);
        } else {
            LOG_SUCCESS(client, "Encrypted message length: %zu", strlen(return_encryption));
        }

        if (send_secure(network_socket, return_encryption) == 0) {
            LOG_SUCCESS(client, "Encrypted message sent to server successfully.");
        }
        free(return_encryption);
    }
}


/**
 * @brief (CLIENT)Threads working on this function for the client-server-client com.
 * 
 * @param arg 
 * @return void* 
 */
void *secure_listening_messages_thread(void *arg) {
    int network_socket = *(int *)arg;
    free(arg); // Soket kopyasını serbest bırak
    char buffer[BUFFER_SIZE*MAX_CLIENTS];

    int terminal_width = get_terminal_width(); // Terminal genişliğini dinamik olarak al
    size_t half_terminal_width = (size_t)terminal_width / 2;

    while (true) {
      ssize_t amount_received = recv(network_socket, buffer, BUFFER_SIZE, 0);
      if (amount_received <= 0) 
      {
          if (amount_received == 0) {
              LOG_ERROR(client, "Connection closed by server");
          } else {
              LOG_ERROR(client, "Message receive error");
          }
          break; // Hata durumunda döngüden çık
      }
      
      // DEC START
      LOG_INFO(client, "Decryption is start");
      char *decrypted_buffer = decrypt_message(buffer, RSA_size(load_private_key(PRIVATE_KEY)), PRIVATE_KEY);
      strncpy(buffer, decrypted_buffer, BUFFER_SIZE);
      LOG_INFO(client, "Decrypted Buffer: %s", decrypted_buffer);
      LOG_INFO(client, "Decrypted Buffer Lenght: %zu", strlen(decrypted_buffer));
      // DEC END
      
      buffer[amount_received] = '\0';
      size_t message_length = strlen(buffer);

      char temp_username[32];
      char temp_buffer[1024];
      sscanf(buffer, "%31[^:]:%1023[^\n]", temp_username, temp_buffer);
      size_t username_len = strlen(temp_username);
      message_length -= username_len;
      fprintf(stdout, "\r"); // Satırı başa döndür
      
      if (half_terminal_width < message_length){
          size_t start_index = 0;
          size_t remaining_length = message_length;
          fprintf(stdout, BCYN "%*s-[%s]:", (int)half_terminal_width, "", temp_username);
          while (remaining_length > 0) {
              size_t line_length = remaining_length > half_terminal_width ? half_terminal_width : remaining_length;
              fprintf(stdout, "\n");
              fprintf(stdout, BCYN "%*s", (int)half_terminal_width, "");
              fwrite(temp_buffer + start_index, 1, line_length, stdout);
              remaining_length -= line_length;
              start_index += line_length;
        }
        } else {
            fprintf(stdout, BCYN "%*s%s\n", (int)half_terminal_width, "", buffer);
        }
        fflush(stdout);
        newline_messagebox(); // Mesaj yazdırma işleminden sonra çağrılır
    }

    return NULL;
}

// TCP_CLIENT