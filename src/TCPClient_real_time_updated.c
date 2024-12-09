
// SOCKET PROGRAMMING "TCP_CLIENT" //
// -----------------------------  //
/**
 * @file TCPClient.c
 * @author ...
 * @brief Client application for TCP communication with encryption and terminal-based messaging.
 * @version 0.2
 * @date 2024-12-09
 */

#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>    // For 'isatty' function
#include <sys/ioctl.h> // For 'ioctl' function

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
 * @brief Real-time controlled input and message sending to the server.
 * 
 * @param network_socket The client's network socket.
 * @param server_address Pointer to the server's address structure.
 * @param username The client's username.
 */
void secure_user_send_message(int network_socket, struct sockaddr *server_address, char *username) {
    char input_buffer[MAX_CHAR_LIMIT + 1] = {0}; // Buffer for user input, +1 for null terminator
    size_t char_count = 0;                      // Current character count
    char ch;                                    // Current character input
    char stack_buffer[BUFFER_SIZE];             // Buffer for sending message
    bool max_length_error = false;             // Flag for max length error

    newline_messagebox(); // Initialize message box
    fflush(stdout);

    while (true) {
        ch = getchar(); // Read a single character

        // Handle newline (Enter key)
        if (ch == '\n') {
            input_buffer[char_count] = '\0'; // Null-terminate the string
            if (strcmp(input_buffer, "/exit") == 0 || strcmp(input_buffer, "/quit") == 0) {
                break;
            }

            snprintf(stack_buffer, sizeof(stack_buffer), "%s: %s", username, input_buffer);
            char *encrypted_message = encrypt_message(stack_buffer, PUBLIC_KEY);
            if (!encrypted_message) {
                LOG_ERROR(client, "Encryption failed.");
                free(encrypted_message);
                exit(EXIT_FAILURE);
            } else {
                LOG_SUCCESS(client, "Encrypted message length: %zu", strlen(encrypted_message));
            }
            
            if (send_secure(network_socket, encrypted_message) == 0) {
                LOG_SUCCESS(client, "Encrypted message sent to server successfully.");
                free(encrypted_message);
            }

            fflush(stdout);
            char_count = 0; // Reset for next input
            max_length_error = false; // Reset error state
            continue;
        }

        // Handle backspace
        if (ch == 127 || ch == '\b') {
            if (char_count > 0) {
                char_count--;
                printf("\b \b"); // Erase character from terminal
                fflush(stdout);
            }
            continue;
        }

        // Handle character input within limit
        if (char_count < MAX_CHAR_LIMIT) {
            input_buffer[char_count++] = ch;
            putchar(ch); // Echo character
            fflush(stdout);
        } else if (!max_length_error) {
            // Show max length error message once
            max_length_error = true;
            printf("\n\033[1;31mError: Maximum message size is %d characters.\033[0m\n", MAX_CHAR_LIMIT);
            printf("Enter your message: %s", input_buffer);
            fflush(stdout);
        }
    }
}

/**
 * @brief Dynamically display active users at the bottom of the terminal.
 * 
 * @param user_count The number of active users.
 * @param usernames An array of active usernames.
 */
void display_active_users(int user_count, char **usernames) {
    printf("\033[s"); // Save cursor position
    int terminal_height = get_terminal_height();
    printf("\033[%d;1H", terminal_height - 1); // Move to the bottom line
    printf("\033[K"); // Clear the line
    printf(RESET HWHT "Active Users (%d): ", user_count);
    for (int i = 0; i < user_count; i++) {
        printf("%s%s", usernames[i], (i < user_count - 1) ? ", " : "");
    }
    printf(RESET);
    printf("\033[u"); // Restore cursor position
    fflush(stdout);
}
