// SOCKET PROGRAMMING "SOCKET_HEADER_FILE" //
// ------------------------    //
/**
 * @file socketutil.c
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2024-11-25
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#include "socketutil.h"

int createTCPIp4Socket(){

    // @params AF_INET: IPV4, SOCK_STREAM: TCP, PROTOCOL: 0
    int socket_return = socket(AF_INET, SOCK_STREAM, 0);

    // ? Socket is succesfully created
    if(socket_return < 0){
        LOG_ERROR(auth, "Socket error.");
        exit(EXIT_FAILURE);
    } else {
        LOG_SUCCESS(auth, "Socket created succesfully.");
    }

    return socket_return;
}

struct sockaddr_in* createIPv4Address(const char *ip_address, unsigned short int port){

    struct sockaddr_in *address = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    
    // Reset the created server_address using the memset
    // memset((struct sockaddr *)address, 0, sizeof(*address));

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    
    if(strlen(ip_address) == 0)
        address->sin_addr.s_addr = (INADDR_ANY);
    else
        inet_pton(AF_INET, ip_address, &(address->sin_addr));
        

    return address;
}
