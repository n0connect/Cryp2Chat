// SOCKET PROGRAMMING "SOCKET_HEADER" //
// ------------------------    //
#ifndef SOCKETUTIL_SOCKETUTIL_H
#define SOCKETUTIL_SOCKETUTIL_H
// ------------------------    //
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include "colorcodes.h"
#include "logmacro.h"
// ------------------------    //
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
// ------------------------    //


int createTCPIp4Socket();
struct sockaddr_in* createIPv4Address(const char *ip_address, unsigned short int port);

#endif //SOCKETUTIL_SOCKETUTIL_H