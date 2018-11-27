/*  Ankit Gola
 *  2017EET2296
 *
 *  Utility functions declarations
 */

#ifndef __FTP_MYSOCKET_H__
#define __FTP_MYSOCKET_H__

// Include files
#include <stdio.h>
#include "sys/socket.h"

// Struct
struct sockaddr new_addr(uint32_t inaddr, unsigned short port);

// Create new server
int new_server(uint32_t inaddr, uint16_t port, int backlog);

// Create new client
int new_client(uint32_t srv_addr, unsigned short port);

// Send string
int send_str(int peer, const char *fmt, ...);

// Send file
int send_file(int peer, FILE *f);

// Send path
int send_path(int peer, char *file, uint32_t offset);

// Recieve file
int recv_file(int peer, FILE *f);

// Recieve path
int recv_path(int peer, char *file, uint32_t offset);

// Parse number
int parse_number(const char *buf, uint32_t *number);

// Parse address and port for server
int parse_addr_port(const char *buf, uint32_t *addr, uint16_t *port);

// Parse path
char * parse_path(const char *buf);

// Parse address as string
char * n2a(uint32_t addr);

#endif

