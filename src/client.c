/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"

#define BUF_SIZE 16000

void functionality(ut_socket_t *sock) {
  uint8_t buf[BUF_SIZE];
  int read;
  FILE *fp;

  ut_write(sock, "Knock knock", 11);
  read = ut_read(sock, buf, 200, NO_FLAG);
  printf("R: %.*s\n", read, buf);
  printf("N: %d\n", read);

  ut_write(sock, "Client", 6);
  read = ut_read(sock, buf, 200, NO_FLAG);
  printf("R: %.*s\n", read, buf);
  printf("N: %d\n", read);

  ut_write(sock, "Client believe you’re still LISTENing — can I connect now?", 63);

  sleep(1);

  fp = fopen("tests/random.input", "rb");
  if (fp == NULL) {
    perror("Error opening file");
    exit(EXIT_FAILURE);
  }
  read = 1;
  int total_read = 0;
  while (read > 0) {
    read = fread(buf, 1, 2000, fp);
    if (read > 0) {
      int error = 0;
      int retry = 0;
      do {
        error = ut_write(sock, buf, read);
        if (error != 0){
          retry++;
          printf("Error writing to socket, retrying...: %d\n", retry);
          sleep(1);
        }
      } while(error != 0 && retry < 10);
      if (error != 0) {
        perror("Error writing to socket");
        exit(EXIT_FAILURE);
      }
    }
    total_read += read;
  }
  printf("Total read: %d\n", total_read);
  sleep(1);
  fclose(fp);
}

int main() {
  int portno;
  char *serverip;
  char *serverport;
  ut_socket_t socket;

  serverip = getenv("UT_TCP_ADDR");
  if (!serverip) {
    serverip = "127.0.0.1";
  }

  serverport = getenv("UT_TCP_PORT");
  if (!serverport) {
    serverport = "8000";
  }
  portno = (uint16_t)atoi(serverport);

  if (ut_socket(&socket, TCP_INITIATOR, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket);

  if (ut_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
