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

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how
 *  the sockets will be used.
 *
 */
void functionality(ut_socket_t *sock, int file_size_in_bytes) {
  uint8_t buf[BUF_SIZE];
  FILE *fp;
  int n;

  n = ut_read(sock, buf, BUF_SIZE, NO_FLAG);
  printf("R: %.*s\n", n, buf);
  printf("N: %d\n", n);
  ut_write(sock, "Who's there?", 12);

  n = ut_read(sock, buf, 200, NO_FLAG);
  printf("R: %.*s\n", n, buf);
  printf("N: %d\n", n);
  ut_write(sock, "Client who?", 11);

  n = ut_read(sock, buf, 200, NO_FLAG);
  printf("R: %.*s\n", n, buf);
  printf("N: %d\n", n);

  if (access("tests/random.output", F_OK) == 0) {
    remove("tests/random.output");
  }

  printf("Writing output file...\n");
  int total_n = 0;
  fp = fopen("tests/random.output", "a");
  for (int i = 0; i < 10000; i++) {
    n = ut_read(sock, buf, BUF_SIZE, NO_FLAG);
    if (n > 0) {
      fwrite(buf, n, 1, fp);
    }
    total_n += n;
    if (total_n >= file_size_in_bytes) {
      break;
    }
    printf("Num read bytes: %d\n", total_n);
    usleep(100 * 1000);
  }
  fclose(fp);
}

int main() {
  int portno;
  int file_size_in_bytes;
  char *serverip;
  char *serverport;
  char *filesize;
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

  filesize = getenv("UT_TCP_FILE_SIZE");
  if (!filesize) {
    filesize = "10240";
  }
  file_size_in_bytes = atoi(filesize);

  if (ut_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket, file_size_in_bytes);

  if (ut_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
