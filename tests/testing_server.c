/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"

#define BUF_SIZE 16000

void functionality(ut_socket_t *sock) {
  uint8_t buf[BUF_SIZE];
  FILE *fp;
  int n;
  int read;

  n = 0;
  while (n == 0) {
    n = ut_read(sock, buf, BUF_SIZE, NO_FLAG);
  }
  printf("Read %d bytes\n", n);

  // Send over a random file
  fp = fopen("tests/random.input", "rb");
  read = 1;
  while (read > 0) {
    read = fread(buf, 1, 2000, fp);
    if (read > 0) ut_write(sock, buf, read);
  }
}

int main(int argc, char **argv) {
  int portno;
  char *serverip;
  ut_socket_t socket;

  serverip = "127.0.0.1";

  if (argc > 1) {
    portno = atoi(argv[1]);
  } else {
    portno = 12000;
  }

  printf("starting initiator\n");
  if (ut_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
    exit(EXIT_FAILURE);
  sleep(1);
  functionality(&socket);

  if (ut_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
