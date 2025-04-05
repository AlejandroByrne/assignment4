/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include "ut_tcp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "backend.h"

int ut_socket(ut_socket_t *sock, const ut_socket_type_t socket_type,
               const int port, const char *server_ip) {
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  sock->socket = sockfd;
  sock->received_buf = NULL;
  sock->received_len = 0;
  pthread_mutex_init(&(sock->recv_lock), NULL);

  sock->sending_buf = NULL;
  sock->sending_len = 0;
  pthread_mutex_init(&(sock->send_lock), NULL);

  sock->type = socket_type;
  sock->dying = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  srand(time(NULL)); // Seed the random number generator
  sock->send_win.last_ack = rand() % 10000;
  sock->send_win.last_sent = sock->send_win.last_ack;
  sock->send_win.last_write = sock->send_win.last_ack + 1;

  sock->recv_win.last_read = 0;
  sock->recv_win.next_expect = 1;
  sock->recv_win.last_recv = 0;

  sock->complete_init = 0;
  sock->send_adv_win = 1;
  sock->recv_fin = 0;
  sock->fin_acked = 0;
  sock->dup_ack_count = 0;
  sock->cong_win = WINDOW_INITIAL_WINDOW_SIZE;
  sock->slow_start_thresh = WINDOW_INITIAL_SSTHRESH;

  if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }

  switch (socket_type) {
    case TCP_INITIATOR:
      sock->send_syn = 1;

      if (server_ip == NULL) {
        perror("ERROR server_ip NULL");
        return EXIT_ERROR;
      }
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(port);
      sock->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }

      break;

    case TCP_LISTENER:
      sock->send_syn = 0;

      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((uint16_t)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      sock->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  sock->my_port = ntohs(my_addr.sin_port);

  pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);
  return EXIT_SUCCESS;
}

int ut_close(ut_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  if (sock != NULL) {
    if (sock->received_buf != NULL) {
      free(sock->received_buf);
    }
    if (sock->sending_buf != NULL) {
      free(sock->sending_buf);
    }
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

int ut_read(ut_socket_t *sock, void *buf, int length, ut_read_mode_t flags) {
  uint8_t *new_buf;
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  switch (flags) {
    case NO_FLAG:
      while ((sock->recv_win.next_expect - sock->recv_win.last_read - 1) == 0) {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
      }
    // Fall through.
    case NO_WAIT:
      uint32_t avail = sock->recv_win.next_expect - sock->recv_win.last_read - 1;
      if (avail > 0) {
        read_len = avail > length ? length : avail;
        memcpy(buf, sock->received_buf, read_len);
        if (read_len < sock->received_len) {
          new_buf = malloc(sock->received_len - read_len);
          memcpy(new_buf, sock->received_buf + read_len,
                 sock->received_len - read_len);
          free(sock->received_buf);
          sock->received_len -= read_len;
          sock->received_buf = new_buf;
          sock->recv_win.last_read += read_len;
        } else {
          free(sock->received_buf);
          sock->received_buf = NULL;
          sock->received_len = 0;
          sock->recv_win.last_read += read_len;
        }
      }
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

int ut_write(ut_socket_t *sock, const void *buf, int length) {
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  int dying = sock->dying;
  pthread_mutex_unlock(&(sock->death_lock));

  if (dying) {
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }

  if (sock->sending_buf == NULL) {
    sock->sending_buf = malloc(length);
  }
  else {
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  }
  memcpy(sock->sending_buf + sock->sending_len, buf, length);
  sock->sending_len += length;
  sock->send_win.last_write += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}
