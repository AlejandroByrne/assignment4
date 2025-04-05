/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#ifndef UTCS356_ASSN4_INC_UTCS_TCP_H_
#define UTCS356_ASSN4_INC_UTCS_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ut_packet.h"
#include "grading.h"

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

typedef struct {
  uint32_t last_ack;
  uint32_t last_sent;
  uint32_t last_write;
} send_win_t;

typedef struct {
  uint32_t last_read;
  uint32_t next_expect;
  uint32_t last_recv;
} recv_win_t;

/**
 * UTCS-TCP socket types. (DO NOT CHANGE.)
 */
typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} ut_socket_type_t;

/**
 * This structure holds the state of a socket. You may modify this structure as
 * you see fit to include any additional state you need for your implementation.
 */
typedef struct {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;

  uint8_t* received_buf;
  uint32_t received_len;
  pthread_mutex_t recv_lock;

  pthread_cond_t wait_cond;

  uint8_t* sending_buf;
  uint32_t sending_len;
  pthread_mutex_t send_lock;

  ut_socket_type_t type;
  int dying;
  pthread_mutex_t death_lock;

  bool complete_init; // Indicates whether the socket has completed initialization.
  bool send_syn;      // Specifies whether to send a SYN packet for initialization.
  bool recv_fin;      // Indicates whether a FIN packet has been received from the peer.
  bool fin_acked;     // Indicates whether a previously sent FIN packet has been acknowledged.

  uint32_t send_fin_seq;
  uint32_t recv_fin_seq;
  uint32_t dup_ack_count;

  send_win_t send_win;
  recv_win_t recv_win;
  uint32_t cong_win;
  uint32_t send_adv_win;
  uint32_t slow_start_thresh;
} ut_socket_t;

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

/**
 * Read mode flags supported by a UTCS-TCP socket.
 */
typedef enum {
  NO_FLAG = 0,  // Default behavior: block indefinitely until data is available.
  NO_WAIT,      // Return immediately if no data is available.
  TIMEOUT,      // Block until data is available or the timeout is reached.
} ut_read_mode_t;

/**
 * Constructs a UTCS-TCP socket.
 *
 * An Initiator socket is used to connect to a Listener socket.
 *
 * @param sock The structure with the socket state. It will be initialized by
 *             this function.
 * @param socket_type Indicates the type of socket: Listener or Initiator.
 * @param port Port to either connect to, or bind to. (Based on socket_type.)
 * @param server_ip IP address of the server to connect to. (Only used if the
 *                 socket is an initiator.)
 *
 * @return 0 on success, -1 on error.
 */
int ut_socket(ut_socket_t* sock, const ut_socket_type_t socket_type,
               const int port, const char* server_ip);

/**
 * Closes a UTCS-TCP socket.
 *
 * @param sock The socket to close.
 *
 * @return 0 on success, -1 on error.
 */
int ut_close(ut_socket_t* sock);

/**
 * Reads data from a UTCS-TCP socket.
 *
 * If there is data available in the socket buffer, it is placed in the
 * destination buffer.
 *
 * @param sock The socket to read from.
 * @param buf The buffer to read into.
 * @param length The maximum number of bytes to read.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `ut_read_mode_t` for more information. `TIMEOUT` is not
 *             implemented for UTCS-TCP.
 *
 * @return The number of bytes read on success, -1 on error.
 */
int ut_read(ut_socket_t* sock, void* buf, const int length,
             ut_read_mode_t flags);

/**
 * Writes data to a UTCS-TCP socket.
 *
 * @param sock The socket to write to.
 * @param buf The data to write.
 * @param length The number of bytes to write.
 *
 * @return 0 on success, -1 on error.
 */
int ut_write(ut_socket_t* sock, const void* buf, int length);

#endif  // UTCS356_ASSN4_INC_UTCS_TCP_H_
