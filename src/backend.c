/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

 #include "backend.h"

 #include <poll.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdbool.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <errno.h>
 #include <assert.h>

 #include "ut_packet.h"
 #include "ut_tcp.h"

 #define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
 #define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

 void send_empty(ut_socket_t *sock, int s_flags, bool fin_ack, bool send_fin)
 {
   size_t conn_len = sizeof(sock->conn);
   int sockfd = sock->socket;

   uint16_t src = sock->my_port;
   uint16_t dst = ntohs(sock->conn.sin_port);

   uint32_t seq = sock->send_win.last_sent + 1;
   if (send_fin)
   {
     seq = sock->send_fin_seq;
   }
   uint32_t ack = sock->recv_win.next_expect;
   if (fin_ack)
   {
     ack++;
   }

   uint16_t hlen = sizeof(ut_tcp_header_t);
   uint8_t flags = s_flags;
   uint16_t adv_window = MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len);

   uint16_t payload_len = 0;
   uint8_t *payload = &flags;
   uint16_t plen = hlen + payload_len;

   uint8_t *msg = create_packet(
       src, dst, seq, ack, hlen, plen, flags, adv_window, payload, payload_len);
   sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
   free(msg);
 }

 bool check_dying(ut_socket_t *sock)
 {
   while (pthread_mutex_lock(&(sock->death_lock)) != 0)
   {
   }
   bool dying = sock->dying;
   if (dying)
   {
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     if (sock->sending_len == 0)
     {
       sock->send_fin_seq = sock->send_win.last_write + 1;
     }
     else
     {
       dying = false;
     }
     pthread_mutex_unlock(&(sock->send_lock));
   }
   pthread_mutex_unlock(&(sock->death_lock));
   return dying;
 }

 void handle_pkt_handshake(ut_socket_t *sock, ut_tcp_header_t *hdr)
 {
   /*
   TODOs:
   * The `handle_pkt_handshake` function processes TCP handshake packets for a given socket.
   * DONE It first extracts the flags from the TCP header and determines whether the socket is an initiator or a listener.
   * If the socket is an initiator, it verifies the SYN-ACK response and updates the send and receive windows accordingly.
   * If the socket is a listener, it handles incoming SYN packets and ACK responses, updating the socket’s state and windows as needed.
   */

   // REMEMBER: this function gets called after a packet has been received and the data has been read

  uint8_t flags = get_flags(hdr);

  if (sock->type == TCP_INITIATOR) { // assume we just sent the initial SYN and are now receiving the SYN+ACK
    // verify the SYN-ACK response
    // printf("Initiator received the SYN+ACK\n");
    assert((flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) ==
    (SYN_FLAG_MASK | ACK_FLAG_MASK));
    printf("Initiator received SYN+ACK\n");
    printf("seq: %d\n", get_seq(hdr));
    printf("ack: %d\n", get_ack(hdr));
    sock->send_syn = false;

    //update receive window with server’s ISN
    sock->send_win.last_ack = get_ack(hdr) - 1;
    sock->send_win.last_sent = get_ack(hdr) - 1;

    sock->recv_win.last_read = get_seq(hdr);
    sock->recv_win.last_recv = get_seq(hdr);
    sock->recv_win.next_expect = get_seq(hdr) + 1;  // SYN+ACK consumes 1 byte

    // slide our send window

  } else { // only two cases, we know we're the listener in this case
    // handle the incoming SYN or ACK responses.
    if ((flags & SYN_FLAG_MASK) == SYN_FLAG_MASK) { // CASE 1: received a SYN
      // printf("Listener received the initial SYN\n");
      // update receive window
      printf("Listener received SYN\n");
      printf("seq: %d\n", get_seq(hdr));
      printf("ack: %d\n", get_ack(hdr));
      sock->recv_win.last_read = get_seq(hdr);
      sock->recv_win.last_recv = get_seq(hdr);
      sock->recv_win.next_expect = get_seq(hdr) + 1;  // SYN consumes 1 byte

      sock->send_syn = true;
      // sending window should be updated in send_pkts_handshake()

    } else if ((flags & ACK_FLAG_MASK) == ACK_FLAG_MASK) { // CASE 2: received the final ACK for the handshake
      // do not have to set the complete_init flag, it should have already been sent
      // printf("Listener got the final ack\n");
      printf("Listener received ACK\n");
      printf("seq: %d\n", get_seq(hdr));
      printf("ack: %d\n", get_ack(hdr));
      //when receive ack, update send window in ANY CASE
      sock->send_win.last_ack = get_ack(hdr) - 1;
      sock->send_win.last_sent = get_ack(hdr) - 1;

      sock->complete_init = true;
      sock->send_syn = false;
    }
  }
 }

 void handle_ack(ut_socket_t *sock, ut_tcp_header_t *hdr)
 {
   if (after(get_ack(hdr) - 1, sock->send_win.last_ack))
   {
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     /*
     TODOs:
     * Reset duplicated ACK count to zero.
     * Update the congestion window.
     * Update the sender window based on the ACK field.
       * Update `last_ack`, re-allocate the sending buffer, and update the `sending_len` field.
     */
     pthread_mutex_unlock(&(sock->send_lock));
   }
   // Handle Duplicated ACK.
   else if (get_ack(hdr) - 1 == sock->send_win.last_ack)
   {
     if (sock->dup_ack_count == 3)  // `Fast recovery` state
     {
       sock->cong_win += MSS;
     }
     else // `Slow start` or `Congestion avoidance` state
     {
       /*
       TODOs:
       * Increment the duplicated ACK count (Up to 3).
       * If the duplicated ACK count reaches 3, adjust the congestion window and slow start threshold.
       * Retransmit missing segments using Go-back-N (i.e., update the `last_sent` to `last_ack`).
       */
     }
   }
 }

 void update_received_buf(ut_socket_t *sock, uint8_t *pkt)
 {
   /*
   - This function processes an incoming TCP packet by updating the receive buffer based on the packet's sequence number and payload length.
   - If the new data extends beyond the last received sequence, it reallocates the receive buffer and copies the payload into the correct position.

   TODOs:
   * Extract the TCP header and sequence number from the packet.
   * Determine the end of the data segment and update the receive window if needed.
   * Copy the payload into the receive buffer based on the sequence number:
     * Ensure that the required buffer space does not exceed `MAX_NETWORK_BUFFER` before proceeding.
     * Use `memcpy` to copy the payload:
       memcpy(void *to, const void *from, size_t numBytes);
   * Send an acknowledgment if the packet arrives in order:
     * Use the `send_empty` function to send the acknowledgment.
   */

   ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;

    /* ----------- extract lengths and pointers --------------------- */
    uint32_t seq  = get_seq(hdr);               /* first byte of payload */
    uint16_t plen = get_plen(hdr);
    uint16_t hlen = get_hlen(hdr);
    uint16_t dlen = plen - hlen;                /* payload size         */

    if (dlen == 0) {                            /* nothing to store     */
        send_empty(sock, ACK_FLAG_MASK, false, false);
        return;
    }

    /* ----------- calculate where this data belongs ---------------- */
    /* byte (last_read+1) is stored at offset 0 in received_buf */
    uint32_t offset = seq - (sock->recv_win.last_read + 1);
    uint32_t seg_end = seq + dlen - 1;
    uint32_t needed  = offset + dlen;           /* bytes of buffer we’ll touch */

    if (needed > MAX_NETWORK_BUFFER)            /* would overflow our buf */
        return;                                 /* drop segment silently */

    /* ----------- (re)allocate receive buffer if needed ------------ */
    if (sock->received_buf == NULL) {
        sock->received_buf = malloc(needed);
        sock->received_len = 0;
    } else if (needed > sock->received_len) {
        sock->received_buf = realloc(sock->received_buf, needed);
    }

    /* ----------- copy payload into the right slot ----------------- */
    memcpy(sock->received_buf + offset, pkt + hlen, dlen);

    /* ----------- book‑keeping for window pointers ----------------- */
    if (seg_end > sock->recv_win.last_recv)
        sock->recv_win.last_recv = seg_end;

    if (seq == sock->recv_win.next_expect) {
        /* we just filled the next missing byte → advance contiguous run */
        sock->recv_win.next_expect = seg_end + 1;
    }

    if (needed > sock->received_len)
        sock->received_len = needed;

    /* ----------- send cumulative ACK back to the peer ------------- */
    send_empty(sock, ACK_FLAG_MASK, false, false);

 }

 void handle_pkt(ut_socket_t *sock, uint8_t *pkt)
 {
   ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;
   uint8_t flags = get_flags(hdr);
   if (!sock->complete_init)
   {
     handle_pkt_handshake(sock, hdr);
     return;
   }
     /*
     TODOs:
     * Handle the FIN flag.
       * Mark the socket as having received a FIN, store the sequence number, and send an ACK response.

     * Update the advertised window.
     * Handle the ACK flag. You will have to handle the following cases:
       1) ACK after sending FIN.
         * If the ACK is for the FIN sequence, mark the socket as FIN-ACKed.
       2) ACK after sending data.
         * If the ACK is for a new sequence, update the send window and congestion control (call `handle_ack`).
     * Update the receive buffer (call `update_received_buf`).
     */

    /* ---------------------------------------------------------------
       2.  Flow‑control: remember the peer’s advertised window.
       --------------------------------------------------------------- */
    sock->send_adv_win = get_advertised_window(hdr);

    /* ---------------------------------------------------------------
       3.  ACK processing (data‑path only, FIN ignored for now).
       --------------------------------------------------------------- */
    if (flags & ACK_FLAG_MASK) {
        handle_ack(sock, hdr);          /* will deal with new vs. dup ACKs */
    }

    /* ---------------------------------------------------------------
       4.  Payload (and cumulative‑ACK generation on our side).
           Even if the segment carries *no* payload, calling the helper
           is harmless—it will notice dlen == 0 and return.
       --------------------------------------------------------------- */
    printf("");
    update_received_buf(sock, pkt);
 }

 void recv_pkts(ut_socket_t *sock)
 {
   ut_tcp_header_t hdr;
   uint8_t *pkt;
   socklen_t conn_len = sizeof(sock->conn);
   ssize_t len = 0, n = 0;
   uint32_t plen = 0, buf_size = 0;

   struct pollfd ack_fd;
   ack_fd.fd = sock->socket;
   ack_fd.events = POLLIN;
   if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) > 0)
   {
     len = recvfrom(sock->socket, &hdr, sizeof(ut_tcp_header_t),
                    MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                    &conn_len);
   }
   else  // TIMEOUT
   {
     /*
     TODOs:
     * Reset duplicated ACK count to zero.
     * Implement the rest of timeout handling
       * Congestion control window and slow start threshold adjustment
       * Adjust the send window for retransmission of lost packets (Go-back-N)
     */
   }

   if (len >= (ssize_t)sizeof(ut_tcp_header_t))
   {
     plen = get_plen(&hdr);
     pkt = malloc(plen);
     while (buf_size < plen)
     {
       n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                    (struct sockaddr *)&(sock->conn), &conn_len);
       buf_size = buf_size + n;
     }
     while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
     {
     }
     handle_pkt(sock, pkt);
     pthread_mutex_unlock(&(sock->recv_lock));
     free(pkt);
   }
 }

 void send_pkts_handshake(ut_socket_t *sock)
 {
   /*
   TODOs:
   * Implement the handshake initialization logic.
   * We provide an example of sending a SYN packet by the initiator below:
   */

   // REMEMBER: this function gets called right before the data is actually sent/written

   if (sock->type == TCP_INITIATOR)
   {
     if (sock->send_syn) { // case 1: sending the first SYN
        // printf("initiator: %d\n", sock->send_win.last_sent);
        // printf("Initiator sending SYN\n");
        printf("Initiator sending SYN seq: %d\n", sock->send_win.last_sent);
        send_empty(sock, SYN_FLAG_MASK, false, false); // send_win.last_sent + 1 happens here
     } else { // case 2: sending the final ACK to complete the handshake, can start sending data after this
        // printf("Initiator sending final ACK\n");
        sock->complete_init = true;
        printf("Initiator sending ACK seq: %d\n", sock->send_win.last_sent);
        // we can assume that this final ack will not be dropped, per #265 on Ed.
        send_empty(sock, ACK_FLAG_MASK, false, false);
     }
   } else { // listener side, received the first SYN from the sender, now to send SYN+ACK
    if (sock->send_syn) {
      // have to send the syn+ack packet
      // printf("listener: %d\n", sock->send_win.last_sent);
      printf("Listener sending SYN+ACK seq: %d\n", sock->send_win.last_sent);
      // uint32_t isn = (uint32_t) rand();
      // sock->send_win.last_sent = isn - 1;
      // sock->send_win.last_ack = isn - 1;
      // sock->send_win.last_write = 0;
      send_empty(sock, SYN_FLAG_MASK | ACK_FLAG_MASK, false, false);
    }
   }
 }

 void send_pkts_data(ut_socket_t *sock)
 {
   /*
   * Sends packets of data over a TCP connection.
   * This function handles the transmission of data packets over a TCP connection
     using the provided socket. It ensures that the data is sent within the constraints
     of the congestion window, advertised window, and maximum segment size (MSS).

   TODOs:
   * Calculate the available window size for sending data based on the congestion window,
     advertised window, and the amount of data already sent.
   * Iterate the following steps until the available window size is consumed in the sending buffer:
     * Create and send packets with appropriate sequence and acknowledgment numbers,
       ensuring the payload length does not exceed the available window or MSS.
       * Refer to the send_empty function for guidance on creating and sending packets.
     * Update the last sent sequence number after each packet is sent.
   */

  // in order to calculate the available window size for sending data, we have to know how much data is currently in flight
  uint32_t in_flight = sock->send_win.last_sent - sock->send_win.last_ack;
  uint32_t win_limit = MIN(sock->cong_win, sock->send_adv_win);

  if (in_flight >= win_limit) return;                 /* window full */

  uint32_t usable = win_limit - in_flight;

  /* unsent bytes start right after the in‑flight region inside sending_buf */
  uint32_t unsent_off = in_flight;
  uint32_t unsent_len = (sock->sending_len > unsent_off)
                        ? (sock->sending_len - unsent_off)
                        : 0;

  if (unsent_len == 0) return;                        /* nothing buffered */

  uint8_t  *payload_ptr = sock->sending_buf + unsent_off;
  uint32_t  to_push     = MIN(usable, unsent_len);

  /* ------------------------------------------------------------------
     2.  Send as many MSS‑sized chunks as fit into ‘to_push’
     ------------------------------------------------------------------ */
  size_t   conn_len = sizeof(sock->conn);
  int      sockfd   = sock->socket;

  while (to_push > 0) {
      uint16_t seg_len = (uint16_t)MIN(MSS, to_push);

      /* header fields */
      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);

      uint32_t seq = sock->send_win.last_sent + 1;    /* next byte to send */
      uint32_t ack = sock->recv_win.next_expect;      /* piggy‑back ACK   */

      uint16_t hlen = sizeof(ut_tcp_header_t);
      uint16_t plen = hlen + seg_len;
      uint8_t  flags = ACK_FLAG_MASK;                 /* data + cumulative ACK */

      uint16_t adv_window =
          MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len);

      /* craft packet */
      uint8_t *msg = create_packet(src, dst, seq, ack,
                                   hlen, plen, flags,
                                   adv_window,
                                   payload_ptr, seg_len);

      sendto(sockfd, msg, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(msg);

      /* bookkeeping -------------------------------------------------- */
      sock->send_win.last_sent += seg_len;            /* extend in‑flight */
      payload_ptr               += seg_len;
      to_push                   -= seg_len;
  }
   
 }

 void send_pkts(ut_socket_t *sock)
 {
   if (!sock->complete_init)
   {
     send_pkts_handshake(sock);
   }
   else
   {
     // Stop sending when duplicated ACKs are received and not in fast recovery state.
     if (sock->dup_ack_count < 3 && sock->dup_ack_count > 0)
       return;
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     send_pkts_data(sock);
     pthread_mutex_unlock(&(sock->send_lock));
   }
 }

 void *begin_backend(void *in)
 {
   ut_socket_t *sock = (ut_socket_t *)in;
   int death, buf_len, send_signal;
   uint8_t *data;

   while (1)
   {
     if (check_dying(sock))
     {
       if (!sock->fin_acked)
       {
         send_empty(sock, FIN_FLAG_MASK, false, true);
       }
     }

     if (sock->fin_acked && sock->recv_fin)
     {
       // Finish the connection after timeout
       sleep(DEFAULT_TIMEOUT / 1000);
       break;
     }
     send_pkts(sock);
     recv_pkts(sock);
     while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
     {
     }
     uint32_t avail = sock->recv_win.next_expect - sock->recv_win.last_read - 1;
     send_signal = avail > 0;
     pthread_mutex_unlock(&(sock->recv_lock));

     if (send_signal)
     {
       pthread_cond_signal(&(sock->wait_cond));
     }
   }
   pthread_exit(NULL);
   return NULL;
 }
