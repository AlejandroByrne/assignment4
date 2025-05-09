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

 #include "ut_packet.h"
 #include "ut_tcp.h"
 #include <assert.h>

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
   * If the socket is a listener, it handles incoming SYN packets and ACK responses, updating the socket's state and windows as needed.
   */
   uint8_t flags = get_flags(hdr);
   uint32_t seq = get_seq(hdr);
   uint32_t ack = get_ack(hdr);

   if (sock->type == TCP_INITIATOR) { // Client side
     if ((flags & SYN_FLAG_MASK) && (flags & ACK_FLAG_MASK)) {
       // Step 2: Client receives SYN-ACK from server
       sock->recv_win.next_expect = seq + 1;
       sock->recv_win.last_read = seq;
       sock->recv_win.last_recv = seq;

       // Update send window
       sock->send_win.last_ack = ack - 1;
       sock->send_win.last_sent = ack - 1;
       sock->send_win.last_write = ack - 1;

       // Connection is now initialized
       sock->send_syn = false;
       sock->complete_init = true;

       // Step 3: Send ACK to server
       send_empty(sock, ACK_FLAG_MASK, false, false);
     }
   } else { // Server side
     if ((flags & SYN_FLAG_MASK) && !(flags & ACK_FLAG_MASK)) {
       // Step 1: Server receives SYN from client
       sock->recv_win.next_expect = seq + 1;
       sock->recv_win.last_read = seq;
       sock->recv_win.last_recv = seq;

       // Initialize send window
       sock->send_win.last_ack = seq;
       sock->send_win.last_sent = seq;
       sock->send_win.last_write = seq;

       // Mark connection as initialized
       sock->complete_init = true;

       // Step 2: Send SYN-ACK to client
       send_empty(sock, SYN_FLAG_MASK | ACK_FLAG_MASK, false, false);
     } 
     else if (flags & ACK_FLAG_MASK) {
       // Step 3: Server receives ACK from client
       if (!after(ack - 1, sock->send_win.last_ack)) {
         sock->send_win.last_ack = ack - 1;
         sock->send_win.last_sent = ack - 1;
         sock->send_win.last_write = ack - 1;
       }
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

   // Extract the TCP header and sequence number from the packet
   ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;
   uint32_t seq = get_seq(hdr);
   uint32_t plen = get_plen(hdr);
   uint32_t hlen = get_hlen(hdr);
   uint32_t payload_len = plen - hlen;
   uint8_t *payload = pkt + hlen;

   // Calculate the end of the data segment
   uint32_t data_end = seq + payload_len;

   // Check if we have space in the receive buffer
   if (sock->received_len + payload_len > MAX_NETWORK_BUFFER) {
      //assert(false);
       // Buffer is full, drop the packet
       return;
   }

   // Check if this is an in-order packet
   if (seq == sock->recv_win.next_expect) {
      printf("This is an in-order packet\n");
       // Calculate the offset in the receive buffer
       uint32_t offset = seq - sock->recv_win.last_read - 1;
       
       // Copy the payload into the receive buffer
       memcpy(sock->received_buf + offset, payload, payload_len);
       
       // Update the receive window
       sock->recv_win.next_expect = data_end;
       sock->recv_win.last_recv = MAX(sock->recv_win.last_recv, data_end - 1);
       sock->received_len += payload_len;
       
       // Send acknowledgment
       send_empty(sock, ACK_FLAG_MASK, false, false);
       //assert(false);
   } else if (seq > sock->recv_win.next_expect) {
      //assert(false);
       // Out-of-order packet, store it if we have space
       uint32_t offset = seq - sock->recv_win.last_read - 1;
       if (offset + payload_len <= MAX_NETWORK_BUFFER) {
           memcpy(sock->received_buf + offset, payload, payload_len);
           sock->recv_win.last_recv = MAX(sock->recv_win.last_recv, data_end - 1);
       }
   }
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

   // Handle FIN flag
   if (flags & FIN_FLAG_MASK) {
     // Mark that we received a FIN and store its sequence number
     sock->recv_fin = true;
     sock->recv_fin_seq = get_seq(hdr);
     // Send ACK for the FIN
     send_empty(sock, ACK_FLAG_MASK, true, false);
   }

   // Update advertised window
   sock->send_adv_win = MAX_NETWORK_BUFFER - sock->recv_win.last_recv - sock->recv_win.last_read;
   

   // Handle ACK flag
   if (flags & ACK_FLAG_MASK) {
     uint32_t ack = get_ack(hdr);
     
     // Case 1: ACK after sending FIN
     if (sock->dying && ack == sock->send_fin_seq + 1) {
       sock->fin_acked = true;
     }
     
     // Case 2: ACK after sending data
     if (after(ack - 1, sock->send_win.last_ack)) {
       handle_ack(sock, hdr);
     }
   }

   // Update receive buffer
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
   if (sock->type == TCP_INITIATOR)
   {
     if (sock->send_syn)
     {
       send_empty(sock, SYN_FLAG_MASK, false, false);
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
    
    // Calculate available window size
    uint32_t available_window = MIN(sock->cong_win, sock->send_adv_win);
    uint32_t bytes_to_send = sock->send_win.last_write - sock->send_win.last_sent;
    uint32_t bytes_can_send = MIN(available_window, bytes_to_send);
    
    // If no data to send or window is full, return
    if (bytes_to_send == 0 || bytes_can_send == 0) {
        // If advertised window is 0, probe with one byte
        if (sock->send_adv_win == 0 && bytes_to_send > 0) {
            bytes_can_send = 1;
        } else {
            return;
        }
    }
    
    // Calculate how many full MSS segments we can send
    uint32_t num_segments = bytes_can_send / MSS;
    uint32_t remaining_bytes = bytes_can_send % MSS;
    
    // Send full MSS segments
    for (uint32_t i = 0; i < num_segments; i++) {
        uint32_t seq = sock->send_win.last_sent + 1;
        uint32_t ack = sock->recv_win.next_expect;
        
        // Create and send packet
        uint8_t *payload = sock->sending_buf + (seq - sock->send_win.last_ack - 1);
        uint16_t payload_len = MSS;
        
        uint8_t *msg = create_packet(
            sock->my_port,
            ntohs(sock->conn.sin_port),
            seq,
            ack,
            sizeof(ut_tcp_header_t),
            sizeof(ut_tcp_header_t) + payload_len,
            ACK_FLAG_MASK,
            MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len),
            payload,
            payload_len
        );
        
        sendto(sock->socket, msg, sizeof(ut_tcp_header_t) + payload_len, 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        free(msg);
        
        // Update last_sent
        sock->send_win.last_sent += payload_len;
    }
    
    // Send remaining bytes if any
    if (remaining_bytes > 0) {
        uint32_t seq = sock->send_win.last_sent + 1;
        uint32_t ack = sock->recv_win.next_expect;
        
        // Create and send packet
        uint8_t *payload = sock->sending_buf + (seq - sock->send_win.last_ack - 1);
        uint16_t payload_len = remaining_bytes;
        
        uint8_t *msg = create_packet(
            sock->my_port,
            ntohs(sock->conn.sin_port),
            seq,
            ack,
            sizeof(ut_tcp_header_t),
            sizeof(ut_tcp_header_t) + payload_len,
            ACK_FLAG_MASK,
            MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len),
            payload,
            payload_len
        );
        
        sendto(sock->socket, msg, sizeof(ut_tcp_header_t) + payload_len, 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        free(msg);
        
        // Update last_sent
        sock->send_win.last_sent += payload_len;
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
