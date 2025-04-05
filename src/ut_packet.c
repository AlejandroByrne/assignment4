/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include "ut_packet.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint16_t get_src(ut_tcp_header_t* header) {
  return ntohs(header->source_port);
}

uint16_t get_dst(ut_tcp_header_t* header) {
  return ntohs(header->destination_port);
}

uint32_t get_seq(ut_tcp_header_t* header) { return ntohl(header->seq_num); }

uint32_t get_ack(ut_tcp_header_t* header) { return ntohl(header->ack_num); }

uint16_t get_hlen(ut_tcp_header_t* header) { return ntohs(header->hlen); }

uint16_t get_plen(ut_tcp_header_t* header) { return ntohs(header->plen); }

uint8_t get_flags(ut_tcp_header_t* header) { return header->flags; }

uint16_t get_advertised_window(ut_tcp_header_t* header) {
  return ntohs(header->advertised_window);
}

void set_src(ut_tcp_header_t* header, uint16_t src) {
  header->source_port = htons(src);
}

void set_dst(ut_tcp_header_t* header, uint16_t dst) {
  header->destination_port = htons(dst);
}

void set_seq(ut_tcp_header_t* header, uint32_t seq) {
  header->seq_num = htonl(seq);
}

void set_ack(ut_tcp_header_t* header, uint32_t ack) {
  header->ack_num = htonl(ack);
}

void set_hlen(ut_tcp_header_t* header, uint16_t hlen) {
  header->hlen = htons(hlen);
}

void set_plen(ut_tcp_header_t* header, uint16_t plen) {
  header->plen = htons(plen);
}

void set_flags(ut_tcp_header_t* header, uint8_t flags) {
  header->flags = flags;
}

void set_advertised_window(ut_tcp_header_t* header, uint16_t adv_window) {
  header->advertised_window = htons(adv_window);
}

void set_header(ut_tcp_header_t* header, uint16_t src, uint16_t dst,
                uint32_t seq, uint32_t ack, uint16_t hlen, uint16_t plen,
                uint8_t flags, uint16_t adv_window) {
  header->identifier = htonl(IDENTIFIER);
  header->source_port = htons(src);
  header->destination_port = htons(dst);
  header->seq_num = htonl(seq);
  header->ack_num = htonl(ack);
  header->hlen = htons(hlen);
  header->plen = htons(plen);
  header->flags = flags;
  header->advertised_window = htons(adv_window);
}

uint8_t* get_payload(uint8_t* pkt) {
  ut_tcp_header_t* header = (ut_tcp_header_t*)pkt;
  int offset = sizeof(ut_tcp_header_t);
  return (uint8_t*)header + offset;
}

uint16_t get_payload_len(uint8_t* pkt) {
  ut_tcp_header_t* header = (ut_tcp_header_t*)pkt;
  return get_plen(header) - get_hlen(header);
}

void set_payload(uint8_t* pkt, uint8_t* payload, uint16_t payload_len) {
  ut_tcp_header_t* header = (ut_tcp_header_t*)pkt;
  int offset = sizeof(ut_tcp_header_t);
  memcpy((uint8_t*)header + offset, payload, payload_len);
}

uint8_t* create_packet(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
                       uint16_t hlen, uint16_t plen, uint8_t flags,
                       uint16_t adv_window, uint8_t* payload, uint16_t payload_len) {
  if (hlen < sizeof(ut_tcp_header_t)) {
    return NULL;
  }
  if (plen < hlen) {
    return NULL;
  }

  uint8_t* packet = malloc(sizeof(ut_tcp_header_t) + payload_len);
  if (packet == NULL) {
    return NULL;
  }

  ut_tcp_header_t* header = (ut_tcp_header_t*)packet;
  set_header(header, src, dst, seq, ack, hlen, plen, flags, adv_window);

  uint8_t* pkt_payload = get_payload(packet);
  memcpy(pkt_payload, payload, payload_len);

  return packet;
}
