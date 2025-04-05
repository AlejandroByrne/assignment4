#!/usr/bin/env python3
# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin

import unittest

from .common import (
    SYN_MASK,
    TIMEOUT,
    UTTCP,
    check_packet_is_valid_synack,
    get_free_port,
    get_ut,
    launch_client,
    launch_server,
    sniff,
    sr1,
)

handshake_syn_packet_probes = {
    "initial seq num is 0": UTTCP(plen=23, seq_num=0, flags=SYN_MASK),
    "initial seq num is 1": UTTCP(plen=23, seq_num=1, flags=SYN_MASK),
    "initial seq num is 1000": UTTCP(plen=23, seq_num=1000, flags=SYN_MASK),
    "initial seq num is random": UTTCP(plen=23, seq_num=10004, flags=SYN_MASK),
}


class TestCases(unittest.TestCase):
    def test_initiator_syn(self):
        print("Test if the initiator sends a SYN packet.")

        server_port = get_free_port()
        with launch_client(server_port):
            syn_pkts, client_port = sniff(
                count=0, timeout=TIMEOUT * 3, portno=server_port
            )

            if len(syn_pkts) == 0:
                print("Did not receive SYN packet from initiator after 3 RTO.")
                assert False

            if syn_pkts[0][UTTCP].flags != SYN_MASK:
                print(
                    f"First packet was not a syn packet. Expect only SYN flag in "
                    f"the first packet, but got {syn_pkts[0][UTTCP].flags}."
                )
                assert False

    def test_listener_syn_ack(self):
        for test_name, probe in handshake_syn_packet_probes.items():
            print("-----------------------------------------")
            print(f"Testing: {test_name}.")
            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                resp = sr1(probe, TIMEOUT, server_port, client_port)
                next_seq_num = probe[UTTCP].seq_num + 1
                if check_packet_is_valid_synack(get_ut(resp), next_seq_num):
                    print(f"Passed {test_name}.")
                else:
                    print(f"Failed {test_name}. Did not receive a valid SYN ACK")

    # Feel free to add more test cases here!
    # def test_your_test_case(self):
    #     pass
