#!/usr/bin/env python3
# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin

import unittest

from scapy.all import Raw
from .common import (
    SYN_MASK,
    ACK_MASK,
    FIN_MASK,
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
    def test_ack_numbers(self):
        print("Test if ACK numbers are correct during handshake.")
        server_port = get_free_port()
        client_port = get_free_port()
        
        with launch_server(server_port):
            # Send SYN packet
            syn_pkt = UTTCP(plen=23, seq_num=1000, flags=SYN_MASK)
            syn_ack_resp = sr1(syn_pkt, TIMEOUT, server_port, client_port)
            
            if syn_ack_resp is None:
                print("Did not receive SYN-ACK response")
                assert False
                
            # Check if ACK number is correct (should be SYN seq + 1)
            expected_ack = syn_pkt[UTTCP].seq_num + 1
            received_ack = get_ut(syn_ack_resp).ack_num
            
            if received_ack != expected_ack:
                print(f"ACK number incorrect. Expected {expected_ack}, got {received_ack}")
                assert False
                
            # Send ACK to complete handshake
            ack_pkt = UTTCP(plen=23, seq_num=syn_ack_resp[UTTCP].ack_num, 
                          ack_num=syn_ack_resp[UTTCP].seq_num + 1, flags=ACK_MASK)
            sr1(ack_pkt, TIMEOUT, server_port, client_port)
            
            print("ACK numbers test passed")

    def test_connection_termination(self):
        print("Test if connection termination works correctly.")
        server_port = get_free_port()
        client_port = get_free_port()
        
        with launch_server(server_port):
            # Complete three-way handshake first
            syn_pkt = UTTCP(plen=23, seq_num=1000, flags=SYN_MASK)
            syn_ack_resp = sr1(syn_pkt, TIMEOUT, server_port, client_port)
            ack_pkt = UTTCP(plen=23, seq_num=syn_ack_resp[UTTCP].ack_num, 
                          ack_num=syn_ack_resp[UTTCP].seq_num + 1, flags=ACK_MASK)
            sr1(ack_pkt, TIMEOUT, server_port, client_port)
            
            # Send FIN packet
            fin_pkt = UTTCP(plen=23, seq_num=syn_ack_resp[UTTCP].ack_num, 
                          ack_num=syn_ack_resp[UTTCP].seq_num + 1, flags=FIN_MASK)
            fin_ack_resp = sr1(fin_pkt, TIMEOUT, server_port, client_port)
            
            if fin_ack_resp is None:
                print("Did not receive FIN-ACK response")
                assert False
                
            # Check if FIN-ACK has correct sequence and acknowledgment numbers
            expected_ack = fin_pkt[UTTCP].seq_num + 1
            received_ack = get_ut(fin_ack_resp).ack_num
            
            if received_ack != expected_ack:
                print(f"FIN-ACK number incorrect. Expected {expected_ack}, got {received_ack}")
                assert False
                
            print("Connection termination test passed")
    
    def test_sliding_window_data_transfer(self):
        print("Test sliding window implementation with data transfer.")
        server_port = get_free_port()
        client_port = get_free_port()
        
        # Test data to send
        test_data = b"Hello, this is a test message for sliding window implementation!"
        data_len = len(test_data)
        
        with launch_server(server_port):
            # Complete three-way handshake
            syn_pkt = UTTCP(plen=23, seq_num=1000, flags=SYN_MASK)
            syn_ack_resp = sr1(syn_pkt, TIMEOUT, server_port, client_port)
            ack_pkt = UTTCP(plen=23, seq_num=syn_ack_resp[UTTCP].ack_num, 
                          ack_num=syn_ack_resp[UTTCP].seq_num + 1, flags=ACK_MASK)
            sr1(ack_pkt, TIMEOUT, server_port, client_port)
            
            # Send data in multiple segments to test sliding window
            # First segment
            data_pkt1 = UTTCP(plen=23 + 20, seq_num=syn_ack_resp[UTTCP].ack_num,
                            ack_num=syn_ack_resp[UTTCP].seq_num + 1, flags=ACK_MASK)
            data_pkt1 = data_pkt1 / Raw(load=test_data[:20])
            ack_resp1 = sr1(data_pkt1, TIMEOUT, server_port, client_port)
            
            # Verify first ACK
            if ack_resp1 is None:
                print("Did not receive ACK for first data segment")
                assert False
            if ack_resp1[UTTCP].ack_num != data_pkt1[UTTCP].seq_num + 20:
                print(f"ACK number incorrect for first segment. Expected {data_pkt1[UTTCP].seq_num + 20}, got {ack_resp1[UTTCP].ack_num}")
                assert False
            
            # Second segment
            data_pkt2 = UTTCP(plen=23 + 20, seq_num=data_pkt1[UTTCP].seq_num + 20,
                            ack_num=ack_resp1[UTTCP].seq_num, flags=ACK_MASK)
            data_pkt2 = data_pkt2 / Raw(load=test_data[20:40])
            ack_resp2 = sr1(data_pkt2, TIMEOUT, server_port, client_port)
            
            # Verify second ACK
            if ack_resp2 is None:
                print("Did not receive ACK for second data segment")
                assert False
            if ack_resp2[UTTCP].ack_num != data_pkt2[UTTCP].seq_num + 20:
                print(f"ACK number incorrect for second segment. Expected {data_pkt2[UTTCP].seq_num + 20}, got {ack_resp2[UTTCP].ack_num}")
                assert False
            
            # Final segment
            data_pkt3 = UTTCP(plen=23 + (data_len - 40), seq_num=data_pkt2[UTTCP].seq_num + 20,
                            ack_num=ack_resp2[UTTCP].seq_num, flags=ACK_MASK)
            data_pkt3 = data_pkt3 / Raw(load=test_data[40:])
            ack_resp3 = sr1(data_pkt3, TIMEOUT, server_port, client_port)
            
            # Verify final ACK
            if ack_resp3 is None:
                print("Did not receive ACK for final data segment")
                assert False
            if ack_resp3[UTTCP].ack_num != data_pkt3[UTTCP].seq_num + (data_len - 40):
                print(f"ACK number incorrect for final segment. Expected {data_pkt3[UTTCP].seq_num + (data_len - 40)}, got {ack_resp3[UTTCP].ack_num}")
                assert False
            
            print("Sliding window data transfer test passed")