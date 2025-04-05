# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin

from __future__ import annotations

import subprocess
import time
from contextlib import contextmanager

from scapy.all import (
    ByteEnumField,
    IntField,
    Packet,
    Raw,
    ShortField,
    bind_layers,
    socket,
)
from scapy.layers.inet import UDP

HOST_PORT = 1234
TESTING_HOST_PORT = 8000

T_UDP_IP = "127.0.0.1"
T_UDP_PORT = 12000

test_addr = (T_UDP_IP, T_UDP_PORT)

FIN_MASK = 0x2
ACK_MASK = 0x4
SYN_MASK = 0x8

TIMEOUT = 1

TEST_CLIENT = "tests/testing_client"
TEST_SERVER = "tests/testing_server"


def get_ut(pkt):
    """Converts a raw packet into a UT TCP packet."""
    if pkt is None:
        return None
    elif UTTCP in pkt:
        return pkt[UTTCP]
    elif Raw in pkt:
        try:
            return UTTCP(pkt[Raw])
        except Exception:
            return None
    else:
        return None


def check_packet_is_valid_synack(pkt, expected_ack_num):
    """Check packets for required characteristics."""
    if pkt is None:
        print("Did not receive SYN+ACK packet")
        return False
    pkt = get_ut(pkt)
    if pkt is None:
        print("Received packet is not a UTTCP packet")
        return False
    if not (pkt.flags & SYN_MASK):
        print("SYN+ACK packet does not contain SYN flag")
        return False
    if pkt.flags != (SYN_MASK | ACK_MASK):
        print("SYN+ACK packet has SYN flag but no ACK flag")
        return False
    if pkt.ack_num != expected_ack_num:
        print("SYNACK packet's ACK number is incorrect")
        return False
    if pkt.plen != pkt.hlen or len(pkt) != pkt.hlen or len(pkt.payload) != 0:
        print("SYNACK packet has unexpected plen/payload")
        return False
    return True


def get_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portno = sock.getsockname()[1]
    sock.close()
    return portno


@contextmanager
def launch_client(server_port: int):
    p = subprocess.Popen(
        [TEST_CLIENT, str(server_port)],
        stdout=None,
        stderr=None,
    )
    try:
        time.sleep(1)
        yield p
    finally:
        p.terminate()
        p.wait()


@contextmanager
def launch_server(server_port: int):
    p = subprocess.Popen(
        [TEST_SERVER, str(server_port)],
        stdout=None,
        stderr=None,
    )
    try:
        time.sleep(1)
        yield p
    finally:
        p.terminate()
        p.wait()


@contextmanager
def mock_socket(portno, timeout=TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", portno))
        sock.settimeout(float(timeout))
        yield sock
    finally:
        sock.close()


def sr1(message, timeout, dest_port, bind_port):
    with mock_socket(bind_port, timeout) as sock:
        sock.sendto(bytes(message), ("127.0.0.1", dest_port))
        try:
            data, rcv_addr = sock.recvfrom(4096)
            data = get_ut(UTTCP(data))
        except Exception:
            data = None
    return data


def send(message, bind_port, dest_port):
    with mock_socket(bind_port) as sock:
        sock.sendto(bytes(message), ("127.0.0.1", dest_port))


def sniff(count, timeout, portno=12000):
    if count == 0:
        count = float("inf")

    with mock_socket(portno, timeout) as sock:
        pkts = []
        num_pkts = 0
        start_time = time.time()
        end_time = start_time
        rcv_addr = ("0.0.0.0", -1)
        while (end_time - start_time) < timeout:
            try:
                data, rcv_addr = sock.recvfrom(4096)
            except Exception:
                data = None
            if data is not None:
                pkts.append(UTTCP(data))
                num_pkts += 1
                if num_pkts == count:
                    break
            end_time = time.time()

    return pkts, rcv_addr[1]


"""
These tests assume there is only one connection in the PCAP
and expects the PCAP to be collected on the server. All of
the basic tests pass on the starter code, without you having
to make any changes. You will need to add to these tests as
you add functionality to your implementation. It is also
important to understand what the given tests are testing for!
"""


# we can make UTTCP packets using scapy
class UTTCP(Packet):
    name = "UT TCP"
    fields_desc = [
        IntField("identifier", 51085),
        ShortField("source_port", HOST_PORT),
        ShortField("destination_port", TESTING_HOST_PORT),
        IntField("seq_num", 0),
        IntField("ack_num", 0),
        ShortField("hlen", 23),
        ShortField("plen", 23),
        ByteEnumField(
            "flags",
            0,
            {
                FIN_MASK: "FIN",
                ACK_MASK: "ACK",
                SYN_MASK: "SYN",
                FIN_MASK | ACK_MASK: "FIN ACK",
                SYN_MASK | ACK_MASK: "SYN ACK",
            },
        ),
        ShortField("advertised_window", 1),
    ]

    def answers(self, other):
        return isinstance(other, UTTCP)


bind_layers(UDP, UTTCP)
