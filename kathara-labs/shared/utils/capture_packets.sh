#!/usr/bin/env bash
# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOST=$(hostname)
IFNAME=eth0
FUNCTION_TO_RUN=$1
PCAP_NAME=$2

if [ -z "$FUNCTION_TO_RUN" ]
    then
        echo "usage: ./capture_packets.sh < start | stop | analyze > PCAP_NAME"
        echo "Expecting name of function to run: start, stop, or analyze."
        exit 1
fi

if [ -z "$PCAP_NAME" ]
  then
    PCAP_NAME=$HOST.pcap
    echo NO PCAP_NAME PARAM SO USING DEFAULT FILE: $PCAP_NAME
fi

start() {
    tcpdump -i $IFNAME -w $PCAP_NAME udp > /dev/null 2> /dev/null < \
    /dev/null &
}

stop() {
    pkill -f "tcpdump -i $IFNAME -w $PCAP_NAME udp"
}

analyze() {
    tshark -X lua_script:$DIR/tcp.lua -R "uttcp and not icmp" -r $PCAP_NAME \
    -T fields \
    -e frame.time_relative \
    -e ip.src \
    -e uttcp.source_port \
    -e ip.dst \
    -e uttcp.destination_port \
    -e uttcp.seq_num \
    -e uttcp.ack_num \
    -e uttcp.hlen \
    -e uttcp.plen \
    -e uttcp.flags \
    -e uttcp.advertised_window \
    -E header=y -E separator=, \
    -2
}

$FUNCTION_TO_RUN
