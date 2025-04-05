#!/usr/bin bash

sudo apt-get update

sudo apt-get install -y build-essential vim emacs tree tmux git gdb valgrind python3-dev libffi-dev libssl-dev \
    clang-format iperf3 tshark iproute2 iputils-ping net-tools tcpdump cppcheck

sudo apt-get install -y python3 python3-pip libcairo2 libcairo2-dev libgirepository1.0-dev

pip3 install --upgrade pip
pip3 install -r requirements.txt
