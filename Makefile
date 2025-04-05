TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build
KATHARA_SHARED_DIR = $(TOP_DIR)/kathara-labs/shared
CC=gcc
FLAGS = -pthread -fPIC -g -ggdb -pedantic -Wall -Wextra -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/ut_packet.o $(BUILD_DIR)/ut_tcp.o $(BUILD_DIR)/backend.o

all: server client tests/testing_client tests/testing_server

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(FLAGS) -c -o $@ $<

server: $(OBJS) $(SRC_DIR)/server.c
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)
	cp server $(KATHARA_SHARED_DIR)

client: $(OBJS) $(SRC_DIR)/client.c
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS)
	cp client $(KATHARA_SHARED_DIR)

tests/testing_client: $(OBJS)
	$(CC) $(FLAGS) tests/testing_client.c -o tests/testing_client $(OBJS)

tests/testing_server: $(OBJS)
	$(CC) $(FLAGS) tests/testing_server.c -o tests/testing_server $(OBJS)

test:
	sudo -E python3 -m unittest tests/test_ack_packets.py

clean:
	rm -f $(BUILD_DIR)/*.o client server
	rm -f tests/testing_client
	rm -f tests/testing_server
