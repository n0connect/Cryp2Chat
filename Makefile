# Compiler and flags
CC = g++
CFLAGS = -g -Wall -Wextra -std=c++20
INCLUDES = -Iheaders
LDFLAGS = $(shell pkg-config --libs openssl) -lssl -lcrypto -lgmp -lgmpxx
SFLAG = -static

# Directories
SRC_DIR = src
BUILD_DIR = build

# Source and object files
SRC_FILES_SERVER = $(SRC_DIR)/TCPServer.c $(SRC_DIR)/socketutil.c $(SRC_DIR)/database.c $(SRC_DIR)/cryp2.cpp $(SRC_DIR)/strtohex.c $(SRC_DIR)/serverkey.c
SRC_FILES_CLIENT = $(SRC_DIR)/TCPClient.c $(SRC_DIR)/socketutil.c $(SRC_DIR)/cryp2.cpp $(SRC_DIR)/strtohex.c $(SRC_DIR)/clientkey.c
OBJ_FILES_SERVER = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRC_FILES_SERVER)))
OBJ_FILES_CLIENT = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRC_FILES_CLIENT)))

# Targets
all: build server client

build:
	mkdir -p $(BUILD_DIR)

server: $(OBJ_FILES_SERVER)
	$(CC) $(CFLAGS) $(OBJ_FILES_SERVER) -o server $(LDFLAGS) $(SFLAG)

client: $(OBJ_FILES_CLIENT)
	$(CC) $(CFLAGS) $(OBJ_FILES_CLIENT) -o client $(LDFLAGS) $(SFLAG)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) server client
