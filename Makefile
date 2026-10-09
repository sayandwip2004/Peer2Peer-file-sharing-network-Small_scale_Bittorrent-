CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Iinclude -Isrc
LDLIBS  = -lpthread
BIN     = bin

PROTO   = src/protocol.c src/peer.c src/choker.c
STORE   = src/metadata.c src/sha256.c src/piece_manager.c

all: $(BIN)/tracker $(BIN)/mktorrent $(BIN)/peer

$(BIN):
	mkdir -p $(BIN)

$(BIN)/tracker: src/tracker.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

$(BIN)/mktorrent: src/mktorrent.c src/metadata.c src/sha256.c | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@

$(BIN)/peer: src/peer_main.c $(PROTO) $(STORE) | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/test_pieces: tests/test_pieces.c $(STORE) src/choker.c | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/test_kritideepta: tests/test_kritideepta.c $(PROTO) | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: $(BIN)/test_pieces $(BIN)/test_kritideepta
	./$(BIN)/test_pieces
	./$(BIN)/test_kritideepta

clean:
	rm -rf $(BIN)

.PHONY: all test clean
