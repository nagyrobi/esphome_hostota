CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
LDFLAGS ?= -lssl -lcrypto

SRC := $(wildcard src/*.cpp)
OBJ := $(SRC:.cpp=.o)
BIN := esphome_hostota

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(BIN) $(OBJ)
