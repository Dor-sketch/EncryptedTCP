# Compiler options
CXX = g++
CPPFLAGS = -I$(BOOST_INCLUDE) -I$(CRYPTOPP_LIB)

# Replace '/path/to/boost' and '/path/to/cryptopp' with the actual paths on your system
CRYPTOPP_LIB = /usr/local/opt/cryptopp
BOOST_ROOT = /usr/local/opt/boost
FMT_LIB = /usr/local/opt/fmt

# Add this path to the library path
LDFLAGS = -L$(BOOST_LIB) -L$(CRYPTOPP_LIB) -L$(FMT_LIB)

# Link the libraries
LDLIBS = -lboost_system -lcryptopp -lfmt

BOOST_INCLUDE = $(BOOST_ROOT)/include
BOOST_LIB = $(BOOST_ROOT)/lib
BOOST_LIBS = -lboost_system -lboost_filesystem

CXXFLAGS = -I$(BOOST_INCLUDE) -I/usr/include/cryptopp -std=c++17 -Wall -Wextra -pedantic -g -mrdrnd

# Adding a conditional compile flag for decryption
ifeq ($(MODE),decrypt)
CXXFLAGS += -DDECRYPT_MODE
endif

# Adding a conditional compile flag for log level
ifeq ($(LOG_LEVEL),CRITICAL)
CXXFLAGS += -DCRITICAL_LOGGING_ONLY
endif

ifeq ($(LOG_LEVEL),DEBUG)
CPPFLAGS += -DENABLE_DEBUG_LOGGING
endif

# Link the libraries
LDLIBS += -lboost_system -lcryptopp


# Source files and object files
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)

# Executable file
EXEC = client_app

# Targets
all: $(EXEC)

debug: CPPFLAGS += -DENABLE_DEBUG_LOGGING
debug: all

info: $(EXEC) transfer.info

transfer.info:
	echo "127.0.0.1:1234" > transfer.info
	echo "Michael Jackson" >> transfer.info
	echo "makefile" >> transfer.info
	echo "client.cpp" >> transfer.info

SERVER_PATH = ../server

server_transfer_info:
	echo "127.0.0.1:1234"  > $(SERVER_PATH)/transfer.info
	echo "Michael Jackson"     $(SERVER_PATH)/transfer.info



$(EXEC): $(OBJS)
	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

FILE_PATH = /home/dor/Documents/sec_mmn15/server

clean:
	rm -f $(OBJS) $(EXEC)

deepclean: clean
	rm -f *.db priv.key me.info logs.info defensive.db transfer.info
	rm -f $(FILE_PATH)/defensive.db $(FILE_PATH)/priv.key $(FILE_PATH)/me.info $(FILE_PATH)/logs.txt
