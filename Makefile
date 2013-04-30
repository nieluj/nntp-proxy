UNAME_S := $(shell uname -s)

CC = gcc
CFLAGS = -g -c -Wall

ifneq ($(UNAME_S),Darwin)
  LDFLAGS = -lcrypt 
endif

SOURCES = nntp-proxy.c
OBJECTS = $(SOURCES:.c=.o)

EXECUTABLE = nntp-proxy

INSTALL_DIR = /usr/local/bin

CFLAGS  += `pkg-config --cflags libevent_openssl openssl libconfig`
LDFLAGS += `pkg-config --libs libevent_openssl openssl libconfig`

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

install: all
	/usr/bin/install -c -p -m 755 $(EXECUTABLE) $(INSTALL_DIR)

clean:
	rm $(OBJECTS) $(EXECUTABLE)

.PHONY : all clean
