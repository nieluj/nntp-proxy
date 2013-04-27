UNAME_S := $(shell uname -s)

CC = gcc
CFLAGS = -g -c -Wall

ifneq ($(UNAME_S),Darwin)
  LDFLAGS = -lcrypt 
endif

SOURCES = nntp-proxy.c
OBJECTS = $(SOURCES:.c=.o)

EXECUTABLE = nntp-proxy

CFLAGS  += `pkg-config --cflags libevent_openssl openssl libconfig`
LDFLAGS += `pkg-config --libs libevent_openssl openssl libconfig`

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)

.PHONY : all clean
