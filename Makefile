UNAME_S := $(shell uname -s)

CC = gcc
CFLAGS = -g -c -Wall

ifneq ($(UNAME_S),Darwin)
  LDFLAGS = -lcrypt 
endif

SOURCES = nntp-proxy.c
OBJECTS = $(SOURCES:.c=.o)

EXECUTABLE = nntp-proxy
EXECUTABLE_STATIC := $(EXECUTABLE)-static

INSTALL_DIR = /usr/local/bin

LDFLAGS_STATIC := $(LDFLAGS)

CFLAGS  += `pkg-config --cflags libevent_openssl openssl libconfig`
LDFLAGS += `pkg-config --libs libevent_openssl openssl libconfig`
LDFLAGS_STATIC += `pkg-config --static --libs libevent_openssl openssl libconfig`

all: $(SOURCES) $(EXECUTABLE)

static: $(EXECUTABLE_STATIC)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(EXECUTABLE_STATIC): $(OBJECTS)
	$(CC) $(OBJECTS) -static -o $@ $(LDFLAGS_STATIC)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

install: all
	/usr/bin/install -c -p -m 755 $(EXECUTABLE) $(INSTALL_DIR)

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) $(EXECUTABLE)-static

.PHONY : all static clean 
