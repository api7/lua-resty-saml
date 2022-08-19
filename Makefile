VERSION=0.1

# Default locations
LUA_INCDIR=/usr/local/openresty/luajit/include/luajit-2.1/

CC=gcc
CFLAGS=-g -fPIC -O2
XMLSEC1_CFLAGS=$(shell xmlsec1-config --cflags --crypto=openssl)
CFLAGS_ALL=$(CFLAGS) -Wall -Werror -std=c99 $(XMLSEC1_CFLAGS)
LIBFLAG=-shared
LDFLAGS=-g -O2
XMLSEC1_LDFLAGS=$(shell xmlsec1-config --libs --crypto=openssl)
LDFLAGS_ALL=$(LIBFLAG) $(LDFLAGS) $(XMLSEC1_LDFLAGS)

.PHONY: build
build: saml.so

.PHONY: clean
clean:
	rm -f *.so *.o

saml.o: src/*.c
	$(CC) -c $(CFLAGS_ALL) -o saml.o src/saml.c

src/saml.o:
	$(MAKE) -C src saml.o

lua_saml.o: src/lua_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(LUA_INCDIR) -Isrc/ -o $@ $<

saml.so: lua_saml.o saml.o
	$(CC) -o $@ $^ $(LDFLAGS_ALL)
