INST_PREFIX ?= /usr
INST_LIBDIR ?= $(INST_PREFIX)/lib/lua/5.1
INST_LUADIR ?= $(INST_PREFIX)/share/lua/5.1
INSTALL ?= install

LUA_INCDIR=/usr/local/openresty/luajit/include/luajit-2.1/
LUAJIT_DIR=/usr/local/openresty/luajit

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

.PHONY: test
test: build deps
	prove -r t/

.PHONY: clean
clean:
	rm -f *.so *.o

saml.o: src/*.c
	$(CC) -c $(CFLAGS_ALL) -o saml.o src/saml.c

lua_saml.o: src/lua_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(LUA_INCDIR) -Isrc/ -o $@ $<

saml.so: lua_saml.o saml.o
	$(CC) -o $@ $^ $(LDFLAGS_ALL)

.PHONY: install
install:
	$(INSTALL) -d $(INST_LUADIR)/resty/
	$(INSTALL) lua/resty/*.lua $(INST_LUADIR)/resty/
	$(INSTALL) -d $(INST_LIBDIR)/
	$(INSTALL) saml.so $(INST_LIBDIR)/
	$(INSTALL) -d $(INST_LUADIR)/resty/saml/xsd/
	$(INSTALL) xsd/* $(INST_LUADIR)/resty/saml/xsd/
	$(INSTALL) t/lib/keycloak.lua $(INST_LUADIR)/resty/saml/

.PHONY: deps
deps:
	luarocks install --lua-dir=$(LUAJIT_DIR) rockspec/lua-resty-saml-main-0-0.rockspec --tree=deps --only-deps --local
