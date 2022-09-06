INST_PREFIX ?= /usr
INST_LIBDIR ?= $(INST_PREFIX)/lib/lua/5.1
INST_LUADIR ?= $(INST_PREFIX)/share/lua/5.1
INSTALL ?= install

LUA_INCDIR=/usr/local/openresty/luajit/include/luajit-2.1/
LUAJIT_DIR=/usr/local/openresty/luajit
OPENSSL_DIR=/usr/local/openresty/openssl111

XMLSEC_VER=1.2.28

CC=gcc
CFLAGS_SAML=-g -fPIC -O2 -fcommon
XMLSEC1_CFLAGS=-D__XMLSEC_FUNCTION__=__func__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_GOST2012=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -Ixmlsec1-$(XMLSEC_VER)/include/ -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1
CFLAGS_ALL=$(CFLAGS_SAML) -Wall -Werror -std=c99 $(XMLSEC1_CFLAGS)
LIBFLAG=-shared
LDFLAGS=-g -O2
XMLSEC1_STATIC_LIBS=xmlsec1-$(XMLSEC_VER)/./src/openssl/.libs/libxmlsec1-openssl.a xmlsec1-$(XMLSEC_VER)/./src/.libs/libxmlsec1.a
XMLSEC1_LDFLAGS=-Wl,--whole-archive $(XMLSEC1_STATIC_LIBS) -Wl,--no-whole-archive -L$(OPENSSL_DIR)/lib/ -lxml2 -lssl -lcrypto -ldl -lxslt -Wl,-rpath $(OPENSSL_DIR)/lib
LDFLAGS_ALL=$(LIBFLAG) $(LDFLAGS) $(XMLSEC1_LDFLAGS)

### build:        build from source
.PHONY: build
build: $(XMLSEC1_STATIC_LIBS) saml.so

$(XMLSEC1_STATIC_LIBS):
	wget --no-check-certificate https://www.aleksey.com/xmlsec/download/older-releases/xmlsec1-$(XMLSEC_VER).tar.gz
	tar zxf xmlsec1-$(XMLSEC_VER).tar.gz
	cd xmlsec1-$(XMLSEC_VER); CFLAGS="-std=c99" ./configure --with-openssl=$(OPENSSL_DIR)/ --with-pic --disable-crypto-dl --disable-apps-crypto-dl; make

### test:         nginx test
.PHONY: test
test: build deps/
	prove -r t/

.PHONY: clean
clean:
	rm -rf *.so *.o xmlsec1-$(XMLSEC_VER)*

saml.o: src/*.c
	$(CC) -c $(CFLAGS_ALL) -o saml.o src/saml.c

lua_saml.o: src/lua_saml.c
	$(CC) -c $(CFLAGS_ALL) -I$(LUA_INCDIR) -Isrc/ -o $@ $<

saml.so: lua_saml.o saml.o
	$(CC) -o $@ $^ $(LDFLAGS_ALL)

### install:      Install the library to runtime
.PHONY: install
install:
	$(INSTALL) -d $(INST_LUADIR)/resty/
	$(INSTALL) lua/resty/*.lua $(INST_LUADIR)/resty/
	$(INSTALL) -d $(INST_LIBDIR)/
	$(INSTALL) saml.so $(INST_LIBDIR)/
	$(INSTALL) -d $(INST_LUADIR)/resty/saml/xsd/
	$(INSTALL) xsd/* $(INST_LUADIR)/resty/saml/xsd/

deps/:
	luarocks install --lua-dir=$(LUAJIT_DIR) rockspec/lua-resty-saml-main-0-0.rockspec --tree=deps --only-deps --local

### help:         Show Makefile rules
.PHONY: help
help:
	@echo Makefile rules:
	@echo
	@grep -E '^### [-A-Za-z0-9_]+:' Makefile | sed 's/###/   /'
