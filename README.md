lua-resty-saml: SAML auth lib
===========================================

Access SAML (Security Assertion Markup Language 2.0) IdP (Identity Provider) to do authentication via cosocket, from the SP (service provider) perspective.

This project is based on [player-two/saml](https://github.com/player-two/saml).

**Supported Protocols:**

* Authentication Request Protocol
* Single Logout Protocol

**Bindings:**

* HTTP Redirect Binding
* HTTP POST Binding

**Features not supported:**

* SAML encryption
* IdP discovery
* Back-channel logout

Installation
------------

The preferred way to install this library is to use Luarocks:

    luarocks install lua-resty-saml

Usage
-----

### Synopsis

```lua
local resty_saml = require "resty.saml"
local opts = {
    sp_issuer = "sp",
    idp_uri = "http://127.0.0.1:8080/realms/test/protocol/saml",
    idp_cert = "xxx",
    login_callback_uri = "/acs",
    logout_uri = "/logout",
    logout_callback_uri = "/sls",
    logout_redirect_uri = "/",
    sp_cert = "xxx",
    sp_private_key = "xxx",
}

local saml = resty_saml.new(opts)
local data = saml:authenticate()
```

### API

#### resty.saml
To load this module:

```
local resty_saml = require "resty.saml"
```

#### saml object

```
local saml = resty_saml.new(opts)
```

`opts` is a table of below items:

| key      | type | default value      | Description |
| ----------- | ----------- | ----------- | ----------- |
| `sp_issuer`      | string       | None      | SP name to access IdP.       |
| `idp_uri`      | string       | None      | URI of IdP.       |
| `idp_cert`      | string       | None      | IdP Certificate, used to verify saml response.       |
| `login_callback_uri`      | string       | None      | redirect uri used to callback the SP from IdP after login.       |
| `logout_uri`      | string       | None      | logout uri to trigger logout.       |
| `logout_callback_uri`      | string       | None      | redirect uri used to callback the SP from IdP after logout.       |
| `logout_redirect_uri`      | string       | None      | redirect uri after sucessful logout.       |
| `sp_cert`      | string       | None      | SP Certificate, used to sign the saml request.       |
| `sp_private_key`      | string       | None      | SP private key.       |

#### saml:authenticate()

**syntax:** *data = saml:authenticate()*
