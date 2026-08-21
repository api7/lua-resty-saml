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
| `idp_issuers`      | array of strings       | None      | Issuers accepted on a login response; every assertion it carries has to name one. Unset accepts any issuer the `idp_cert` signs for, which is not the same as an empty list: that one accepts nobody.       |
| `login_callback_uri`      | string       | None      | redirect uri used to callback the SP from IdP after login.       |
| `logout_uri`      | string       | None      | logout uri to trigger logout.       |
| `logout_callback_uri`      | string       | None      | redirect uri used to callback the SP from IdP after logout.       |
| `logout_redirect_uri`      | string       | None      | redirect uri after sucessful logout.       |
| `sp_cert`      | string       | None      | SP Certificate, used to sign the saml request.       |
| `sp_private_key`      | string       | None      | SP private key.       |
| `sp_acs_url`      | string       | built from the request       | Absolute URL of this SP's assertion consumer service. It is announced to the IdP, every `SubjectConfirmationData/@Recipient` has to name it, and a `Destination` has to name it on a response carrying one. Unset, it is assembled from the request's scheme and host, which is only as trustworthy as whatever sits in front: set it wherever the ingress does not normalise `Forwarded` and `X-Forwarded-*`, or terminates TLS without setting `X-Forwarded-Proto`.       |
| `sp_audiences`      | array of strings       | `{ sp_issuer }`      | Audiences this SP answers to. An assertion carrying an `AudienceRestriction` has to name one of them; an assertion carrying none is unrestricted.       |
| `clock_skew`      | number       | `60`      | Seconds of clock difference tolerated against the IdP when weighing `NotBefore` and `NotOnOrAfter`.       |

#### Binding a response to the request

An ID is minted for every `AuthnRequest` this SP sends and kept on the session as
`saml_request_id`. On the way back, a `SubjectConfirmationData` has to name that ID
in its `InResponseTo`, so an assertion captured from one login cannot be presented
in another. `Response/@InResponseTo` is weighed as well when it is there, though it
sits outside the signature, so it catches a misdirected answer rather than a
deliberate one.

Two consequences worth knowing before upgrading:

- An IdP that leaves `InResponseTo` off `SubjectConfirmationData` is refused. Profile
  4.1.4.2 requires the value of an IdP answering an `AuthnRequest`, and answering one
  is the only thing this SP ever asks for: a response arriving with no login in
  progress is refused whatever it carries.
- A session minted before this SP kept the ID has nothing for the assertion to name,
  so the login is started again rather than refused. The window lasts as long as an
  `AuthnRequest` is outstanding across the upgrade.

#### Seeding the worker

Request IDs and `RelayState` both come from `resty.jit-uuid`, which is seeded when
this module is first loaded, from the clock and the process ID. Loading `resty.saml`
from `init_by_lua` therefore seeds once in the master, and every worker forked after
it inherits that same sequence. Require this module from `init_worker_by_lua`, or
call `uuid.seed()` there yourself.

#### saml:authenticate()

**syntax:** *data = saml:authenticate()*
