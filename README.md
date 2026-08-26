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
| `replay_dict`      | string       | None      | Name of an `lua_shared_dict` in which to remember the assertions this instance has already accepted, so it accepts none of them twice. Unset leaves them untracked. See [Remembering assertions](#remembering-assertions) for what the zone has to hold and how far the guarantee reaches.       |
| `replay_ttl`      | number       | `600`      | Seconds to remember an assertion that names no `NotOnOrAfter` anywhere, on its `Conditions` or on any subject confirmation. One that names it is remembered until that moment plus `clock_skew`, capped at a day.       |

#### Binding a response to the request

An ID is minted for every `AuthnRequest` this SP sends and kept on the session as
`saml_request_id`. On the way back, a `SubjectConfirmationData` naming a different
request refuses the login, so an assertion captured from one login cannot be
presented in another. `Response/@InResponseTo` is weighed the same way,
though what it is worth depends on what the IdP signed: an IdP signing the whole
`Response` covers it, while one signing only the assertion, the common shape, leaves
it outside the signature, where the party replaying an assertion deletes it. Rely on
the copy inside the assertion, and read this one as catching a misdirected answer.

That guarantee is worth what the IdP sends. Profile 4.1.4.2 asks an IdP answering an
`AuthnRequest` to name it, and every mainstream IdP does, but an IdP that leaves
`InResponseTo` out, or sends no `SubjectConfirmation` at all, keeps working and gets
no binding. Refusing it would trade a working login for protection against another
party's misconfiguration, and no attacker can produce the shape: the value sits
inside the signature, so it cannot be stripped from a captured assertion.

One note for upgrading. A session minted before this SP kept the ID has nothing for
the assertion to name, so the login is started again rather than refused. The window
lasts as long as an `AuthnRequest` is outstanding across the upgrade.

#### Remembering assertions

Set `replay_dict` and every assertion this instance accepts is remembered until it
could no longer be used, so presenting the same one again is refused. Leave it unset
and assertions go untracked, which is what happened before the option existed.

**The guarantee is per instance.** An `lua_shared_dict` is shared between the workers
of one gateway and nowhere else, so a captured assertion replayed through a load
balancer lands on a replica that has never seen it and is accepted. Across replicas
the binding in [Binding a response to the request](#binding-a-response-to-the-request)
is what carries the weight, since it travels in the user's own session, and this
option is the defence for the deployments that binding leaves uncovered: the ones
whose IdP sends no `InResponseTo`.

**Size the zone for what it holds.** One entry per accepted login, held for the
assertion's remaining lifetime. An SP taking ten logins a second against an IdP
issuing ten-minute assertions holds around six thousand of them at once, so `1m` is
too small for that and a busy deployment wants more. A zone with no room leaves the
login untracked and logs an error naming it, rather than evicting an entry that is
still protecting somebody else.

**Two things it deliberately does not do.** An assertion carrying `<saml:OneTimeUse/>`
is still refused outright, so an IdP asking for exactly this protection cannot log in
even with the option on; that is tracked separately and the two do not meet yet. And
re-submitting a response that already logged in is refused, which is what a browser
does when it loses the redirect that ends a login. Returning to the application starts
a fresh login, and the IdP will not ask for a password again.

#### Seeding the worker

Request IDs and `RelayState` both come from `resty.jit-uuid`, which is seeded when
this module is first loaded, from the clock and the process ID. Loading `resty.saml`
from `init_by_lua` therefore seeds once in the master, and every worker forked after
it inherits that same sequence. Require this module from `init_worker_by_lua`, or
call `uuid.seed()` there yourself.

#### saml:authenticate()

**syntax:** *data = saml:authenticate()*
