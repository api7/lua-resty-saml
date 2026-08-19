use Test::Nginx::Socket::Lua;

log_level('info');
no_long_string();
repeat_each(1);
no_shuffle();
plan 'no_plan';

my $pwd = `pwd`;
chomp $pwd;

add_block_preprocessor(sub {
    my ($block) = @_;

    if ((!defined $block->error_log) && (!defined $block->no_error_log)) {
        $block->set_value("no_error_log", "[error]");
    }

    if (!defined $block->request) {
        $block->set_value("request", "GET /t");
    }

    my $main_config = $block->main_config // <<_EOC_;
    env SAML_DATA_DIR=./;
_EOC_

    $block->set_value("main_config", $main_config);

    my $http_config = $block->http_config // <<_EOC_;
    lua_package_path '$pwd/lua/?.lua;$pwd/deps/share/lua/5.1/?.lua;$pwd/t/?.lua;;';
    lua_package_cpath '$pwd/?.so;$pwd/deps/lib/lua/5.1/?.so;;';

    lua_shared_dict saml_replay 1m;

    init_by_lua_block {
        saml = require "saml"
        local err = saml.init({ debug = true, data_dir = os.getenv("SAML_DATA_DIR") })
        if err then assert(nil, err) end

        SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
        IDP = "https://idp.example.com"
        ACS = "http://127.0.0.1:1984/acs"
        BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

        KEY_PEM = [[-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDYYOJFazEru+eF
1bGFzH8xuC2clcWjnpIvXf5Jrseg7gfMh0nMM83OddLWB2Er+RWmVj361qaQR35p
JHGm3hFw20b2S+zBPxA6LCrHJ7vD/kOKEiDKxU3Ls5QK9+fTHFXIbpDtGAuISmmc
eWNaTZPIMdxPlpKYIyNJIUc2RxSREjsGlsrWWEtsroMjxpaHNNupadRUmkHXvZsC
EAsi3penjfZxG6v9R22tBwJxgj/ceXZwtTQJ7tuNtthv+kWP6/Q9owHW3uGL8Bin
46GRqAfHSGC64No+NwETF5iuephkIggtbvrlazTdPwu8Ddl8l4I1QfYmNxKPxnzJ
7pDwvBeRAgMBAAECggEAFkMTjKZcav48cg/cIaK6VGx5XuKm8LBcJHz0cHLHzbYn
vcKOlHChBFSpgkVEmWBZeqFlY5Upkm8Uoa8y9ULkQvsAiE8j9vbszbtlFFPxdNcI
bmBymMIngKWDfgRnCNiht8suZIJkj1tulb+EehJAuehtXQ/mGbqFwxymJb627jzk
MJ5bDsaVeBNu4gBQAp0USzreMO3AN9YxXmcJapZ5Bdc8avQzhzWRxNNJxtp6Uw56
cviuDxg7OJCaEHhUBFiDVu4O2HmrS/XdYUAwFcRO1hY/JfcaJ3DOHOl6y5eoRHwC
kMb8DhT/qECJ9rWc+APdUqiY1ag0Kq9BcRxkEGlcMQKBgQD32hzAPpuwW9Z0M9qd
x70PPkrJD8jgIprC92DHpHfztiZ2ctH3WxupH7UtZfI8tSVzh7WhWPPtrQ01ZcFh
ZPsFN74c7pWtW+JSm0pvDCQQG5qX9eJLna8GeI6f3hpM+u8pXr6p2ZQJGnjlGZfc
VNfJhvqCVH7hiG9fdAavsH1dKQKBgQDffeUD7x8I3ARbiZqDgANA9HqJi1ffhqFZ
xTWKLtr8NCPS8X+DvFrUDlGhBoDY7IGZhDhmBcb8/v7Kke3GT0/mff8GFsj9TUqh
fgzDxj5I/9HEjBKgpAG1J4B87QYZueLriMfX5Ff2wmCeqCwF4ftfjZVU9izyIa7B
hKYubQBMKQKBgQDslAk1h41cfYzqRkS6rllMH42K9cIsD1viFfcPGXJV8twr29WH
YjO470clGlZqlA43hKZeaGYNzEz7VzGLIbRpepfBTgsY+sfBSfF2pgQWTAL4Yf+r
ZcwXRSP+fSZlrHB08LbVsZWYSuhy5kcKTQHcnzanCLhD1tNYLYvkT3aaYQKBgQDK
c3nMuYUMenn8DceJTaIk6hJCnJZqZsOs1UdtuIooona9NITFag+BPsNVMdXwKzYv
QaXxTVR3g+p8x/pzhQ8lBYfKFUPWqXhsmAmqIt/zMsHr4NNS756YYoMzJ2c6ULgt
ksctW60PW/84WbEfVxll8pSO1T3bzQVISghbz+PQGQKBgQCEptD2bKHhF8RzRyfC
QXydnF7O6GEK3au3OKPb6BsLwJpTP2Wc1feTcg/lzCS5eUhNMxPv+4Ua7SLiF4li
vnI8SyPV2nGlsjna9maSkBq01YrLEMsPPSqw01Nf4W5jtUgk+jbZt9K3SrvTGzpJ
/2lpqvTIUUQTrTJNL6GZUBY1/Q==
-----END PRIVATE KEY-----]]

        CERT_PEM = [[-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUC9GZCQFhxDfguRhTjIcG/LxOZMQwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMB4XDTI2MDgxMDExMDkwNFoX
DTM2MDgwNzExMDkwNFowGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2GDiRWsxK7vnhdWxhcx/MbgtnJXF
o56SL13+Sa7HoO4HzIdJzDPNznXS1gdhK/kVplY9+tamkEd+aSRxpt4RcNtG9kvs
wT8QOiwqxye7w/5DihIgysVNy7OUCvfn0xxVyG6Q7RgLiEppnHljWk2TyDHcT5aS
mCMjSSFHNkcUkRI7BpbK1lhLbK6DI8aWhzTbqWnUVJpB172bAhALIt6Xp432cRur
/UdtrQcCcYI/3Hl2cLU0Ce7bjbbYb/pFj+v0PaMB1t7hi/AYp+OhkagHx0hguuDa
PjcBExeYrnqYZCIILW765Ws03T8LvA3ZfJeCNUH2JjcSj8Z8ye6Q8LwXkQIDAQAB
o1MwUTAdBgNVHQ4EFgQUlbLjSTfPYYltgF5anYLJxHTRS/owHwYDVR0jBBgwFoAU
lbLjSTfPYYltgF5anYLJxHTRS/owDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAjCv57yzpZMReoVJaZor6NGd5kcf8DfI2LLWJ4MGXzq/6kZLYy+Op
M1CxHA2wnxFmqcVmEra0zi2H2PkbM9p3oPK3upPdrL/ke2dIChP1yokaQoW9f2bY
K2INu9LIVuSD8hOUHDXPiH4Smt91V0GfrFHcxysfm97Y+TC+84grwcFE3JiRgfF+
WYG9w8xaCTTorUKUGum8/5beRd8qNCxVnh4Ke5vaRaUj28MbqLSQp1dvm0cqe+4d
kna+UpbWKQOQ8uAAtFIH+bX2uh8NbCBfATfwEMYzAffGKkmRkkoQHNv0Uf5uIduu
GnHKA3uj9HpsS6fAxHNPPvWxRjO67Xj8Yw==
-----END CERTIFICATE-----]]

        -- one SP per configuration under test, picked by request header
        OPTS = {
            plain = {},
            skew = { clock_skew = 300 },
            audiences = { sp_audiences = { "https://sp.example.com/metadata" } },
            acs = { sp_acs_url = "http://127.0.0.1:1984/acs" },
            replay = { replay_dict = "saml_replay" },
        }
        SPS = {}

        function sp(name)
            if SPS[name] == nil then
                local opts = {
                    sp_issuer = "sp",
                    idp_uri = "http://127.0.0.1:1984/idp",
                    login_callback_uri = "/acs",
                    logout_uri = "/logout",
                    logout_callback_uri = "/sls",
                    logout_redirect_uri = "/logout_ok",
                    sp_cert = CERT_PEM,
                    sp_private_key = KEY_PEM,
                    idp_cert = CERT_PEM,
                    secret = "very-secret-key-that-is-32-byte!",
                }
                for k, v in pairs(OPTS[name]) do opts[k] = v end
                SPS[name] = require("resty.saml").new(opts)
            end
            return SPS[name]
        end

        function sign_doc(xml)
            local key = assert(saml.key_read_memory(KEY_PEM, saml.KeyDataFormatPem))
            saml.key_add_cert_memory(key, CERT_PEM, saml.KeyDataFormatCertPem)
            local transform = saml.find_transform_by_href(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            local out = assert(saml.sign_xml(key, transform, xml,
                { id_attr = "ID", insert_after = { saml.XMLNS_ASSERTION, "Issuer" } }))
            return (out:gsub("<%?xml.-%?>%s*", ""))
        end

        -- an IdP timestamp this many seconds away from now
        function at(offset)
            return os.date("!%Y-%m-%dT%TZ", ngx.time() + offset)
        end

        function attr(name, value)
            if value == nil then return "" end
            return string.format(' %s="%s"', name, value)
        end

        function audience(...)
            local out = {}
            for _, name in ipairs({...}) do
                out[#out + 1] = "<saml:Audience>" .. name .. "</saml:Audience>"
            end
            return "<saml:AudienceRestriction>" .. table.concat(out) .. "</saml:AudienceRestriction>"
        end

        function conditions(spec)
            spec = spec or {}
            return string.format('<saml:Conditions%s%s>%s</saml:Conditions>',
                attr("NotBefore", spec.not_before), attr("NotOnOrAfter", spec.not_on_or_after),
                spec.body or "")
        end

        function confirmation(spec)
            spec = spec or {}
            local data = ""
            if spec.data ~= false then
                data = string.format('<saml:SubjectConfirmationData%s%s%s%s/>',
                    attr("Recipient", spec.recipient), attr("NotBefore", spec.not_before),
                    attr("NotOnOrAfter", spec.not_on_or_after),
                    attr("InResponseTo", spec.in_response_to))
            end
            return string.format('<saml:SubjectConfirmation Method="%s">%s</saml:SubjectConfirmation>',
                spec.method or BEARER, data)
        end

        -- Conditions follows Subject, the order the schema prescribes
        function assertion(spec)
            spec = spec or {}
            return string.format('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' ..
                'ID="%s" Version="2.0" IssueInstant="2026-07-21T00:00:00Z">' ..
                '<saml:Issuer>%s</saml:Issuer>' ..
                '<saml:Subject><saml:NameID>%s</saml:NameID>%s</saml:Subject>%s</saml:Assertion>',
                spec.id or "a1", IDP, spec.name_id or "signed\@example.com",
                spec.confirmations or "", spec.conditions or "")
        end

        function response(body, destination, in_response_to)
            return string.format('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-1" Version="2.0"%s%s ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>%s</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response>',
                attr("Destination", destination), attr("InResponseTo", in_response_to),
                IDP, SUCCESS, body)
        end

        -- only the assertion is signed, the shape an IdP sends by default
        function saml_response(spec, destination, in_response_to)
            return response(sign_doc(assertion(spec)), destination, in_response_to)
        end

        -- the ID of the AuthnRequest the SP just issued, read back out of the
        -- redirect it sent the browser
        function authn_request_id(location)
            local args = {}
            for k, v in location:gmatch("([^?&=]+)=([^&]*)") do
                args[k] = ngx.unescape_uri(v)
            end
            local cert = assert(saml.key_read_memory(CERT_PEM, saml.KeyDataFormatCertPem))
            local doc = assert(saml.binding_redirect_parse("SAMLRequest", args,
                function(_) return cert end))
            return saml.doc_id(doc)
        end

        function callback_headers(name, cookie, extra)
            local headers = {
                ["X-Test-SP"] = name,
                ["Cookie"] = cookie:match("^[^;]+"),
                ["Content-Type"] = "application/x-www-form-urlencoded",
            }
            for k, v in pairs(extra or {}) do headers[k] = v end
            return headers
        end

        -- start a login, then hand the crafted response back to the callback
        -- with the session and RelayState that login handed out
        function login_with(name, xml, extra)
            local httpc = require("resty.http").new()
            local base = "http://127.0.0.1:1984"
            local headers = { ["X-Test-SP"] = name }

            local res, err = httpc:request_uri(base .. "/", { headers = headers })
            if not res then return "login request: " .. err end
            local cookie = res.headers["Set-Cookie"]
            if type(cookie) == "table" then cookie = cookie[1] end
            local state = res.headers["Location"]:match("RelayState=([^&]+)")

            -- a response that has to name the request gets built once the SP
            -- has issued one
            if type(xml) == "function" then
                xml = xml(authn_request_id(res.headers["Location"]))
            end

            res, err = httpc:request_uri(base .. "/acs", {
                method = "POST",
                body = "SAMLResponse=" .. ngx.escape_uri(saml.base64_encode(xml)) ..
                    "&RelayState=" .. state,
                headers = callback_headers(name, cookie, extra),
            })
            if not res then return "callback request: " .. err end
            return res.status .. " " .. tostring(res.headers["Location"])
        end

        function parse(xml)
            local key = assert(saml.key_read_memory(CERT_PEM, saml.KeyDataFormatCertPem))
            local mngr = assert(saml.create_keys_manager({ key }))
            saml.key_add_ca_memory(mngr, CERT_PEM)
            return saml.binding_post_parse(saml.base64_encode(xml), function(_) return mngr end)
        end
    }

    server {
        listen 1984;

        location / {
            access_by_lua_block {
                sp(ngx.var.http_x_test_sp or "plain"):authenticate()
            }

            content_by_lua_block {
                ngx.exit(200)
            }
        }
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

run_tests();

__DATA__

=== TEST 1: an assertion inside its validity window is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_before = at(-60), not_on_or_after = at(600) }),
            })))
        }
    }
--- response_body
302 /


=== TEST 2: an expired assertion is refused however it is replayed
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_before = at(-7200), not_on_or_after = at(-3600) }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
is not valid on or after


=== TEST 3: an assertion whose window has not opened is refused
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_before = at(3600), not_on_or_after = at(7200) }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
is not valid before


=== TEST 4: the clock skew allowance covers a small difference with the IdP
--- config
    location /t {
        content_by_lua_block {
            local spec = { conditions = conditions({ not_on_or_after = at(-120) }) }
            ngx.say(login_with("plain", saml_response(spec)))
            ngx.say(login_with("skew", saml_response(spec)))
        }
    }
--- response_body
401 nil
302 /
--- error_log
is not valid on or after


=== TEST 5: an assertion restricted to another SP is refused
--- config
    location /t {
        content_by_lua_block {
            -- what an IdP serving a federation mints for a different SP
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ body = audience("https://other.example.com") }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
is restricted to https://other.example.com


=== TEST 6: an assertion restricted to this SP is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ body = audience("https://other.example.com", "sp") }),
            })))
        }
    }
--- response_body
302 /


=== TEST 7: sp_audiences names the audience the IdP was configured with
--- config
    location /t {
        content_by_lua_block {
            local spec = {
                conditions = conditions({ body = audience("https://sp.example.com/metadata") }),
            }
            ngx.say(login_with("plain", saml_response(spec)))
            ngx.say(login_with("audiences", saml_response(spec)))
        }
    }
--- response_body
401 nil
302 /
--- error_log
is restricted to https://sp.example.com/metadata


=== TEST 8: each AudienceRestriction narrows the audience on its own
--- config
    location /t {
        content_by_lua_block {
            -- named in the first restriction, left out of the second
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({
                    body = audience("sp") .. audience("https://other.example.com"),
                }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
is restricted to https://other.example.com


=== TEST 9: a confirmation addressed to another endpoint is refused
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = "http://evil.example.com/acs" }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
offers no subject confirmation this SP can satisfy


=== TEST 10: a confirmation addressed here and still open is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = ACS, not_on_or_after = at(300) }),
            })))
        }
    }
--- response_body
302 /


=== TEST 11: a confirmation that has run out is refused
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = ACS, not_on_or_after = at(-3600) }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
offers no subject confirmation this SP can satisfy


=== TEST 12: one satisfiable confirmation among several is enough
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = "http://evil.example.com/acs" }) ..
                    confirmation({ recipient = ACS, not_on_or_after = at(300) }),
            })))
        }
    }
--- response_body
302 /


=== TEST 13: a condition this SP cannot satisfy leaves the assertion indeterminate
--- config
    location /t {
        content_by_lua_block {
            -- ProxyRestriction binds the IdP, not this SP, so it is satisfied
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ body = "<saml:ProxyRestriction Count=\"1\"/>" }),
            })))
            -- OneTimeUse asks this SP to remember which assertions it has spent
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ body = "<saml:OneTimeUse/>" }),
            })))
            -- and a condition it has never heard of asks who knows what
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({
                    body = '<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' ..
                        'xsi:type="saml:AudienceRestrictionType"><saml:Audience>sp</saml:Audience></saml:Condition>',
                }),
            })))
        }
    }
--- response_body
302 /
401 nil
401 nil
--- error_log eval
[qr/carries a condition this SP cannot satisfy: OneTimeUse/,
qr/carries a condition this SP cannot satisfy: Condition/]


=== TEST 14: a response addressed to another endpoint is refused
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({}, "http://evil.example.com/acs")))
            ngx.say(login_with("plain", saml_response({}, ACS)))
        }
    }
--- response_body
401 nil
302 /
--- error_log
response from IdP is addressed to http://evil.example.com/acs


=== TEST 15: an assertion carrying no constraints is still accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({})))
        }
    }
--- response_body
302 /


=== TEST 16: the constraints are reported per assertion, not pooled
--- config
    location /t {
        content_by_lua_block {
            local xml = sign_doc(response(
                assertion({ id = "a1", conditions = conditions({ not_on_or_after = "2026-07-21T00:00:00Z",
                    body = audience("sp") }) }) ..
                assertion({ id = "a2", name_id = "second@example.com",
                    confirmations = confirmation({ recipient = ACS }) })))
            local doc, err = parse(xml)
            if err then ngx.say("err: ", err) return end

            for _, a in ipairs(saml.doc_assertions(doc)) do
                ngx.say(a.id, " conditions=", tostring(a.has_conditions),
                    " expires=", tostring(a.not_on_or_after),
                    " audiences=", #a.audience_restrictions,
                    " confirmations=", #a.subject_confirmations)
            end
            ngx.say("destination: ", tostring(saml.doc_destination(doc)))
        }
    }
--- response_body
a1 conditions=true expires=2026-07-21T00:00:00Z audiences=1 confirmations=0
a2 conditions=false expires=nil audiences=0 confirmations=1
destination: nil


=== TEST 17: a UTC timestamp is read as UTC whatever the machine's timezone is
--- config
    location /t {
        content_by_lua_block {
            -- an assertion good for another hour, with the worker fourteen
            -- hours ahead of UTC: read as local time it would already have run
            -- out
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_before = at(-60), not_on_or_after = at(3600) }),
            })))
        }
    }
--- main_config
env SAML_DATA_DIR=./;
env TZ=XXX-14;
--- response_body
302 /


=== TEST 18: a configured ACS URL settles what the endpoint checks compare against
--- config
    location /t {
        content_by_lua_block {
            local elsewhere = saml_response({
                confirmations = confirmation({ recipient = "https://sp.example.com/acs" }),
            })
            local here = saml_response({ confirmations = confirmation({ recipient = ACS }) })
            local forged = {
                ["X-Forwarded-Proto"] = "https",
                ["X-Forwarded-Host"] = "sp.example.com",
            }

            -- assembled from the request, the endpoint moves with the headers
            ngx.say(login_with("plain", elsewhere, forged))
            -- configured, it stays where the deployment put it
            ngx.say(login_with("acs", elsewhere, forged))
            -- and headers that disagree cannot refuse an assertion that names it
            ngx.say(login_with("acs", here, forged))
        }
    }
--- response_body
302 /
401 nil
302 /
--- error_log
offers no subject confirmation this SP can satisfy


=== TEST 19: an audience with no text leaves the rest of its restriction readable
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ body = "<saml:AudienceRestriction>" ..
                    "<saml:Audience/><saml:Audience>sp</saml:Audience>" ..
                    "</saml:AudienceRestriction>" }),
            })))
        }
    }
--- response_body
302 /


=== TEST 20: a response answering another request is refused
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", saml_response({}, nil, "ID_some-other-request")))
        }
    }
--- response_body
401 nil
--- error_log
response from IdP answers request ID_some-other-request


=== TEST 21: a confirmation answering another request is refused
--- config
    location /t {
        content_by_lua_block {
            -- inside the signature, so this is the binding an attacker replaying
            -- a captured assertion cannot rewrite
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = ACS, in_response_to = "ID_some-other-request" }),
            })))
        }
    }
--- response_body
401 nil
--- error_log
offers no subject confirmation this SP can satisfy


=== TEST 22: a response answering this SP's own request is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("plain", function(request_id)
                return saml_response({
                    confirmations = confirmation({ recipient = ACS, in_response_to = request_id }),
                }, ACS, request_id)
            end))
        }
    }
--- response_body
302 /


=== TEST 23: an assertion is good for one login
--- config
    location /t {
        content_by_lua_block {
            local xml = saml_response({ conditions = conditions({ not_on_or_after = at(600) }) })
            ngx.say(login_with("replay", xml))
            ngx.say(login_with("replay", xml))
        }
    }
--- response_body
302 /
401 nil
--- error_log
assertion a1 has been presented already


=== TEST 24: a second assertion of its own is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("replay", saml_response({ id = "a1" })))
            ngx.say(login_with("replay", saml_response({ id = "a2" })))
        }
    }
--- response_body
302 /
302 /


=== TEST 25: an assertion is remembered for as long as it is usable
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("replay", saml_response({
                conditions = conditions({ not_on_or_after = at(600) }),
            })))
            -- the window plus the skew allowance, which is when it stops being
            -- accepted and so stops being worth remembering
            local ttl = ngx.shared.saml_replay:ttl("sp|a1")
            ngx.say("tracked: ", ttl > 600 and ttl <= 660)

            ngx.say(login_with("replay", saml_response({ id = "a2" })))
            local default = ngx.shared.saml_replay:ttl("sp|a2")
            ngx.say("default: ", default > 590 and default <= 600)
        }
    }
--- response_body
302 /
tracked: true
302 /
default: true
