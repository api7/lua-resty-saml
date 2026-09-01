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
    } elsif (!defined $block->no_error_log) {
        # a block naming the error it expects gets no other assertion about the
        # log, so a block that also drives a success asserts nothing about that
        # half. This is the part of it that can be said generically.
        $block->set_value("no_error_log", "[crit]\n[alert]\n[emerg]");
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
    large_client_header_buffers 4 64k;
    client_max_body_size 1m;
    client_body_buffer_size 128k;

    # a zone of the same name and size is reused across a reload, so entries
    # outlive the block that made them under TEST_NGINX_USE_HUP=1. Blocks name
    # their own assertions to stay apart, and flush as well
    lua_shared_dict saml_replay 1m;
    lua_shared_dict saml_replay_full 32k;

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
            replay_short = { replay_dict = "saml_replay", replay_ttl = 90 },
            replay_long = { replay_dict = "saml_replay", replay_ttl = 172800 },
            replay_full = { replay_dict = "saml_replay_full" },
            replay_pinned = {
                replay_dict = "saml_replay",
                idp_issuers = { "https://elsewhere.example.com" },
            },
            save_fails_start = {},
            save_fails_replay = { replay_dict = "saml_replay" },
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
                if name == "save_fails_start" or name == "save_fails_replay" then
                    SPS[name].session_config.compression_threshold = 0
                end
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

        function authn_statement(session_expires)
            if session_expires == nil then
                return ""
            end
            return string.format('<saml:AuthnStatement AuthnInstant="2026-07-21T00:00:00Z"%s>' ..
                '<saml:AuthnContext><saml:AuthnContextClassRef>' ..
                'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' ..
                '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>',
                attr("SessionNotOnOrAfter", session_expires))
        end

        -- Subject, then Conditions, then the statements, the order the schema
        -- prescribes
        function assertion(spec)
            spec = spec or {}
            return string.format('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' ..
                'ID="%s" Version="2.0" IssueInstant="2026-07-21T00:00:00Z">' ..
                '<saml:Issuer>%s</saml:Issuer>' ..
                '<saml:Subject><saml:NameID>%s</saml:NameID>%s</saml:Subject>%s%s</saml:Assertion>',
                spec.id or "a1", spec.issuer or IDP, spec.name_id or "signed\@example.com",
                spec.confirmations or "", spec.conditions or "",
                authn_statement(spec.session_expires) .. (spec.attributes or ""))
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

        -- the module owns this layout; naming it once here keeps a change to
        -- the scheme from surfacing as a comparison against nil
        -- fill a zone to refusal, so the next safe_add answers no memory.
        -- Hands back whether it truly got there, for the block to assert
        function fill_dict(name)
            local dict = ngx.shared[name]
            dict:flush_all()
            dict:flush_expired()
            local filler = string.rep("x", 256)
            local i, ok, err = 0, true, nil
            while ok do
                ok, err = dict:safe_set("filler-" .. i, filler, 600)
                if ok then i = i + 1 end
                if i > 5000 then break end
            end
            local j = 0
            while dict:safe_add("small-" .. j, true, 600) do
                j = j + 1
                if j > 5000 then break end
            end
            return i > 0 and j > 0 and err == "no memory"
        end

        function replay_key(id, issuer)
            return "sp|" .. (issuer or IDP) .. "|" .. id
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

        function login_start_with_large_uri()
            local bits = {}
            for i = 1, 1200 do bits[i] = ngx.md5(i) end
            local res = assert(require("resty.http").new():request_uri(
                "http://127.0.0.1:1984/?q=" .. table.concat(bits), {
                    headers = { ["X-Test-SP"] = "save_fails_start" },
                }))
            return res.status
        end

        -- hand a response to a session the old code would have left behind
        function login_with_legacy(name, xml)
            local httpc = require("resty.http").new()
            local base = "http://127.0.0.1:1984"

            local res = assert(httpc:request_uri(base .. "/legacy", {
                headers = { ["X-Test-SP"] = name },
            }))
            local cookie = res.headers["Set-Cookie"]
            if type(cookie) == "table" then cookie = cookie[1] end

            res = assert(httpc:request_uri(base .. "/acs", {
                method = "POST",
                body = "SAMLResponse=" .. ngx.escape_uri(saml.base64_encode(xml)) ..
                    "&RelayState=legacy-state",
                headers = callback_headers(name, cookie),
            }))
            return res.status .. " " .. (res.headers["Location"] or ""):match("^[^?]*")
        end

        -- log in, then ask the app again carrying the session the callback
        -- handed out: a live session answers 200, an expired one starts over
        function session_after_login(name, xml)
            local httpc = require("resty.http").new()
            local base = "http://127.0.0.1:1984"
            local headers = { ["X-Test-SP"] = name }

            local res = assert(httpc:request_uri(base .. "/", { headers = headers }))
            local cookie = res.headers["Set-Cookie"]
            if type(cookie) == "table" then cookie = cookie[1] end
            local state = res.headers["Location"]:match("RelayState=([^&]+)")

            res = assert(httpc:request_uri(base .. "/acs", {
                method = "POST",
                body = "SAMLResponse=" .. ngx.escape_uri(saml.base64_encode(xml)) ..
                    "&RelayState=" .. state,
                headers = callback_headers(name, cookie),
            }))
            if res.status ~= 302 then return "callback: " .. res.status end

            local rotated = res.headers["Set-Cookie"]
            if type(rotated) == "table" then rotated = rotated[1] end
            if rotated then cookie = rotated end

            res = assert(httpc:request_uri(base .. "/", {
                headers = { ["X-Test-SP"] = name, ["Cookie"] = cookie:match("^[^;]+") },
            }))
            return res.status
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

        # a login in progress with no record of the request that started it,
        # the shape a session minted before the binding existed has
        location /legacy {
            content_by_lua_block {
                local name = ngx.var.http_x_test_sp or "plain"
                local sess = require("resty.session").start(sp(name).session_config)
                sess:set("saml_state", "legacy-state")
                sess:set("request_uri", "/")
                sess:save()
                ngx.exit(200)
            }
        }

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
            -- OneTimeUse is always valid (Core 2.5.1.5); with no replay_dict it
            -- asks for a record this SP does not keep, which is said, not refused
            ngx.say(login_with("plain", saml_response({
                id = "single", conditions = conditions({ body = "<saml:OneTimeUse/>" }),
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
302 /
401 nil
--- error_log eval
[qr/\[warn\] .* assertion single from https:\/\/idp\.example\.com carries OneTimeUse, which this SP cannot enforce without replay_dict/,
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
--- no_error_log
[error]
cannot enforce without replay_dict



=== TEST 16: the constraints are reported per assertion, not pooled
--- config
    location /t {
        content_by_lua_block {
            local xml = sign_doc(response(
                assertion({ id = "a1", conditions = conditions({ not_on_or_after = "2026-07-21T00:00:00Z",
                    body = audience("sp") .. "<saml:OneTimeUse/>" }) }) ..
                assertion({ id = "a2", name_id = "second@example.com",
                    confirmations = confirmation({ recipient = ACS }) })))
            local doc, err = parse(xml)
            if err then ngx.say("err: ", err) return end

            for _, a in ipairs(saml.doc_assertions(doc)) do
                ngx.say(a.id, " conditions=", tostring(a.has_conditions),
                    " expires=", tostring(a.not_on_or_after),
                    " audiences=", #a.audience_restrictions,
                    " confirmations=", #a.subject_confirmations,
                    " one_time_use=", tostring(a.one_time_use))
            end
            ngx.say("destination: ", tostring(saml.doc_destination(doc)))
        }
    }
--- response_body
a1 conditions=true expires=2026-07-21T00:00:00Z audiences=1 confirmations=0 one_time_use=true
a2 conditions=false expires=nil audiences=0 confirmations=1 one_time_use=false
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

            -- the same value settles Destination, which is read on a response
            -- carrying no confirmation to weigh
            local addressed = saml_response({}, "https://sp.example.com/acs")
            ngx.say(login_with("plain", addressed, forged))
            ngx.say(login_with("acs", addressed, forged))
        }
    }
--- response_body
302 /
401 nil
302 /
302 /
401 nil
--- error_log eval
[qr/offers no subject confirmation this SP can satisfy/,
qr{addressed to https://sp\.example\.com/acs}]



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



=== TEST 20: a confirmation that states nothing confirms nothing
--- config
    location /t {
        content_by_lua_block {
            local elsewhere = confirmation({ recipient = "https://evil.example.com/acs" })

            -- no SubjectConfirmationData at all
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ data = false }),
            })))
            -- the element written out with nothing in it, which the schema
            -- allows since every attribute on it is optional
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({}),
            })))
            -- and neither spelling may answer in place of a sibling that binds
            -- the assertion somewhere else
            ngx.say(login_with("plain", saml_response({
                confirmations = elsewhere .. confirmation({ data = false }),
            })))
            ngx.say(login_with("plain", saml_response({
                confirmations = elsewhere .. confirmation({}),
            })))
            -- nor may one carrying only a condition that happens to hold
            ngx.say(login_with("plain", saml_response({
                confirmations = elsewhere .. confirmation({ not_before = at(-600) }),
            })))
        }
    }
--- response_body
401 nil
401 nil
401 nil
401 nil
401 nil
--- error_log
offers no subject confirmation this SP can satisfy



=== TEST 21: session lifetime follows the IdP's clock, not the machine's
--- config
    location /t {
        content_by_lua_block {
            -- ten minutes of session left, with the worker fourteen hours
            -- ahead of UTC: read as local time it would already be spent
            ngx.say(session_after_login("plain", saml_response({ session_expires = at(600) })))
            -- and ten minutes past, which is spent either way
            ngx.say(session_after_login("plain", saml_response({ session_expires = at(-600) })))
        }
    }
--- main_config
env SAML_DATA_DIR=./;
env TZ=XXX-14;
--- response_body
200
302



=== TEST 22: a newline smuggled into the response cannot split a log line
--- config
    location /t {
        content_by_lua_block {
            -- Destination rides the unsigned wrapper, so it is the sender's to
            -- write, and a character reference is not folded to a space the way
            -- a literal newline would be
            ngx.say(login_with("plain", saml_response({}, "https://x&#10;WARNING-forged-entry")))
        }
    }
--- response_body
401 nil
--- error_log
addressed to https://x\x0AWARNING-forged-entry



=== TEST 23: a year the parser cannot hold is refused, not read from part way in
--- config
    location /t {
        content_by_lua_block {
            -- 9999 BCE, which the schema accepts: unanchored, the match starts
            -- after the minus and reads a far-future 9999 CE out of an
            -- already-expired bound
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_on_or_after = "-9999-01-01T00:00:00Z" }),
            })))
            -- five digits, where the match can start one character in
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_on_or_after = "20260-01-01T00:00:00Z" }),
            })))
            -- a fractional second is still read
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_on_or_after = (at(600):gsub("Z", ".500Z")) }),
            })))
        }
    }
--- response_body
401 nil
401 nil
302 /
--- error_log
carries an unreadable NotOnOrAfter -9999-01-01T00:00:00Z



=== TEST 24: an unreadable session expiry is an error, not a 200 carrying one
--- config
    location /t {
        content_by_lua_block {
            local httpc = require("resty.http").new()
            local base = "http://127.0.0.1:1984"

            local res = assert(httpc:request_uri(base .. "/", { headers = { ["X-Test-SP"] = "plain" } }))
            local cookie = res.headers["Set-Cookie"]
            if type(cookie) == "table" then cookie = cookie[1] end
            local state = res.headers["Location"]:match("RelayState=([^&]+)")

            -- schema-valid xs:dateTime this parser will not read: a numeric
            -- offset where SAML requires Z
            local xml = saml_response({ session_expires = "2030-01-01T00:00:00+00:00" })
            res = assert(httpc:request_uri(base .. "/acs", {
                method = "POST",
                body = "SAMLResponse=" .. ngx.escape_uri(saml.base64_encode(xml)) ..
                    "&RelayState=" .. state,
                headers = callback_headers("plain", cookie),
            }))
            -- the status the branch always meant to send, and the parse
            -- error kept out of the body it used to be written into
            ngx.say(res.status, " leaks=",
                tostring(((res.body or ""):find("UTC time", 1, true)) ~= nil))
        }
    }
--- response_body
500 leaks=false
--- error_log
unreadable SessionNotOnOrAfter 2030-01-01T00:00:00+00:00



=== TEST 25: a window that opens after it closes is empty on every clock
--- config
    location /t {
        content_by_lua_block {
            -- inverted by less than twice the skew allowance, so each end taken
            -- on its own still looks acceptable
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_before = at(30), not_on_or_after = at(-30) }),
            })))
            -- the same shape on a subject confirmation, which shares the check
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = ACS,
                    not_before = at(30), not_on_or_after = at(-30) }),
            })))
            -- both ends inside one second still reads as open, since the
            -- fractional part is truncated away before they are compared
            ngx.say(login_with("plain", saml_response({
                conditions = conditions({ not_before = at(0), not_on_or_after = at(0) }),
            })))
        }
    }
--- response_body
401 nil
401 nil
302 /
--- error_log eval
[qr/opens at .* and closes at /,
qr/offers no subject confirmation this SP can satisfy/]



=== TEST 26: a document type declaration is refused, whatever it declares
--- config
    location /t {
        content_by_lua_block {
            -- an ATTLIST default answers every reader that asks the node for an
            -- attribute, without ever being written onto the node, and
            -- canonicalisation drops the prologue before anything is hashed. So
            -- this invents a Recipient inside signed content while leaving every
            -- signature intact, whichever scope it covers
            local doctype = '<!DOCTYPE samlp:Response [<!ATTLIST saml:SubjectConfirmationData ' ..
                'Recipient CDATA "http://127.0.0.1:1984/acs">]>'
            local body = assertion({ confirmations = confirmation({}) })

            ngx.say(login_with("plain", doctype .. response(sign_doc(body))))
            ngx.say(login_with("plain", doctype .. sign_doc(response(body))))
            -- and the same documents without the prologue, which carry no
            -- Recipient of their own
            ngx.say(login_with("plain", response(sign_doc(body))))
        }
    }
--- response_body
400 nil
400 nil
401 nil
--- error_log eval
[qr/parse post from IdP: document carries a document type declaration/,
qr/offers no subject confirmation this SP can satisfy/]


=== TEST 27: a response answering another request is refused
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


=== TEST 28: a confirmation answering another request is refused
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


=== TEST 29: a response answering this SP's own request is accepted
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


=== TEST 30: a confirmation naming no request keeps working
--- config
    location /t {
        content_by_lua_block {
            -- naming one is what the profile asks of an IdP answering a
            -- request, so an IdP that leaves it out is already out of spec.
            -- The binding is worth what that IdP sends and no more.
            ngx.say(login_with("plain", saml_response({
                confirmations = confirmation({ recipient = ACS }),
            })))
        }
    }
--- response_body
302 /


=== TEST 31: a session minted before the binding starts the login again
--- config
    location /t {
        content_by_lua_block {
            -- nothing to compare the assertion against, and the login is
            -- genuinely this user's, so send them back to the IdP for one
            -- that is remembered
            ngx.say(login_with_legacy("plain", saml_response({
                confirmations = confirmation({ recipient = ACS, in_response_to = "ID_earlier" }),
            })))
        }
    }
--- response_body
302 http://127.0.0.1:1984/idp
--- error_log
session carries no request id, starting the login again


=== TEST 32: an assertion is good for one login
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            local xml = saml_response({
                id = "once", conditions = conditions({ not_on_or_after = at(600) }),
            })
            ngx.say(login_with("replay", xml))
            ngx.say(login_with("replay", xml))
        }
    }
--- response_body
302 /
401 nil
--- error_log
assertion once has been presented already


=== TEST 33: a second assertion of its own is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            ngx.say(login_with("replay", saml_response({ id = "first" })))
            ngx.say(login_with("replay", saml_response({ id = "second" })))
        }
    }
--- response_body
302 /
302 /


=== TEST 34: an assertion is remembered for as long as it is usable
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            ngx.say(login_with("replay", saml_response({
                id = "bounded", conditions = conditions({ not_on_or_after = at(600) }),
            })))
            -- the window plus the skew allowance, which is when it stops being
            -- accepted and so stops being worth remembering
            local ttl = ngx.shared.saml_replay:ttl(replay_key("bounded"))
            ngx.say("tracked: ", ttl > 600 and ttl <= 660)
        }
    }
--- response_body
302 /
tracked: true


=== TEST 35: two IdPs may mint the same assertion ID
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- an ID is unique only within the IdP that issued it, so sharing
            -- one is not a replay
            ngx.say(login_with("replay", saml_response({ id = "shared" })))
            ngx.say(login_with("replay", saml_response({
                id = "shared", issuer = "https://second-idp.example.com",
            })))
        }
    }
--- response_body
302 /
302 /


=== TEST 36: an expiry the IdP puts on the confirmation decides it too
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- profile 4.1.4.2 puts a bearer assertion's expiry here, so a
            -- Conditions naming only an audience is the ordinary shape. Reading
            -- only Conditions forgot the assertion while it was still accepted.
            ngx.say(login_with("replay", function(request_id)
                return saml_response({
                    id = "on-confirmation",
                    conditions = conditions({ body = audience("sp") }),
                    confirmations = confirmation({
                        recipient = ACS, not_on_or_after = at(3600),
                        in_response_to = request_id,
                    }),
                }, ACS, request_id)
            end))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("on-confirmation"))
            ngx.say("tracked: ", ttl > 3600 and ttl <= 3660)
        }
    }
--- response_body
302 /
tracked: true


=== TEST 37: an assertion naming no expiry falls back to replay_ttl
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- nothing bounds it, so it is replayable once the record lapses.
            -- That is what replay_ttl is for and the README says so.
            ngx.say(login_with("replay", saml_response({ id = "unbounded" })))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("unbounded"))
            ngx.say("default: ", ttl > 590 and ttl <= 600)
        }
    }
--- response_body
302 /
default: true


=== TEST 38: replay_ttl settles that fallback
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            ngx.say(login_with("replay_short", saml_response({ id = "configured" })))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("configured"))
            ngx.say("configured: ", ttl > 80 and ttl <= 90)
        }
    }
--- response_body
302 /
configured: true


=== TEST 39: an assertion good for years is remembered for a day
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- the schema takes any year up to 9999, and an entry that never
            -- lapses is a slot the dict never reclaims
            ngx.say(login_with("replay", saml_response({
                id = "forever",
                conditions = conditions({ not_on_or_after = "9999-12-31T23:59:59Z" }),
            })))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("forever"))
            ngx.say("capped: ", ttl > 86300 and ttl <= 86400)
        }
    }
--- response_body
302 /
capped: true
--- no_error_log
[error]
stays acceptable past its record


=== TEST 40: a full dict leaves the login working and says so
--- config
    location /t {
        content_by_lua_block {
            ngx.say("full: ", fill_dict("saml_replay_full"))

            -- evicting would take the record away from whoever holds it and
            -- report it against this request, so this login goes untracked
            ngx.say(login_with("replay_full", saml_response({ id = "untracked" })))
        }
    }
--- response_body
full: true
302 /
--- error_log eval
qr/\[error\] .* assertion untracked from https:\/\/idp\.example\.com in saml_replay_full: no memory, this assertion is not tracked/
--- no_error_log
[crit]
[alert]
[emerg]
though it carries OneTimeUse


=== TEST 41: a login refused after the checks leaves the assertion unspent
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- idp_issuers refuses this one below where the record used to be
            -- written, so writing it early told the retry it was a replay
            local xml = saml_response({ id = "unspent" })
            ngx.say(login_with("replay_pinned", xml))
            ngx.say("remembered: ", ngx.shared.saml_replay:get(replay_key("unspent")) ~= nil)
            ngx.say(login_with("replay", xml))
        }
    }
--- response_body
401 nil
remembered: false
302 /
--- error_log
unexpected issuer in response from IdP


=== TEST 42: a response refused part way spends none of its assertions
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- one signature over the whole Response, so it carries two
            -- assertions and the reader draws identity from both
            local spent = sign_doc(response(assertion({ id = "pair-b" })))
            ngx.say(login_with("replay", spent))

            local pair = sign_doc(response(
                assertion({ id = "pair-a" }) .. assertion({ id = "pair-b" })))
            ngx.say(login_with("replay", pair))
            ngx.say("remembered: ", ngx.shared.saml_replay:get(replay_key("pair-a")) ~= nil)

            ngx.say(login_with("replay", sign_doc(response(assertion({ id = "pair-a" })))))
        }
    }
--- response_body
302 /
401 nil
remembered: false
302 /
--- error_log
assertion pair-b has been presented already


=== TEST 43: replay configuration is weighed when the SP is built
--- config
    location /t {
        content_by_lua_block {
            local resty_saml = require("resty.saml")
            local function build(extra, drop)
                local opts = {
                    sp_issuer = "sp",
                    idp_uri = "http://127.0.0.1:1984/idp",
                    login_callback_uri = "/acs",
                    sp_cert = CERT_PEM,
                    sp_private_key = KEY_PEM,
                    idp_cert = CERT_PEM,
                    secret = "very-secret-key-that-is-32-byte!",
                }
                for k, v in pairs(extra) do opts[k] = v end
                if drop then opts[drop] = nil end
                local ok, err = pcall(resty_saml.new, opts)
                return ok and "built" or err:gsub("^.-:%d+: ", "")
            end

            ngx.say(build({ replay_dict = true }))
            ngx.say(build({ replay_dict = "no-such-dict" }))
            ngx.say(build({ replay_dict = "saml_replay" }, "sp_issuer"))
            -- zero means never expire to lua_shared_dict, and text is what a
            -- YAML or environment config path hands over
            ngx.say(build({ replay_dict = "saml_replay", replay_ttl = 0 }))
            ngx.say(build({ replay_dict = "saml_replay", replay_ttl = "600" }))
            ngx.say(build({ replay_dict = "saml_replay", replay_ttl = 90 }))
        }
    }
--- response_body
replay_dict must be the name of a lua_shared_dict
no lua_shared_dict named no-such-dict
sp_issuer must be a string to track assertions
replay_ttl must be a positive number of seconds
replay_ttl must be a positive number of seconds
built


=== TEST 44: a confirmation bound this parser will not take is skipped
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- an offset rather than Z is legal xs:dateTime and refused here, so
            -- that confirmation is unsatisfiable and the login rides on the
            -- other one. Refusing on it would let replay_dict decide who is let
            -- in, which is what the option must never do.
            ngx.say(login_with("replay", function(request_id)
                return saml_response({
                    id = "unreadable-bound",
                    confirmations = confirmation({
                        recipient = ACS, not_on_or_after = at(600),
                        in_response_to = request_id,
                    }) .. confirmation({
                        recipient = ACS, not_on_or_after = "2030-01-01T00:00:00+00:00",
                        in_response_to = request_id,
                    }),
                }, ACS, request_id)
            end))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("unreadable-bound"))
            ngx.say("tracked: ", ttl > 600 and ttl <= 660)
        }
    }
--- response_body
302 /
tracked: true


=== TEST 45: a confirmation naming no close keeps the fallback in charge
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- the dated sibling gives out in a minute; the dateless one never
            -- does, so it decides, and the record falls to replay_ttl rather
            -- than to the shortest date in sight
            ngx.say(login_with("replay", function(request_id)
                return saml_response({
                    id = "never-gives-out",
                    confirmations = confirmation({
                        recipient = ACS, not_on_or_after = at(60),
                        in_response_to = request_id,
                    }) .. confirmation({
                        recipient = ACS, in_response_to = request_id,
                    }),
                }, ACS, request_id)
            end))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("never-gives-out"))
            ngx.say("fallback: ", ttl > 590 and ttl <= 600)
        }
    }
--- response_body
302 /
fallback: true
--- no_error_log
[error]
stays acceptable past its record


=== TEST 46: acceptance ends at whichever close comes first
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- the Conditions window and the confirmations combine as an AND,
            -- so the Conditions closing first is when acceptance ends
            ngx.say(login_with("replay", function(request_id)
                return saml_response({
                    id = "conditions-first",
                    conditions = conditions({ not_on_or_after = at(300) }),
                    confirmations = confirmation({
                        recipient = ACS, not_on_or_after = at(3600),
                        in_response_to = request_id,
                    }),
                }, ACS, request_id)
            end))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("conditions-first"))
            ngx.say("earlier: ", ttl > 300 and ttl <= 360)
        }
    }
--- response_body
302 /
earlier: true


=== TEST 47: a confirmation that cannot confirm here has no say in the record
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- the dateless one is addressed elsewhere, so it can never keep
            -- this assertion alive here and does not unbound the record
            ngx.say(login_with("replay", function(request_id)
                return saml_response({
                    id = "elsewhere-dateless",
                    confirmations = confirmation({
                        recipient = ACS, not_on_or_after = at(3600),
                        in_response_to = request_id,
                    }) .. confirmation({
                        recipient = "https://other-sp.example.com/acs",
                    }),
                }, ACS, request_id)
            end))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("elsewhere-dateless"))
            ngx.say("dated one decides: ", ttl > 3600 and ttl <= 3660)
        }
    }
--- response_body
302 /
dated one decides: true


=== TEST 48: a failed login-session save does not redirect to the IdP
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_start_with_large_uri())
        }
    }
--- response_body
500
--- error_log
could not save login session: cookie size limit exceeded


=== TEST 49: a failed authenticated-session save returns replay entries
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            local bits = {}
            for i = 1, 1200 do bits[i] = ngx.md5(i) end
            local xml = saml_response({
                id = "save-failed",
                attributes = '<saml:AttributeStatement><saml:Attribute Name="large">' ..
                    '<saml:AttributeValue>' .. table.concat(bits) ..
                    '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>',
            })
            ngx.say(login_with("save_fails_replay", xml))
            ngx.say("remembered: ", ngx.shared.saml_replay:get(replay_key("save-failed")) ~= nil)
        }
    }
--- response_body
500 nil
remembered: false
--- error_log
could not save authenticated session: cookie size limit exceeded


=== TEST 50: with a record, an OneTimeUse assertion is treated like any other
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            local xml = saml_response({
                id = "stamped",
                conditions = conditions({ not_on_or_after = at(600), body = "<saml:OneTimeUse/>" }),
            })
            ngx.say(login_with("replay", xml))
            -- remembered until acceptance ends plus clock_skew, as any other
            local ttl = ngx.shared.saml_replay:ttl(replay_key("stamped"))
            ngx.say("recorded: ", ttl > 600 and ttl <= 660)
            ngx.say(login_with("replay", xml))
        }
    }
--- response_body
302 /
recorded: true
401 nil
--- error_log
assertion stamped has been presented already
--- no_error_log
[crit]
[alert]
[emerg]
OneTimeUse



=== TEST 51: a full dict says when the untracked login asked for single use
--- config
    location /t {
        content_by_lua_block {
            ngx.say("full: ", fill_dict("saml_replay_full"))

            -- twice: with no room the login fails open, both times
            local xml = saml_response({
                id = "untracked-stamped",
                conditions = conditions({ body = "<saml:OneTimeUse/>" }),
            })
            ngx.say(login_with("replay_full", xml))
            ngx.say(login_with("replay_full", xml))
        }
    }
--- response_body
full: true
302 /
302 /
--- error_log eval
qr/\[error\] .* assertion untracked-stamped from https:\/\/idp\.example\.com in saml_replay_full: no memory, this assertion is not tracked though it carries OneTimeUse/
--- grep_error_log eval
qr/could not remember assertion untracked-stamped [^,]*, this assertion is not tracked/
--- grep_error_log_out
could not remember assertion untracked-stamped from https://idp.example.com in saml_replay_full: no memory, this assertion is not tracked
could not remember assertion untracked-stamped from https://idp.example.com in saml_replay_full: no memory, this assertion is not tracked
--- no_error_log
[crit]
[alert]
[emerg]
stays acceptable past its record



=== TEST 52: an OneTimeUse assertion that outlives its record says so
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- nothing bounds it, so the record falls back to replay_ttl
            ngx.say(login_with("replay", saml_response({
                id = "stamped-unbounded",
                conditions = conditions({ body = "<saml:OneTimeUse/>" }),
            })))
            -- valid for years, so the record is capped at a day
            ngx.say(login_with("replay", saml_response({
                id = "stamped-forever",
                conditions = conditions({ not_on_or_after = "9999-12-31T23:59:59Z",
                    body = "<saml:OneTimeUse/>" }),
            })))
        }
    }
--- response_body
302 /
302 /
--- error_log eval
[qr/\[warn\] .* assertion stamped-unbounded from https:\/\/idp\.example\.com carries OneTimeUse but stays acceptable past its record, which lapses in 600 seconds/,
qr/\[warn\] .* assertion stamped-forever from https:\/\/idp\.example\.com carries OneTimeUse but stays acceptable past its record, which lapses in 86400 seconds/]
--- no_error_log
[error]
[crit]
[alert]
[emerg]



=== TEST 53: OneTimeUse is read wherever it sits among the conditions
--- config
    location /t {
        content_by_lua_block {
            local unknown = '<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' ..
                'xsi:type="saml:AudienceRestrictionType"><saml:Audience>sp</saml:Audience></saml:Condition>'
            for _, body in ipairs({ "<saml:OneTimeUse/>" .. unknown, unknown .. "<saml:OneTimeUse/>",
                unknown }) do
                local doc, err = parse(sign_doc(response(assertion({
                    id = "ordered", conditions = conditions({ body = body }),
                }))))
                if err then ngx.say("err: ", err) return end
                local a = saml.doc_assertions(doc)[1]
                ngx.say("one_time_use=", tostring(a.one_time_use),
                    " unknown_condition=", tostring(a.unknown_condition))
            end
        }
    }
--- response_body
one_time_use=true unknown_condition=Condition
one_time_use=true unknown_condition=Condition
one_time_use=false unknown_condition=Condition



=== TEST 54: without a record, an OneTimeUse assertion is accepted again
--- config
    location /t {
        content_by_lua_block {
            local xml = saml_response({
                id = "stamped-untracked",
                conditions = conditions({ not_on_or_after = at(600), body = "<saml:OneTimeUse/>" }),
            })
            ngx.say(login_with("plain", xml))
            ngx.say(login_with("plain", xml))
        }
    }
--- response_body
302 /
302 /
--- error_log eval
qr/\[warn\] .* assertion stamped-untracked from https:\/\/idp\.example\.com carries OneTimeUse, which this SP cannot enforce without replay_dict/
--- no_error_log
[error]
[crit]
[alert]
[emerg]



=== TEST 55: the operator's replay_ttl is taken as given, past the day too
--- config
    location /t {
        content_by_lua_block {
            ngx.shared.saml_replay:flush_all()
            -- the day cap bounds what the assertion claims; this value is
            -- nobody's claim but the operator's
            ngx.say(login_with("replay_long", saml_response({ id = "kept-long" })))
            local ttl = ngx.shared.saml_replay:ttl(replay_key("kept-long"))
            ngx.say("kept: ", ttl > 172700 and ttl <= 172800)
        }
    }
--- response_body
302 /
kept: true
