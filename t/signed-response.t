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
    lua_package_cpath '$pwd/?.so;;';

    init_by_lua_block {
        saml = require "saml"
        local err = saml.init({ debug = true, data_dir = os.getenv("SAML_DATA_DIR") })
        if err then assert(nil, err) end

        SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
        FAILURE = "urn:oasis:names:tc:SAML:2.0:status:Requester"

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

        function saml_ctx()
            local key = assert(saml.key_read_memory(KEY_PEM, saml.KeyDataFormatPem))
            saml.key_add_cert_memory(key, CERT_PEM, saml.KeyDataFormatCertPem)
            local cert = assert(saml.key_read_memory(CERT_PEM, saml.KeyDataFormatCertPem))
            local mngr = assert(saml.create_keys_manager({ cert }))
            saml.key_add_ca_memory(mngr, CERT_PEM)
            local transform = saml.find_transform_by_href(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            return key, mngr, transform
        end

        function sign(key, transform, xml)
            local out = assert(saml.sign_xml(key, transform, xml,
                { id_attr = "ID", insert_after = { saml.XMLNS_ASSERTION, "Issuer" } }))
            return (out:gsub("<%?xml.-%?>%s*", ""))
        end

        function response(status, id, body)
            return string.format('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response>',
                id, status, body)
        end

        function assertion(id, name_id, extra)
            return string.format('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' ..
                'ID="%s" Version="2.0" IssueInstant="2026-07-21T00:00:00Z">' ..
                '<saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject>%s</saml:Assertion>',
                id, name_id, extra or "")
        end

        function attribute(name, value)
            return string.format('<saml:AttributeStatement><saml:Attribute Name="%s">' ..
                '<saml:AttributeValue>%s</saml:AttributeValue>' ..
                '</saml:Attribute></saml:AttributeStatement>', name, value)
        end

        function submit(mngr, xml)
            return saml.binding_post_parse(saml.base64_encode(xml), function(_) return mngr end)
        end

        -- Signature shapes sign_xml cannot build are pre-signed with the key
        -- above and kept under t/fixtures.
        function fixture(name)
            local f = assert(io.open("$pwd/t/fixtures/" .. name, "r"))
            local xml = f:read("*a")
            f:close()
            return xml
        end

        -- The identity read back is only ever the genuinely signed subject or
        -- nil; a forged admin identity must never surface.
        function identity(mngr, xml)
            local doc, err = submit(mngr, xml)
            if err then return "err: " .. err end
            return "name_id: " .. tostring(saml.doc_name_id(doc))
        end
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

run_tests();

__DATA__

=== TEST 1: assertion-level signature over the single assertion is trusted
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local signed = sign(key, transform, assertion("a1", "signed@example.com"))
            ngx.say(identity(mngr, response(SUCCESS, "resp-1", signed)))
        }
    }
--- response_body
name_id: signed@example.com



=== TEST 2: a forged assertion in front of the signed one is dropped, not read
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local signed = sign(key, transform, assertion("a1", "signed@example.com"))
            local forged = assertion("a2", "admin@target.com")
            ngx.say(identity(mngr, response(SUCCESS, "resp-1", forged .. signed)))
        }
    }
--- response_body
name_id: signed@example.com



=== TEST 3: a whole-response signature covering the assertion is trusted
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local resp = response(SUCCESS, "resp-1", assertion("a1", "signed@example.com"))
            ngx.say(identity(mngr, sign(key, transform, resp)))
        }
    }
--- response_body
name_id: signed@example.com



=== TEST 4: a signed non-success response with no assertion reads its status
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local signed_resp = sign(key, transform, response(FAILURE, "resp-1", ""))
            local doc, err = submit(mngr, signed_resp)
            if err then ngx.say("err: ", err) else ngx.say("status: ", saml.doc_status_code(doc)) end
        }
    }
--- response_body
status: urn:oasis:names:tc:SAML:2.0:status:Requester



=== TEST 5: a forged assertion whose Advice holds a signed inner response is dropped
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local inner = sign(key, transform, response(FAILURE, "inner", ""))
            local forged = assertion("a1", "admin@target.com",
                "<saml:Advice>" .. inner .. "</saml:Advice>")
            ngx.say(identity(mngr, response(SUCCESS, "outer", forged)))
        }
    }
--- response_body
name_id: nil



=== TEST 6: a signed success response with no assertion yields no identity
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            ngx.say(identity(mngr, sign(key, transform, response(SUCCESS, "resp-1", ""))))
        }
    }
--- response_body
name_id: nil



=== TEST 7: a nested non-success status in Extensions cannot smuggle an identity
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local inner = sign(key, transform, response(FAILURE, "inner", ""))
            local ext = '<samlp:Extensions>' ..
                assertion("ext", "irrelevant@example.com", "<saml:Advice>" .. inner .. "</saml:Advice>") ..
                '</samlp:Extensions>'
            local outer = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="outer" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                ext ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                assertion("a1", "admin@target.com") ..
                '</samlp:Response>'
            ngx.say(identity(mngr, outer))
        }
    }
--- response_body
name_id: nil



=== TEST 8: a forged assertion under a nested Response cannot shadow the signed one
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            -- the genuine, signed assertion sits directly in the outer response
            local signed = sign(key, transform, assertion("a1", "signed@example.com"))
            -- a forged assertion is a direct child of a nested Response hidden in
            -- Extensions, first in document order
            local nested = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="nested" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                assertion("forged", "admin@target.com") .. '</samlp:Response>'
            local ext = '<samlp:Extensions>' ..
                assertion("ext", "irrelevant@example.com", "<saml:Advice>" .. nested .. "</saml:Advice>") ..
                '</samlp:Extensions>'
            local outer = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="outer" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                ext ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                signed ..
                '</samlp:Response>'
            ngx.say(identity(mngr, outer))
        }
    }
--- response_body
name_id: signed@example.com



=== TEST 9: a whole-response signature covers every assertion it carries
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local a1 = assertion("a1", "signed@example.com", attribute("email", "signed@example.com"))
            local a2 = assertion("a2", "signed@example.com", attribute("role", "admin"))
            local signed = sign(key, transform, response(SUCCESS, "resp-1", a1 .. a2))
            local doc, err = submit(mngr, signed)
            if err then
                ngx.say("err: ", err)
            else
                local attrs = saml.doc_attrs(doc)
                ngx.say("name_id: ", saml.doc_name_id(doc),
                    ", email: ", attrs.email, ", role: ", attrs.role)
            end
        }
    }
--- response_body
name_id: signed@example.com, email: signed@example.com, role: admin



=== TEST 10: an assertion-level signature cannot vouch for a second assertion's attributes
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local signed = sign(key, transform, assertion("a1", "signed@example.com"))
            local forged = assertion("a2", "admin@target.com", attribute("role", "admin"))
            local doc, err = submit(mngr, response(SUCCESS, "resp-1", signed .. forged))
            if err then
                ngx.say("err: ", err)
            else
                local attrs = saml.doc_attrs(doc)
                ngx.say("name_id: ", tostring(saml.doc_name_id(doc)),
                    ", role: ", tostring(attrs.role))
            end
        }
    }
--- response_body
name_id: signed@example.com, role: nil



=== TEST 11: an assertion carrying Advice is trusted, its Advice is not read
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local advice = "<saml:Advice>" .. assertion("adv", "advice@example.com") .. "</saml:Advice>"
            local signed = sign(key, transform, assertion("a1", "signed@example.com", advice))
            ngx.say(identity(mngr, response(SUCCESS, "resp-1", signed)))
        }
    }
--- response_body
name_id: signed@example.com



=== TEST 12: a signed assertion parked in Extensions cannot cover the read assertion
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            -- a genuine assertion the attacker owns, parked where no reader looks
            local stolen = sign(key, transform, assertion("stolen", "attacker@example.com"))
            local outer = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="outer" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Extensions>' .. stolen .. '</samlp:Extensions>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                assertion("a1", "admin@target.com") ..
                '</samlp:Response>'
            ngx.say(identity(mngr, outer))
        }
    }
--- response_body
name_id: nil



=== TEST 13: a LogoutResponse status is read from the root message
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local logout = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="lr-1" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                '</samlp:LogoutResponse>'
            local doc, err = submit(mngr, sign(key, transform, logout))
            if err then
                ngx.say("err: ", err)
            else
                ngx.say(saml.doc_root_name(doc), ": ", saml.doc_status_code(doc))
            end
        }
    }
--- response_body
LogoutResponse: urn:oasis:names:tc:SAML:2.0:status:Success



=== TEST 14: a non-Response root cannot smuggle identity from a nested Response
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            -- a genuinely signed assertion for a low-priv identity sits in a
            -- nested Response beside a forged high-priv one, all wrapped in an
            -- ArtifactResponse whose own status is Success
            local stolen = sign(key, transform, assertion("stolen", "attacker@example.com"))
            local forged = assertion("forged", "admin@target.com", attribute("role", "admin"))
            local nested = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="nested" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                forged .. stolen .. '</samlp:Response>'
            local art = '<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="art" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                nested .. '</samlp:ArtifactResponse>'
            local doc, err = submit(mngr, art)
            if err then
                ngx.say("err: ", err)
            else
                local attrs = saml.doc_attrs(doc)
                ngx.say("root: ", saml.doc_root_name(doc),
                    ", name_id: ", tostring(saml.doc_name_id(doc)),
                    ", role: ", tostring(attrs and attrs.role))
            end
        }
    }
--- response_body
root: ArtifactResponse, name_id: nil, role: nil



=== TEST 15: a nested status earlier in the document is not the root status
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            -- a failure status sits in Extensions, ahead of the root's own
            local ext = '<samlp:Extensions>' ..
                assertion("ext", "irrelevant@example.com",
                    "<saml:Advice>" .. response(FAILURE, "inner", "") .. "</saml:Advice>") ..
                '</samlp:Extensions>'
            local outer = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="outer" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                ext ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                assertion("a1", "signed@example.com") ..
                '</samlp:Response>'
            local doc, err = submit(mngr, sign(key, transform, outer))
            if err then ngx.say("err: ", err) else ngx.say("status: ", saml.doc_status_code(doc)) end
        }
    }
--- response_body
status: urn:oasis:names:tc:SAML:2.0:status:Success



=== TEST 16: one signature covering two assertions keeps both
--- config
    location /t {
        content_by_lua_block {
            local _, mngr = saml_ctx()
            local doc, err = submit(mngr, fixture("multi-reference.xml"))
            if err then
                ngx.say("err: ", err)
            else
                local attrs = saml.doc_attrs(doc)
                ngx.say("name_id: ", tostring(saml.doc_name_id(doc)),
                    ", dept: ", tostring(attrs.dept), ", role: ", tostring(attrs.role))
            end
        }
    }
--- response_body
name_id: first@example.com, dept: eng, role: ops



=== TEST 17: an XPointer reference resolves like a barename one
--- config
    location /t {
        content_by_lua_block {
            local _, mngr = saml_ctx()
            ngx.say(identity(mngr, fixture("xpointer-reference.xml")))
        }
    }
--- response_body
name_id: signed@example.com



=== TEST 18: the issuer comes from the assertion, not the unsigned Response
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            -- the signature covers the assertion only, so the Response around
            -- it, its own Issuer included, is the attacker's to write
            local signed = sign(key, transform, assertion("a1", "signed@example.com"))
            local outer = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-1" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z">' ..
                '<saml:Issuer>https://attacker.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                signed .. '</samlp:Response>'
            local doc, err = submit(mngr, outer)
            if err then ngx.say("err: ", err) else ngx.say("issuer: ", tostring(saml.doc_issuer(doc))) end
        }
    }
--- response_body
issuer: https://idp.example.com



=== TEST 19: a whole-response signature reads the same issuer
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local resp = response(SUCCESS, "resp-1", assertion("a1", "signed@example.com"))
            local doc, err = submit(mngr, sign(key, transform, resp))
            if err then ngx.say("err: ", err) else ngx.say("issuer: ", tostring(saml.doc_issuer(doc))) end
        }
    }
--- response_body
issuer: https://idp.example.com



=== TEST 20: a message carrying no assertion reads its own issuer
--- config
    location /t {
        content_by_lua_block {
            local key, mngr, transform = saml_ctx()
            local logout = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="lr-1" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="' .. SUCCESS .. '"/></samlp:Status>' ..
                '</samlp:LogoutResponse>'
            local doc, err = submit(mngr, sign(key, transform, logout))
            if err then
                ngx.say("err: ", err)
            else
                ngx.say(saml.doc_root_name(doc), " issuer: ", tostring(saml.doc_issuer(doc)))
            end
        }
    }
--- response_body
LogoutResponse issuer: https://idp.example.com
