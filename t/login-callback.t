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

    init_by_lua_block {
        saml = require "saml"
        local err = saml.init({ debug = true, data_dir = os.getenv("SAML_DATA_DIR") })
        if err then assert(nil, err) end

        SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
        IDP = "https://idp.example.com"

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

        -- one SP per allow-list under test, picked by request header
        ALLOW_LISTS = {
            none = nil,
            exact = { IDP },
            other = { "https://other.example.com" },
            both = { IDP, "https://other.example.com" },
        }
        SPS = {}

        function sp(name)
            if SPS[name] == nil then
                SPS[name] = require("resty.saml").new({
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
                    idp_issuers = ALLOW_LISTS[name],
                })
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

        function assertion(issuer, id, name_id)
            return string.format('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' ..
                'ID="%s" Version="2.0" IssueInstant="2026-07-21T00:00:00Z">' ..
                '<saml:Issuer>%s</saml:Issuer>' ..
                '<saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject></saml:Assertion>',
                id, issuer, name_id)
        end

        function response(issuer, body)
            return string.format('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' ..
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-1" Version="2.0" ' ..
                'IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>%s</saml:Issuer>' ..
                '<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response>',
                issuer, SUCCESS, body)
        end

        -- only the assertion is signed, so the Response around it, its own
        -- Issuer included, is whatever the sender wants
        function saml_response(response_issuer, assertion_issuer, name_id)
            return response(response_issuer, sign_doc(assertion(assertion_issuer, "a1", name_id)))
        end

        -- start a login, then hand the crafted response back to the callback
        -- with the session and RelayState that login handed out
        function login_with(name, xml)
            local httpc = require("resty.http").new()
            local base = "http://127.0.0.1:1984"
            local headers = { ["X-Test-SP"] = name }

            local res, err = httpc:request_uri(base .. "/", { headers = headers })
            if not res then return "login request: " .. err end
            local cookie = res.headers["Set-Cookie"]
            if type(cookie) == "table" then cookie = cookie[1] end
            local state = res.headers["Location"]:match("RelayState=([^&]+)")

            res, err = httpc:request_uri(base .. "/acs", {
                method = "POST",
                body = "SAMLResponse=" .. ngx.escape_uri(saml.base64_encode(xml)) ..
                    "&RelayState=" .. state,
                headers = {
                    ["X-Test-SP"] = name,
                    ["Cookie"] = cookie:match("^[^;]+"),
                    ["Content-Type"] = "application/x-www-form-urlencoded",
                },
            })
            if not res then return "callback request: " .. err end
            return res.status .. " " .. tostring(res.headers["Location"])
        end
    }

    server {
        listen 1984;

        location / {
            access_by_lua_block {
                sp(ngx.var.http_x_test_sp or "none"):authenticate()
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

=== TEST 1: no allow-list accepts the issuer the IdP key signs for
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("none", saml_response(IDP, IDP, "signed@example.com")))
        }
    }
--- response_body
302 /



=== TEST 2: an allow-listed issuer is accepted
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("exact", saml_response(IDP, IDP, "signed@example.com")))
        }
    }
--- response_body
302 /



=== TEST 3: an issuer outside the allow-list is rejected
--- config
    location /t {
        content_by_lua_block {
            ngx.say(login_with("exact", saml_response("https://elsewhere.example.com",
                "https://elsewhere.example.com", "signed@example.com")))
        }
    }
--- response_body
401 nil
--- error_log
unexpected issuer in response from IdP: https://elsewhere.example.com



=== TEST 4: an allow-listed Issuer on the unsigned Response does not admit a foreign assertion
--- config
    location /t {
        content_by_lua_block {
            -- the assertion is signed by the same key but issued by another
            -- IdP, and the Response around it claims the allow-listed one
            ngx.say(login_with("exact", saml_response(IDP,
                "https://other.example.com", "attacker@example.com")))
        }
    }
--- response_body
401 nil
--- error_log
unexpected issuer in response from IdP: https://other.example.com



=== TEST 5: a second assertion the allow-list does not name is rejected
--- config
    location /t {
        content_by_lua_block {
            -- the whole response is signed, so both assertions are covered and
            -- both are read from, but only the first names an expected issuer
            local xml = sign_doc(response(IDP,
                assertion(IDP, "a1", "signed@example.com") ..
                assertion("https://other.example.com", "a2", "other@example.com")))
            ngx.say(login_with("exact", xml))
        }
    }
--- response_body
401 nil
--- error_log
unexpected issuer in response from IdP: https://other.example.com



=== TEST 6: two assertions are accepted when the allow-list names both
--- config
    location /t {
        content_by_lua_block {
            local xml = sign_doc(response(IDP,
                assertion(IDP, "a1", "signed@example.com") ..
                assertion("https://other.example.com", "a2", "other@example.com")))
            ngx.say(login_with("both", xml))
        }
    }
--- response_body
302 /
