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
        local saml = require "saml"
        local err = saml.init({
            debug = true,
            data_dir = os.getenv("SAML_DATA_DIR"),
        })
        if err then
            assert(nil, err)
        end
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

run_tests();

__DATA__

=== TEST 1: identity is read only from a response holding a single assertion
--- config
    location /t {
        content_by_lua_block {
            local saml = require "saml"

            local key_pem = [[-----BEGIN PRIVATE KEY-----
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

            local cert_pem = [[-----BEGIN CERTIFICATE-----
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

            local sign_key = assert(saml.key_read_memory(key_pem, saml.KeyDataFormatPem))
            saml.key_add_cert_memory(sign_key, cert_pem, saml.KeyDataFormatCertPem)

            local idp_cert = assert(saml.key_read_memory(cert_pem, saml.KeyDataFormatCertPem))
            local mngr = assert(saml.create_keys_manager({ idp_cert }))
            saml.key_add_ca_memory(mngr, cert_pem)

            local transform = saml.find_transform_by_href(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

            -- an assertion signed on its own subtree, as most IdPs emit it
            local assertion = [[<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-signed" Version="2.0" IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>signed@example.com</saml:NameID></saml:Subject></saml:Assertion>]]

            local signed = assert(saml.sign_xml(sign_key, transform, assertion,
                { id_attr = "ID", insert_after = { saml.XMLNS_ASSERTION, "Issuer" } }))
            signed = signed:gsub("<%?xml.-%?>%s*", "")

            local function parse(xml)
                return saml.binding_post_parse(saml.base64_encode(xml), function(_) return mngr end)
            end

            -- a response carrying the single signed assertion is trusted
            local ok_resp = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"resp-1\" Version=\"2.0\" IssueInstant=\"2026-07-21T00:00:00Z\"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" .. signed .. "</samlp:Response>"
            local doc, err = parse(ok_resp)
            if err then
                ngx.say("single rejected: ", err)
                return
            end
            ngx.say("single name_id: ", saml.doc_name_id(doc))

            -- a response with a second, unsigned assertion in front is rejected,
            -- so its NameID can never be read as the trusted identity
            local extra = [[<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-extra" Version="2.0" IssueInstant="2026-07-21T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>extra@example.com</saml:NameID></saml:Subject></saml:Assertion>]]
            local two_resp = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"resp-1\" Version=\"2.0\" IssueInstant=\"2026-07-21T00:00:00Z\"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" .. extra .. signed .. "</samlp:Response>"
            local doc2, err2 = parse(two_resp)
            if err2 then
                ngx.say("two rejected: ", err2)
            else
                ngx.say("two accepted as: ", saml.doc_name_id(doc2))
            end
        }
    }
--- response_body
single name_id: signed@example.com
two rejected: response must carry exactly one assertion
--- no_error_log
[error]
