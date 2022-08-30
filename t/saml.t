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
    lua_package_path '$pwd/deps/share/lua/5.1/?.lua;$pwd/lua/?.lua;$pwd/t/lib/?.lua;;';
    lua_package_cpath '$pwd/?.so;;';

    lua_shared_dict saml_sessions 10m;

    init_by_lua_block {
        local saml = require "resty.saml"
        local err = saml.init({
            debug = true,
            data_dir = os.getenv("SAML_DATA_DIR"),
        })
        if err then
            assert(nil, err)
        end
        local sp_private_key = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCzo92AOThlqsF\\nfxqIyA9gHrj3493UxTlhWo15OJnNL1ARNdKL4JFH6nY9sMntkLtaMdY6BYDI2lHC\\nv6a1xQSxavkS4kepTFMotj7wmfLXWEY3mFbbITbGUmTQ0yQoJ4Lrii/nQ6Esv20z\\nV/mSTJzHLTdcH/lIuksZXKLPnEzue3zqGopvk4ZduvwyRzU0FzPoSYlCLqAEJcx6\\nbkulQcZcqSER/0bke/m9eCDt91evDJM1yOHzYuiDZH8trhFwzE+9ms/I/8Svt+tQ\\nkAB5EAzfI26VpUWB3oq4eJsoEPEC4UJBsKaZh4a1GA+wbm8ql8EgUr0EsgFZH1Hg\\nGg2m97nLAgMBAAECggEBAJXT0sjadS7/97c5g8nxvMmbt32ItyOfMLusrqSuILSM\\nEBO8hpvoczSRorFd2GCr8Ty0meR0ORHBwCJ9zpV821gtQzX/7UfLmSX1zUC11u1D\\nSnYV56+PwxYTZtCpo+RyRyIrXR6MiFjnPfDAWAXqgKY8I5jqSotiJMJz2hC9UPoV\\ni56tHYXGCjtUAJrvG8FZM46TNL67nQ3ASWb5IH4cOqkgkKAJ/rZLrrMoL/HYpePr\\nn2MxlvT+TgdXebxo3rngu3pLRmLsfyV9eCLoOiP/oNAxTEA35EQQlnVfZOIEit8L\\nuvBYJYfYuXlxb96nQnOLqO/PrydwpXK9h1NtDvq3K2ECgYEA/i5ebOejoXORkFGx\\nDyYwkTczkh7QE328LSUVIiVGh4K1zFeYtj4mYYTeQMbzhlLAf9tGAZyZmvN52/ja\\niFLnI5lObNBooIfAYe3RAzUHGYraY7R1XutdOMjlP9tqjQ55y/xij/tu9qHT4fEz\\naQQPJ8D5sFbB5NgjxC8rlQ/WiLECgYEAxDNss4aMNhvL2+RTda72RMt99BS8PWEZ\\n/sdzzvu2zIJYFjBlCZ3Yd3vLhA/0MQXogMIcJofu4u2edZQVFSw4aHfnHFQCr45B\\n1QdDhZ8zoludEevgnLdSBzNakEJ63C8AQSkjIck4IaEmW+8G7fswpWGuVDBuHQZm\\nPBBcgz84CTsCgYBi8VvSWs0IYPtNyW757azEKk/J1nK605v3mtLCKu5se4YXGBYb\\nAtBf75+waYGMTRQf8RQsNnBYr+REq3ctz8+nvNqZYvsHWjCaLj/JVs//slxWqX1y\\nyH3OR+1tURUF+ZeRvxoC4CYOnWnkLscLXwgjOmw3p13snfI2QQJfEP460QKBgCzD\\nLsGmqMaPgOsiJIhs6nK3mnzdXjUCulOOXbWTaBkwg7hMQkD3ajOYYs42dZfZqTn3\\nD0UbLj1HySc6KbUy6YusD2Y/JH25DvvzNEyADd+01xkHn68hg+1wofDXugASGRTE\\ntec3aT8C7SV8WzBgZrDUoFlE01p740dA1Fp9SeORAoGBAIEa6LBIXuxb13xdOPDQ\\nFLaOQvmDCZeEwy2RAIOhG/1KGv+HYoCv0mMb4UXE1d65TOOE9QZLGUXksFfPc/ya\\nOP1vdjF/HN3DznxQ421GdPDYVIfp7edxZstNtGMYcR/SBwoIcvwaA5c2woMHbeju\\n+rbxDQL4gIT1lqn71w/8uoIJ\\n-----END PRIVATE KEY-----"
        local sp_cert = "-----BEGIN CERTIFICATE-----\\nMIIDgjCCAmqgAwIBAgIUOnf+MXKVU2zfIVaPz5dl0NTwPM4wDQYJKoZIhvcNAQEN\\nBQAwUTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRcwFQYDVQQKDA5sdWEt\\ncmVzdHktc2FtbDEZMBcGA1UEAwwQc2VydmljZS1wcm92aWRlcjAgFw0xOTA1MDgw\\nMTIyMDZaGA8yMTE4MDQxNDAxMjIwNlowUTELMAkGA1UEBhMCVVMxDjAMBgNVBAgM\\nBVRleGFzMRcwFQYDVQQKDA5sdWEtcmVzdHktc2FtbDEZMBcGA1UEAwwQc2Vydmlj\\nZS1wcm92aWRlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMLOj3YA\\n5OGWqwV/GojID2AeuPfj3dTFOWFajXk4mc0vUBE10ovgkUfqdj2wye2Qu1ox1joF\\ngMjaUcK/prXFBLFq+RLiR6lMUyi2PvCZ8tdYRjeYVtshNsZSZNDTJCgnguuKL+dD\\noSy/bTNX+ZJMnMctN1wf+Ui6Sxlcos+cTO57fOoaim+Thl26/DJHNTQXM+hJiUIu\\noAQlzHpuS6VBxlypIRH/RuR7+b14IO33V68MkzXI4fNi6INkfy2uEXDMT72az8j/\\nxK+361CQAHkQDN8jbpWlRYHeirh4mygQ8QLhQkGwppmHhrUYD7BubyqXwSBSvQSy\\nAVkfUeAaDab3ucsCAwEAAaNQME4wHQYDVR0OBBYEFPbRiK9OxGCZeNUViinNQ4P5\\nZOf0MB8GA1UdIwQYMBaAFPbRiK9OxGCZeNUViinNQ4P5ZOf0MAwGA1UdEwQFMAMB\\nAf8wDQYJKoZIhvcNAQENBQADggEBAD0MvA3mk+u3CBDFwPtT9tI8HPSaYXS0HZ3E\\nVXe4WcU3PYFpZzK0x6qr+a7mB3tbpHYXl49V7uxcIOD2aHLvKonKRRslyTiw4UvL\\nOhSSByrArUGleI0wyr1BXAJArippiIhqrTDybvPpFC45x45/KtrckeM92NOlttlQ\\nyd2yW0qSd9gAnqkDu2kvjLlGh9ZYnT+yHPjUuWcxDL66P3za6gc+GhVOtsOemdYN\\nAErhuxiGVNHrtq2dfSedqcxtCpavMYzyGhqzxr9Lt43fpQeXeS/7JVFoC2y9buyO\\nz9HIbQ6/02HIoenDoP3xfqvAY1emixgbV4iwm3SWzG8pSTxvwuM=\\n-----END CERTIFICATE-----"
        local idp_uri = "http://127.0.0.1:8080/realms/test/protocol/saml"
        default_opts = {
            idp_uri = idp_uri,
            login_callback_uri = "/acs",
            logout_uri = "/logout",
            logout_callback_uri = "/sls",
            logout_redirect_uri = "/logout_ok",
            sp_cert = sp_cert,
            sp_private_key = sp_private_key,
        }
        samls = {}
    }

    server {
        listen 127.0.0.1:8088;
        listen 127.0.0.2:8099;

        location / {
            access_by_lua_block {
                local sp_issuer = "sp"
                local host = ngx.var.host
                if host == "127.0.0.2" then
                    sp_issuer = "sp2"
                end
                if samls[sp_issuer] == nil then
                    if idp_cert == nil then
                        local http = require "resty.http"
                        local httpc = http.new()
                        local uri = "http://127.0.0.1:8080/realms/test/protocol/saml/descriptor"
                        local res, err = httpc:request_uri(uri, { method = "GET" })
                        if err then
                            ngx.log(ngx.ERR, err)
                            ngx.exit(500)
                        end

                        local read_cert = require "read_cert"
                        local cert = res.body:match("<ds:X509Certificate>(.-)</ds:X509Certificate>")
                        idp_cert = read_cert.read_cert(cert)
                    end

                    local opts = setmetatable({sp_issuer = sp_issuer, idp_cert = idp_cert}, {__index = default_opts})
                    ngx.log(ngx.INFO, "create sp_issuer=", sp_issuer)
                    local saml = require("resty.saml").new(opts)
                    samls[sp_issuer] = saml
                end
                local saml = samls[sp_issuer]
                local data = saml:authenticate()
                ngx.ctx.data = data
            }
            content_by_lua_block {
                local data = ngx.ctx.data
                if data and data.name_id then
                    ngx.print(data.name_id)
                    ngx.exit(200)
                end
                ngx.say("something wrong")
                ngx.exit(500)
            }
        }

        location /logout_ok {
            content_by_lua_block {
                ngx.print("logout")
            }
        }
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

run_tests();

__DATA__

=== TEST 1: login and logout ok
--- config
    location /t {
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()
            local kc = require "keycloak"

            local uri = "http://127.0.0.1:8088"
            local username = "test"
            local password = "test"

            local res, err, saml_cookie, keycloak_cookie = kc.login_keycloak(uri, username, password)
            if err or res.headers['Location'] ~= "/" then
                ngx.log(ngx.ERR, err)
                ngx.exit(500)
            end
            res, err = httpc:request_uri(uri .. res.headers['Location'], {
                method = "GET",
                headers = {
                    ["Cookie"] = saml_cookie
                }
            })
            assert(res.status == 200)
            assert(res.body == username)

            res, err = kc.logout_keycloak(uri .. "/logout", saml_cookie, keycloak_cookie)
            if err or res.headers['Location'] ~= "/logout_ok" then
                ngx.log(ngx.ERR, err)
                ngx.exit(500)
            end
            res, err = httpc:request_uri(uri .. res.headers['Location'], {
                method = "GET",
            })
            assert(res.status == 200)
            assert(res.body == "logout")
        }
    }
--- error_code: 200



=== TEST 2: login sp1 and sp2, then do single logout
--- config
    location /t {
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()
            local kc = require "keycloak"

            -- login to sp1
            local uri = "http://127.0.0.1:8088"
            local username = "test"
            local password = "test"

            local res, err, saml_cookie, keycloak_cookie = kc.login_keycloak(uri, username, password)
            if err or res.headers['Location'] ~= "/" then
                ngx.log(ngx.ERR, err)
                ngx.exit(500)
            end
            res, err = httpc:request_uri(uri .. res.headers['Location'], {
                method = "GET",
                headers = {
                    ["Cookie"] = saml_cookie
                }
            })
            assert(res.status == 200)
            assert(res.body == username)

            -- login to sp2
            local uri2 = "http://127.0.0.2:8099"

            local res, err, saml_cookie2 = kc.login_keycloak_for_second_sp(uri2, keycloak_cookie)
            if err or res.headers['Location'] ~= "/" then
                ngx.log(ngx.ERR, err)
                ngx.exit(500)
            end
            res, err = httpc:request_uri(uri2 .. res.headers['Location'], {
                method = "GET",
                headers = {
                    ["Cookie"] = saml_cookie2
                }
            })
            assert(res.status == 200)
            assert(res.body == username)

            -- SLO (single logout)
            res, err = kc.single_logout(uri .. "/logout", saml_cookie, saml_cookie2, keycloak_cookie)
            if err or res.headers['Location'] ~= "/logout_ok" then
                ngx.log(ngx.ERR, err)
                ngx.exit(500)
            end
            res, err = httpc:request_uri(uri .. res.headers['Location'], {
                method = "GET",
            })
            assert(res.status == 200)
            assert(res.body == "logout")
        }
    }
--- error_code: 200
