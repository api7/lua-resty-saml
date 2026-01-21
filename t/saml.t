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
    lua_package_path '$pwd/deps/share/lua/5.1/?.lua;$pwd/lua/?.lua;$pwd/t/?.lua;;';
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
        samls = {}
    }

    server {
        listen 1984;

        location / {
            access_by_lua_block {
                local sp_issuer = "sp"
                local host = ngx.var.host
                if host == "127.0.0.2" then
                    sp_issuer = "sp2"
                end

                if samls[sp_issuer] == nil then
                    local kc = require("lib.keycloak")
                    local opts = setmetatable({sp_issuer = sp_issuer}, {__index = kc.get_default_opts()})
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
            local kc = require "lib.keycloak"

            local uri = "http://127.0.0.1:" .. ngx.var.server_port
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
--- error_log
login callback req with redirect


=== TEST 2: login sp1 and sp2, then do single logout
--- config
    location /t {
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()
            local kc = require "lib.keycloak"

            -- login to sp1
            local uri = "http://127.0.0.1:" .. ngx.var.server_port
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
            local uri2 = "http://127.0.0.2:" .. ngx.var.server_port

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
--- error_log
login callback req with redirect
