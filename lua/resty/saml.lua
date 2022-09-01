local saml = require "saml"
local uuid = require 'resty.jit-uuid'
uuid.seed()
local cjson = require "cjson"
local ck = require "resty.cookie"

local _M = {}

local RSA_SHA_512_HREF = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

local SESSION_COOKIE_NAME = "saml_session"

local SESSION_SHM = "saml_sessions"

local DEFAULT_COOKIE_LIFETIME = 300 -- in secs

local EXPIRED_DATE = "Thu, 01 Jan 1970 00:00:01 GMT"

local function create_redirect(key, params)
    local saml_type
    if params.SAMLRequest then
        saml_type = "SAMLRequest"
    elseif params.SAMLResponse then
        saml_type = "SAMLResponse"
    end
    assert(saml_type, "no saml request or response")

    return saml.binding_redirect_create(key, saml_type, params[saml_type], params.SigAlg, params.RelayState)
end

local function parse_redirect(saml_type, cert_from_doc)
    if ngx.req.get_method() ~= "GET" then return nil, nil, "method not allowed" end
    local args = ngx.req.get_uri_args()
    if args[saml_type] == nil then
        return nil
    end
    local doc, err = saml.binding_redirect_parse(saml_type, args, cert_from_doc)
    return doc, args, err
end

local function create_post(key, saml_type, content, sig_alg, relay_state, destination)
    return saml.binding_post_create(key, saml_type, content, sig_alg, relay_state, destination)
end

local function parse_post(saml_type, key_mngr_from_doc)
    if ngx.req.get_method() ~= "POST" then return nil, nil, "method not allowed" end

    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if not args then return nil, nil, err end

    if not args[saml_type] then return nil, args, "no " .. saml_type end
    local doc, err = saml.binding_post_parse(args[saml_type], key_mngr_from_doc)
    return doc, args, err
end

local function generate_saml_id()
    return "ID_" .. uuid.generate_v4()
end

local function get_first(table_or_string)
    local res = table_or_string
    if table_or_string and type(table_or_string) == 'table' then
        res = table_or_string[1]
    end
    return res
end

local function get_first_header(headers, header_name)
    local header = headers[header_name]
    return get_first(header)
end

local function get_first_header_and_strip_whitespace(headers, header_name)
    local header = get_first_header(headers, header_name)
    return header and header:gsub('%s', '')
end

local function get_forwarded_parameter(headers, param_name)
    local forwarded = get_first_header(headers, 'Forwarded')
    local params = {}
    if forwarded then
        local function parse_parameter(pv)
            local name, value = pv:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
            if name and value then
                if value:sub(1, 1) == '"' then
                    value = value:sub(2, -2)
                end
                params[name:lower()] = value
            end
        end

        -- this assumes there is no quoted comma inside the header's value
        -- which should be fine as comma is not legal inside a node name,
        -- a URI scheme or a host name. The only thing that might bite us
        -- are extensions.
        local first_part = forwarded
        local first_comma = forwarded:find("%s*,%s*")
        if first_comma then
            first_part = forwarded:sub(1, first_comma - 1)
        end
        first_part:gsub("[^;]+", parse_parameter)
    end
    return params[param_name:gsub("^%s*(.-)%s*$", "%1"):lower()]
end

local function get_scheme(headers)
    return get_forwarded_parameter(headers, 'proto')
        or get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Proto')
        or ngx.var.scheme
end

local function get_host_name_from_x_header(headers)
    local header = get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Host')
    return header and header:gsub('^([^,]+),?.*$', '%1')
end

local function get_host_name(headers)
    return get_forwarded_parameter(headers, 'host')
        or get_host_name_from_x_header(headers)
        or ngx.var.http_host
end

-- assemble the redirect_uri
local function saml_get_redirect_uri(path)
    if path:sub(1, 1) ~= '/' then
        return path
    end
    local headers = ngx.req.get_headers()
    local scheme = get_scheme(headers)
    local host = get_host_name(headers)
    if not host then
        -- possibly HTTP 1.0 and no Host header
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    return scheme .. "://" .. host .. path
end

local function interp(s, tab)
    return s:gsub('($%b{})', function(w)
        local key = w:sub(3, -2)
        if not key:find(".", 2, true) then
            return tab[key] or ""
        else
            local t = tab
            for k in key:gmatch("%a+") do
                t = t[k]
                if not t then return "" end
            end
            return t
        end
    end)
end

local AUTHN_REQUEST = [[
<?xml version="1.0" ?>
<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="${uuid}" IssueInstant="${issue_instant}" Destination="${destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-GET" AssertionConsumerServiceURL="${acs_url}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${issuer}</saml:Issuer>
</samlp:AuthnRequest>
]]

local function authn_request(opts)
    return interp(AUTHN_REQUEST, {
        acs_url = saml_get_redirect_uri(opts.login_callback_uri),
        destination = opts.idp_uri,
        issue_instant = os.date("!%Y-%m-%dT%TZ"),
        issuer = opts.sp_issuer,
        uuid = generate_saml_id(),
    })
end

local LOGOUT_REQUEST = [[
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="${id}" IssueInstant="${issue_instant}" Destination="${destination}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${issuer}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${name_id}</saml:NameID>
  <samlp:SessionIndex>${session_index}</samlp:SessionIndex>
</samlp:LogoutRequest>
]]

local function logout_request(opts, name_id, session_index)
    return interp(LOGOUT_REQUEST, {
        destination = opts.idp_uri,
        name_id = name_id,
        id = generate_saml_id(),
        issue_instant = os.date("!%Y-%m-%dT%TZ"),
        issuer = opts.sp_issuer,
        session_index = session_index,
    })
end

local function login(self, opts)
    local cookie, err = ck:new()
    if not cookie then
        ngx.log(ngx.ERR, "cookie:new(): ", err)
        ngx.exit(500)
    end

    local session_id = cookie:get(SESSION_COOKIE_NAME)

    if session_id then
        local data = ngx.shared[SESSION_SHM]:get(session_id)
        if data then
            data = cjson.decode(data)
            if data.authenticated then
                return data
            end
        end
    end

    local request_uri = ngx.var.request_uri
    local state = uuid.generate_v4()

    local query_str, err = create_redirect(self.sign_key, {
        SAMLRequest = authn_request(opts),
        SigAlg = RSA_SHA_512_HREF,
        RelayState = state,
    })
    if err then
        ngx.log(ngx.ERR, err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if not session_id then
        session_id = uuid.generate_v4()
        local ok, err = cookie:set({
            key = SESSION_COOKIE_NAME,
            value = session_id,
            path = "/",
            httponly = true,
        })
        if not ok then
            ngx.log(ngx.ERR, "cookie:set(): ", err)
            ngx.exit(500)
        end
    end

    local data = {
        request_uri = request_uri,
        state = state,
    }
    data = cjson.encode(data)
    ngx.shared[SESSION_SHM]:set(session_id, data, DEFAULT_COOKIE_LIFETIME)

    ngx.log(ngx.INFO, "login start, request_uri=", data.request_uri)

    return ngx.redirect(opts.idp_uri .. "?" .. query_str)
end

local function parse_iso8601_utc_time(str)
    -- NOTE: We accept only 'Z' for timezone.
    local year_s, month_s, day_s, hour_s, min_s, sec_s = str:match('(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d).*Z')
    if year_s == nil then
        return nil, 'invalid UTC time pattern unmatch'
    end
    local year = tonumber(year_s)
    if year < 1970 then
        return nil, 'invalid year in UTC time'
    end
    local month = tonumber(month_s)
    if month < 1 or 12 < month then
        return nil, 'invalid month in UTC time'
    end
    local day = tonumber(day_s)
    if day < 1 or 31 < day then
        return nil, 'invalid day in UTC time'
    end
    local hour = tonumber(hour_s)
    if hour < 0 or 23 < hour then
        return nil, 'invalid hour in UTC time'
    end
    local min = tonumber(min_s)
    if min < 0 or 59 < min then
        return nil, 'invalid min in UTC time'
    end
    local sec = tonumber(sec_s)
    if sec < 0 or 59 < sec then
        return nil, 'invalid sec in UTC time'
    end
    return os.time{year=year, month=month, day=day, hour=hour, min=min, sec=sec}
end

local function login_callback(self, opts)
    local cookie, err = ck:new()
    if not cookie then
        ngx.log(ngx.ERR, "cookie:new(): ", err)
        ngx.exit(500)
    end

    local session_id, err = cookie:get(SESSION_COOKIE_NAME)
    if err then
        ngx.log(ngx.ERR, "cookie:get(): ", err)
        ngx.exit(500)
    end

    if not session_id then
        ngx.log(ngx.ERR, "no session found")
        ngx.exit(503)
    end

    local data = ngx.shared[SESSION_SHM]:get(session_id)
    if not data then
        ngx.log(ngx.ERR, "no session found")
        ngx.exit(503)
    end
    data = cjson.decode(data)
    local request_uri = data.request_uri

    local method = ngx.req.get_method()
    local doc, args, err
    if method == "POST" then
        doc, args, err = parse_post("SAMLResponse", self.key_mngr_from_doc)
    elseif method == "GET" then
        doc, args, err = parse_redirect("SAMLResponse", self.idp_cert_func)
    else
        return ngx.exit(405)
    end

    if err then
        ngx.log(ngx.ERR, "parse post from IdP: ", err)
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    local status_code = saml.doc_status_code(doc)
    if status_code ~= saml.STATUS_SUCCESS then
        ngx.log(ngx.ERR, "IdP returned non-success status: ", status_code)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local state = args.RelayState
    if state ~= data.state then
        ngx.log(ngx.ERR, "state different: args.state=", state, ", state=", data.state)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local issuer = saml.doc_issuer(doc)
    local attrs = saml.doc_attrs(doc)
    local name_id = saml.doc_name_id(doc)
    local session_index = saml.doc_session_index(doc)
    local session_expires = saml.doc_session_expires(doc)
    local expires, lifetime
    if session_expires then
        expires, err = parse_iso8601_utc_time(session_expires)
        ngx.log(ngx.INFO, "login callback: session_expires=", os.date("%Y-%m-%d %T %z", expires))
        if err then
            ngx.say(err)
            ngx.exit(500)
        end
        lifetime = expires - ngx.time()
    else
        lifetime = DEFAULT_COOKIE_LIFETIME
        expires = ngx.time() + DEFAULT_COOKIE_LIFETIME
    end

    local data = {
        authenticated = true,
        name_id = name_id,
        session_index = session_index,
        attrs = attrs,
        issuer = issuer,
    }
    data = cjson.encode(data)
    ngx.shared[SESSION_SHM]:set(session_id, data, lifetime)

    local ok, err = cookie:set({
        key = SESSION_COOKIE_NAME,
        value = session_id,
        path = "/",
        httponly = true,
        expires = ngx.cookie_time(expires),
    })
    if not ok then
        ngx.log(ngx.ERR, "cookie:set(): ", err)
        ngx.exit(500)
    end

    ngx.log(ngx.INFO, "login finish: data=", cjson.encode(data))

    return ngx.redirect(request_uri)
end

local LOGOUT_RESPONSE = [[
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${uuid}" Version="2.0" IssueInstant="${issue_instant}" Destination="${destination}" InResponseTo="${in_response_to}">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="${status}"/>
  </samlp:Status>
</samlp:LogoutResponse>
]]

local function logout_response(destination, in_response_to, status, issuer)
    return interp(LOGOUT_RESPONSE, {
        destination = destination,
        in_response_to = in_response_to,
        issue_instant = os.date("!%Y-%m-%dT%TZ"),
        issuer = issuer,
        status = status,
        uuid = generate_saml_id(),
    })
end

local function logout_callback(self, opts)
    local cookie, err = ck:new()
    if not cookie then
        ngx.log(ngx.ERR, "cookie:new(): ", err)
        ngx.exit(500)
    end

    local session_id, err = cookie:get(SESSION_COOKIE_NAME)
    if err then
        ngx.log(ngx.ERR, "cookie:get(): ", err)
        ngx.exit(500)
    end

    if not session_id then
        ngx.log(ngx.ERR, "no session found")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local method = ngx.req.get_method()
    local doc, args, err
    if method == "POST" then
        doc, args, err = parse_post("SAMLResponse", self.key_mngr_from_doc)

        if not doc then
            doc, args, err = parse_post("SAMLRequest", self.key_mngr_from_doc)
        end
    elseif method == "GET" then
        doc, args, err = parse_redirect("SAMLResponse", self.idp_cert_func)

        if not doc then
            doc, args, err = parse_redirect("SAMLRequest", self.idp_cert_func)
        end
    else
        return ngx.exit(405)
    end

    if not doc then
        ngx.log(ngx.WARN, err)
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    local name = saml.doc_root_name(doc)
    if not name then
        ngx.log(ngx.WARN, "no name")
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    local data = ngx.shared[SESSION_SHM]:get(session_id)
    if not data then
        ngx.log(ngx.ERR, "no session found")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    data = cjson.decode(data)

    if name == "LogoutRequest" then
        local issuer = saml.doc_issuer(doc)
        local request_id = saml.doc_id(doc)
        local status = saml.STATUS_SUCCESS
        local name_id = saml.doc_name_id(doc)
        local session_index = saml.doc_session_index(doc)

        if issuer ~= data.issuer then
            ngx.log(ngx.WARN, "issuer different: issuer=", issuer,
                ", data.issuer=", data.issuer)
        end

        if name_id ~= data.name_id then
            ngx.log(ngx.WARN, "name_id different: name_id=", name_id,
                ", data.name_id=", data.name_id)
        end

        if session_index ~= data.session_index then
            ngx.log(ngx.WARN, "session_index different: session_index=",
                session_index, ", data.session_index=", data.session_index)
        end

        cookie:set({
            key = SESSION_COOKIE_NAME,
            value = "",
            expires = EXPIRED_DATE,
            max_age = 0,
        })
        ngx.shared[SESSION_SHM]:delete(session_id)

        local query_str, err = create_redirect(self.sign_key, {
            SAMLResponse = logout_response(opts.idp_uri, request_id, status, opts.sp_issuer),
            SigAlg = RSA_SHA_512_HREF,
            RelayState = "",
        })
        if err then
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
        ngx.log(ngx.INFO, "logout finish: data=", cjson.encode(data))

        return ngx.redirect(opts.idp_uri .. "?" .. query_str)

        --[[
        local body, err = create_post(self.sign_key, "SAMLResponse",
            logout_response(opts.idp_uri, request_id, status, opts.sp_issuer), RSA_SHA_512_HREF, "", opts.idp_uri)
        if err then
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        ngx.log(ngx.INFO, "logout finish: data=", cjson.encode(data))

        ngx.header.content_type = "text/html"
        ngx.header.content_length = #body
        ngx.say(body)
        return ngx.exit(ngx.HTTP_OK)
        --]]
    else
        local status_code = saml.doc_status_code(doc)
        if status_code ~= saml.STATUS_SUCCESS then
            ngx.log(ngx.ERR, "IdP returned non-success status: ", status_code)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
        cookie:set({
            key = SESSION_COOKIE_NAME,
            value = "",
            expires = EXPIRED_DATE,
            max_age = 0,
        })
        ngx.shared[SESSION_SHM]:delete(session_id)

        ngx.log(ngx.INFO, "logout finish: data=", cjson.encode(data))
        return ngx.redirect(opts.logout_redirect_uri or "/")
    end
end

local function logout(self, opts)
    local cookie, err = ck:new()
    if not cookie then
        ngx.log(ngx.ERR, "cookie:new(): ", err)
        ngx.exit(500)
    end

    local session_id, err = cookie:get(SESSION_COOKIE_NAME)
    if err then
        ngx.log(ngx.ERR, "cookie:get(): ", err)
        ngx.exit(500)
    end

    local authenticated = false
    if session_id then
        local data = ngx.shared[SESSION_SHM]:get(session_id)
        if data then
            data = cjson.decode(data)
            if data.authenticated then
                authenticated = true
            end
        end
    end
    if not authenticated then
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local query_str, err = create_redirect(self.sign_key, {
        SAMLRequest = logout_request(opts, ngx.shared.name_id, ngx.shared.session_index),
        SigAlg = RSA_SHA_512_HREF,
        RelayState = "",
    })
    if err then
        ngx.log(ngx.ERR, err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    return ngx.redirect(opts.idp_uri .. "?" .. query_str)
end

local function authenticate(self)
    local opts = self.opts
    local uri = ngx.var.uri

    if uri == opts.login_callback_uri then
        return login_callback(self, opts)
    elseif uri == opts.logout_uri then
        return logout(self, opts)
    elseif uri == opts.logout_callback_uri then
        return logout_callback(self, opts)
    end

    return login(self, opts)
end

function _M.new(opts)
    local obj = setmetatable({opts = opts}, {__index = {authenticate = authenticate}})
    obj.sign_key = assert(saml.key_read_memory(opts.sp_private_key, saml.KeyDataFormatPem))
    saml.key_add_cert_memory(obj.sign_key, opts.sp_cert, saml.KeyDataFormatCertPem)
    local idp_cert = assert(saml.key_read_memory(opts.idp_cert, saml.KeyDataFormatCertPem))
    obj.idp_cert_manager = assert(saml.create_keys_manager({ idp_cert }))
    saml.key_add_ca_memory(obj.idp_cert_manager, opts.idp_cert)
    obj.key_mngr_from_doc = function(doc) return obj.idp_cert_manager end
    obj.idp_cert_func = function(doc) return idp_cert end
    return obj
end

function _M.init(opts)
    return saml.init(opts)
end

return _M
