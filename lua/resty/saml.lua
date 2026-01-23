local saml = require "saml"
local uuid = require 'resty.jit-uuid'
uuid.seed()

local session = require "resty.session"
local _M = {}
local RSA_SHA_512_HREF = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"


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
<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="${uuid}" IssueInstant="${issue_instant}" Destination="${destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:${auth_protocol_binding_method}" AssertionConsumerServiceURL="${acs_url}">
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
        auth_protocol_binding_method = opts.auth_protocol_binding_method,
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
    local sess = session.start(self.session_config)

    local authenticated = sess:get("authenticated")
    if authenticated then
        return {
            authenticated = authenticated,
            name_id = sess:get("name_id"),
            session_index = sess:get("session_index"),
            attrs = sess:get("attrs"),
            issuer = sess:get("issuer"),
            request_uri = sess:get("request_uri"),
            saml_state = sess:get("saml_state"),
        }
    end

    local state = uuid.generate_v4()
    local request_uri = ngx.var.request_uri

    sess:set("saml_state", state)
    sess:set("request_uri", request_uri)
    sess:save()

    local query_str, err = create_redirect(self.sign_key, {
        SAMLRequest = authn_request(opts),
        SigAlg = RSA_SHA_512_HREF,
        RelayState = state,
    })
    if err then
        ngx.log(ngx.ERR, err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.log(ngx.INFO, "login start, request_uri=", request_uri)

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
    local sess = session.start(self.session_config)

    local saml_state = sess:get("saml_state")
    if not saml_state then
        ngx.log(ngx.ERR, "no session found or saml_state missing")
        ngx.exit(503)
    end

    local request_uri = sess:get("request_uri")

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
    if state ~= saml_state then
        ngx.log(ngx.ERR, "state different: args.state=", state, ", state=", saml_state)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local issuer = saml.doc_issuer(doc)
    local attrs = saml.doc_attrs(doc)
    local name_id = saml.doc_name_id(doc)
    local session_index = saml.doc_session_index(doc)

    sess:set("authenticated", true)
    sess:set("name_id", name_id)
    sess:set("session_index", session_index)
    sess:set("attrs", attrs)
    sess:set("issuer", issuer)
    sess:save()

    ngx.log(ngx.INFO, "login finish: name_id=", name_id)

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
    local sess = session.start(self.session_config)
    local authenticated = sess:get("authenticated")

    if not authenticated then
        ngx.log(ngx.ERR, "no active session for logout")
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

    if name == "LogoutRequest" then
        local issuer = saml.doc_issuer(doc)
        local request_id = saml.doc_id(doc)
        local status = saml.STATUS_SUCCESS
        local name_id = saml.doc_name_id(doc)
        local session_index = saml.doc_session_index(doc)

        local saved_issuer = sess:get("issuer")
        if issuer ~= saved_issuer then
            ngx.log(ngx.WARN, "issuer different: issuer=", issuer,
                ", data.issuer=", saved_issuer)
        end

        local saved_name_id = sess:get("name_id")
        if name_id ~= saved_name_id then
            ngx.log(ngx.WARN, "name_id different: name_id=", name_id,
                ", data.name_id=", saved_name_id)
        end

        local saved_session_index = sess:get("session_index")
        if session_index ~= saved_session_index then
            ngx.log(ngx.WARN, "session_index different: session_index=",
                session_index, ", data.session_index=", saved_session_index)
        end

        sess:destroy()

        local query_str, err = create_redirect(self.sign_key, {
            SAMLResponse = logout_response(opts.idp_uri, request_id, status, opts.sp_issuer),
            SigAlg = RSA_SHA_512_HREF,
            RelayState = "",
        })
        if err then
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
        ngx.log(ngx.INFO, "logout finish")

        return ngx.redirect(opts.idp_uri .. "?" .. query_str)
    else
        local status_code = saml.doc_status_code(doc)
        if status_code ~= saml.STATUS_SUCCESS then
            ngx.log(ngx.ERR, "IdP returned non-success status: ", status_code)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        sess:destroy()

        ngx.log(ngx.INFO, "logout finish")
        return ngx.redirect(opts.logout_redirect_uri or "/")
    end
end

local function logout(self, opts)
    local sess = session.start(self.session_config)
    local authenticated = sess:get("authenticated")

    if not authenticated then
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local query_str, err = create_redirect(self.sign_key, {
        SAMLRequest = logout_request(opts, sess:get("name_id"), sess:get("session_index")),
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
    obj.auth_protocol_binding_method = opts.auth_protocol_binding_method
    local cookie_secure, cookie_same_site
    if opts.auth_protocol_binding_method == "HTTP-POST" then
        cookie_secure = false
        cookie_same_site = "None"
    end
    obj.session_config = {
        cookie_name = "saml_session",
        secret = opts.secret,
        secret_fallbacks = opts.secret_fallbacks,
        cookie_secure = cookie_secure,
        cookie_same_site = cookie_same_site,
    }
    return obj
end

function _M.init(opts)
    return saml.init(opts)
end

return _M
