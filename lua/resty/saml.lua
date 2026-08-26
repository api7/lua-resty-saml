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

-- The endpoint the IdP delivers the response to. A configured value wins over
-- the one assembled from request headers, which the requester can steer, and it
-- is what an SP behind a proxy that rewrites neither scheme nor host needs.
-- The same value is announced to the IdP and enforced on the way back, so the
-- two cannot drift.
local function sp_acs_url(opts)
    return opts.sp_acs_url or saml_get_redirect_uri(opts.login_callback_uri)
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

local function authn_request(opts, request_id)
    return interp(AUTHN_REQUEST, {
        acs_url = sp_acs_url(opts),
        destination = opts.idp_uri,
        issue_instant = os.date("!%Y-%m-%dT%TZ"),
        issuer = opts.sp_issuer,
        uuid = request_id,
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

-- request_uri is where to return once the IdP answers. It defaults to what is
-- being asked for, and is passed in when a login is restarted from somewhere
-- else, where ngx.var.request_uri is that somewhere else.
local function login(self, opts, request_uri)
    local sess = session.start(self.session_config)

    local authenticated = sess:get("authenticated")
    local expires = sess:get("expires")
    local expired = false
    if type(expires) == "number" then
        local delta = expires - ngx.time()
        if delta < 0 then
            expired = true
        end
    end

    if authenticated and not expired then
        return {
            authenticated = authenticated,
            name_id = sess:get("name_id"),
            session_index = sess:get("session_index"),
            attrs = sess:get("attrs"),
            issuer = sess:get("issuer"),
        }
    end

    local state = uuid.generate_v4()
    request_uri = request_uri or ngx.var.request_uri
    -- kept so the callback can tell the answer to this request from the answer
    -- to some other one
    local request_id = generate_saml_id()

    sess:set("saml_state", state)
    sess:set("saml_request_id", request_id)
    sess:set("request_uri", request_uri)
    sess:save()

    local query_str, err = create_redirect(self.sign_key, {
        SAMLRequest = authn_request(opts, request_id),
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

-- Days since 1970-01-01 for a civil date. os.time reads its table as local
-- time, which would shift every SAML timestamp by the machine's offset.
local function days_from_civil(year, month, day)
    if month <= 2 then
        year = year - 1
    end
    local era = math.floor(year / 400)
    local year_of_era = year - era * 400
    local day_of_year = math.floor((153 * ((month + 9) % 12) + 2) / 5) + day - 1
    local day_of_era = year_of_era * 365 + math.floor(year_of_era / 4)
        - math.floor(year_of_era / 100) + day_of_year
    return era * 146097 + day_of_era - 719468
end

local function parse_iso8601_utc_time(str)
    -- NOTE: We accept only 'Z' for timezone.
    -- Anchored at both ends, so a year the four-digit field cannot hold is
    -- refused rather than read from part way in: xs:dateTime allows a leading
    -- minus for BCE, and an unanchored match starts after it and turns 9999 BCE
    -- into 9999 CE. A fractional second is read and truncated towards the past.
    local year_s, month_s, day_s, hour_s, min_s, sec_s =
        str:match('^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)%.?%d*Z$')
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
    return days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec
end


-- Values lifted out of the IdP's document end up in the error log, which is
-- read a line at a time. XML folds a literal newline inside an attribute to a
-- space, but a character reference survives that, and the Response wrapper is
-- not covered by the signature, so its Destination is whatever the sender
-- typed. Escape rather than trust any of it to stay on one line.
-- Every value read out of a SAML message goes through here on its way to a log,
-- whether or not a signature covers it and whichever message it came from. The
-- rule is the value's origin, not its type: an attribute the schema constrains
-- today is one schema revision away from carrying anything.
local function loggable(value)
    return (tostring(value):gsub("%c", function(c)
        return string.format("\\x%02X", c:byte())
    end))
end


-- A signature says the message came from the IdP. It does not say the assertion
-- is still good, that it was issued for this SP, or that it may be presented
-- here. Those live in the assertion's own Conditions and SubjectConfirmation,
-- and are checked below.
--
-- A constraint the IdP left out is not invented: an IdP that sends no
-- AudienceRestriction keeps working. One the IdP did send is enforced, which is
-- what stops an assertion minted for another SP in the same federation.
local DEFAULT_CLOCK_SKEW = 60

-- how long an assertion that sets no expiry of its own is remembered
local DEFAULT_REPLAY_TTL = 600

-- and how long any assertion is remembered at most, whatever it claims. An
-- assertion valid for years would pin a slot the dict never reclaims, and
-- nobody is still trying to complete that login a day later.
local MAX_REPLAY_TTL = 86400

local function time_bounds_ok(not_before, not_on_or_after, now, skew)
    local opens, closes, err

    if not_before then
        opens, err = parse_iso8601_utc_time(not_before)
        if not opens then
            return false, "carries an unreadable NotBefore " .. not_before .. ": " .. err
        end
    end

    if not_on_or_after then
        closes, err = parse_iso8601_utc_time(not_on_or_after)
        if not closes then
            return false, "carries an unreadable NotOnOrAfter " .. not_on_or_after .. ": " .. err
        end
    end

    -- A window that opens after it closes is empty on every clock, so the skew
    -- allowance has no say in it: without this, each end on its own looks
    -- acceptable and an inversion of up to twice the allowance passes. Strictly
    -- later rather than not earlier, since a fractional second is truncated away
    -- and two instants inside one second read as equal.
    if opens and closes and opens > closes then
        return false, "opens at " .. not_before .. " and closes at " .. not_on_or_after
    end

    if opens and now + skew < opens then
        return false, "is not valid before " .. not_before
    end

    if closes and now - skew >= closes then
        return false, "is not valid on or after " .. not_on_or_after
    end

    return true
end


local function audience_accepted(accepted, audiences)
    for _, audience in ipairs(audiences) do
        for _, expected in ipairs(accepted) do
            if expected == audience then
                return true
            end
        end
    end
    return false
end


-- The assertion may be presented to whoever the Recipient names, for as long as
-- the confirmation data allows. Several confirmations can be offered and any one
-- of them being satisfiable is enough.
local function confirmation_ok(confirmation, expected, now, skew)
    -- Recipient is the only thing a confirmation says about where the assertion
    -- may be presented, so it has to be there. An absent one, an empty
    -- SubjectConfirmationData, and one carrying nothing but conditions that
    -- happen to hold all say the same nothing, and any of them would otherwise
    -- answer in place of a sibling that binds the assertion somewhere else.
    if confirmation.recipient ~= expected.acs_url then
        return false
    end
    -- Checked when the IdP names a request, and not demanded. Naming one is
    -- what profile 4.1.4.2 asks of an IdP answering an AuthnRequest, so an IdP
    -- that leaves it out is already out of spec, and refusing that trades a
    -- working login for protection against somebody else's misconfiguration.
    -- Nothing an attacker sends produces the shape: the value sits inside the
    -- signature, so it cannot be stripped from a captured assertion.
    if confirmation.in_response_to and confirmation.in_response_to ~= expected.request_id then
        return false
    end
    return (time_bounds_ok(confirmation.not_before, confirmation.not_on_or_after, now, skew))
end


-- Every top-level assertion the verified signature left in the document is one
-- the readers draw identity from, so every one of them has to hold up.
local function assertions_acceptable(opts, assertions, expected, now)
    local skew = opts.clock_skew or DEFAULT_CLOCK_SKEW
    local accepted = opts.sp_audiences or { opts.sp_issuer }

    for _, assertion in ipairs(assertions) do
        local where = "assertion " .. tostring(assertion.id) .. " "

        -- SAML Core 2.5.1: a condition the SP cannot satisfy leaves the
        -- assertion Indeterminate, which is not a licence to use it
        if assertion.unknown_condition then
            return false, where .. "carries a condition this SP cannot satisfy: " ..
                assertion.unknown_condition
        end

        local ok, err = time_bounds_ok(assertion.not_before, assertion.not_on_or_after, now, skew)
        if not ok then
            return false, where .. err
        end

        -- each AudienceRestriction narrows the audience separately, so this SP
        -- has to be named in all of them
        for _, restriction in ipairs(assertion.audience_restrictions) do
            if not audience_accepted(accepted, restriction) then
                return false, where .. "is restricted to " .. table.concat(restriction, ", ")
            end
        end

        local confirmations = assertion.subject_confirmations
        if #confirmations > 0 then
            local satisfiable = false
            for _, confirmation in ipairs(confirmations) do
                if confirmation_ok(confirmation, expected, now, skew) then
                    satisfiable = true
                    break
                end
            end
            if not satisfiable then
                return false, where .. "offers no subject confirmation this SP can satisfy"
            end
        end
    end

    return true
end

-- An Issuer is a string in the XML schema, so libxml2 hands back the element
-- text as written, indentation included. Compare what the two sides mean.
local function trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

-- Read idp_issuers once, into a set. A shape the callback cannot walk is a
-- configuration mistake, and finding out at construction names the option,
-- where finding out per request is a 500 or a blanket refusal that blames the
-- IdP. An empty list stays legal and means what it says: nobody is expected.
local function issuer_set(issuers)
    if issuers == nil then
        return nil
    end

    local invalid = "idp_issuers must be a list of strings"
    if type(issuers) ~= "table" then
        error(invalid, 3)
    end

    local set, count = {}, 0
    for i, issuer in pairs(issuers) do
        if type(i) ~= "number" or i % 1 ~= 0 or i < 1 or type(issuer) ~= "string" then
            error(invalid, 3)
        end
        set[trim(issuer)] = true
        count = count + 1
    end
    -- a gap would leave the entries past it unreachable to ipairs
    if count ~= #issuers then
        error(invalid, 3)
    end
    return set
end

-- A valid signature says the message came from the configured key. It does not
-- say which IdP that key speaks for, so pin the issuer when the caller names
-- the ones it expects. No list keeps the previous behaviour; a list nothing
-- matches, an empty one included, admits nobody.
--
-- Every assertion is weighed, not just the one the issuer is taken from: a
-- response may legitimately carry several, and attributes are read from all of
-- them. A response whose issuers cannot be read vouches for nobody. Returns
-- what to name in the log alongside a refusal.
local function issuers_allowed(allowed, issuers)
    if allowed == nil then
        return true
    end
    if type(issuers) ~= "table" or #issuers == 0 then
        return false, "none readable"
    end
    for _, issuer in ipairs(issuers) do
        if not allowed[trim(issuer)] then
            return false, issuer
        end
    end
    return true
end

-- The last moment the checks above would still admit the assertion. They
-- combine as an AND: the Conditions window has to hold, and one confirmation
-- has to be satisfiable, so acceptance ends at whichever gives out first, the
-- Conditions close or the last confirmation still standing. Profile 4.1.4.2
-- puts a bearer assertion's expiry on its confirmation, so a Conditions
-- carrying nothing but an audience is the profile-minimal shape rather than an
-- odd one. Nil when nothing bounds acceptance, which replay_ttl stands in for.
--
-- Only confirmations that could ever confirm at this SP have a say, the same
-- ones confirmation_ok weighs, minus the clock: one naming another Recipient
-- or another request can never keep the assertion alive here, and one whose
-- close this parser will not take, a legal xs:dateTime carrying an offset
-- rather than Z, is unsatisfiable in the same way. Reading those as
-- contributing nothing rather than as unbounded matters in both directions,
-- since a confirmation naming no close never gives out: one satisfiable such
-- confirmation means the confirmations impose no limit at all, where the
-- earlier reading let a shorter sibling shrink the record below what an
-- absent sibling would have left it.
local function last_moment_usable(assertion, expected)
    local notes_close
    local unbounded = #assertion.subject_confirmations == 0
    for _, confirmation in ipairs(assertion.subject_confirmations) do
        local confirms_here = confirmation.recipient == expected.acs_url and
            (confirmation.in_response_to == nil or
                confirmation.in_response_to == expected.request_id)
        if confirms_here then
            if confirmation.not_on_or_after == nil then
                unbounded = true
            else
                local at = parse_iso8601_utc_time(confirmation.not_on_or_after)
                if at and (notes_close == nil or at > notes_close) then
                    notes_close = at
                end
            end
        end
    end
    if unbounded then
        notes_close = nil
    end

    local conditions_close
    if assertion.not_on_or_after then
        conditions_close = parse_iso8601_utc_time(assertion.not_on_or_after)
    end

    if conditions_close and notes_close then
        return math.min(conditions_close, notes_close)
    end
    return conditions_close or notes_close
end


-- An ID is unique only within the IdP that minted it, and idp_issuers takes a
-- list, so the two travel together. The SP name keeps instances sharing one
-- dict apart.
local function replay_key(opts, assertion)
    return opts.sp_issuer .. "|" .. (assertion.issuer or "") .. "|" .. assertion.id
end


-- A bearer assertion is good for one login. Nothing above stops the same one
-- being presented again inside its validity window, so its ID is remembered for
-- as long as it could still be used and a second presentation is refused.
--
-- Called at the last gate rather than beside the checks, so a login the rest of
-- the callback still refuses leaves the assertion unspent. A dict with no room
-- leaves this assertion untracked rather than evicting one that is still
-- protecting somebody else's login, which is what add would do on its own: the
-- entry it takes belongs to another user, the login it stops protecting is
-- theirs, and the warning is reported against whoever needed the space.
local function spend_assertions(dict, opts, assertions, expected, now)
    local skew = opts.clock_skew or DEFAULT_CLOCK_SKEW
    local spent = {}

    for _, assertion in ipairs(assertions) do
        if not assertion.id then
            return false, "an assertion without an ID cannot be tracked"
        end

        local ttl = opts.replay_ttl or DEFAULT_REPLAY_TTL
        local usable_until = last_moment_usable(assertion, expected)
        if usable_until then
            ttl = usable_until + skew - now
        end
        if ttl < 1 then
            ttl = 1
        elseif ttl > MAX_REPLAY_TTL then
            ttl = MAX_REPLAY_TTL
        end

        local key = replay_key(opts, assertion)
        local added, add_err = dict:safe_add(key, true, ttl)
        if added then
            spent[#spent + 1] = key
        elseif add_err == "exists" then
            -- this response authenticates nobody, so the assertions already
            -- taken from it are handed back rather than left spent
            for _, taken in ipairs(spent) do
                dict:delete(taken)
            end
            return false, "assertion " .. assertion.id .. " has been presented already"
        else
            ngx.log(ngx.ERR, "could not remember assertion ", loggable(assertion.id), " in ",
                opts.replay_dict, ": ", add_err,
                ", this login is not covered by replay tracking")
        end
    end

    return true
end


local function login_callback(self, opts)
    local sess = session.start(self.session_config)

    local saml_state = sess:get("saml_state")
    if not saml_state then
        ngx.log(ngx.ERR, "no session found or saml_state missing")
        ngx.exit(503)
    end

    local request_uri = sess:get("request_uri")

    -- A session minted before this SP kept the ID of the request it issued has
    -- nothing for the assertion to name, and refusing dead-ends a login that is
    -- genuinely this user's. Starting over gets a request that is remembered,
    -- and cannot repeat, since the session it mints carries one.
    local request_id = sess:get("saml_request_id")
    if not request_id then
        ngx.log(ngx.WARN, "session carries no request id, starting the login again")
        return login(self, opts, request_uri)
    end

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
        ngx.log(ngx.ERR, "IdP returned non-success status: ", loggable(status_code))
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local state = args.RelayState
    if state ~= saml_state then
        ngx.log(ngx.ERR, "state different: args.state=", loggable(state), ", state=", saml_state)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local expected = {
        acs_url = sp_acs_url(opts),
        request_id = request_id,
    }

    -- the Response is often left unsigned, so this only catches a stray answer;
    -- the binding that holds is the one inside the signed assertion below
    local in_response_to, in_response_to_err = saml.doc_in_response_to(doc)
    if in_response_to_err then
        ngx.log(ngx.ERR, "could not read what the response from IdP answers: ",
            in_response_to_err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    if in_response_to and in_response_to ~= expected.request_id then
        ngx.log(ngx.ERR, "response from IdP answers request ", loggable(in_response_to))
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local destination, destination_err = saml.doc_destination(doc)
    if destination_err then
        ngx.log(ngx.ERR, "could not read the destination of the response from IdP: ",
            destination_err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    if destination and destination ~= expected.acs_url then
        ngx.log(ngx.ERR, "response from IdP is addressed to ", loggable(destination))
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local assertions = saml.doc_assertions(doc)
    if not assertions then
        ngx.log(ngx.ERR, "could not read the assertions in response from IdP")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local now = ngx.time()
    local acceptable, reason = assertions_acceptable(opts, assertions, expected, now)
    if not acceptable then
        ngx.log(ngx.ERR, "response from IdP rejected: ", loggable(reason))
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local issuer = saml.doc_issuer(doc)
    local attrs = saml.doc_attrs(doc)
    local name_id = saml.doc_name_id(doc)
    local session_index = saml.doc_session_index(doc)

    local allowed, unexpected = issuers_allowed(self.idp_issuers, saml.doc_issuers(doc))
    if not allowed then
        ngx.log(ngx.ERR, "unexpected issuer in response from IdP: ", loggable(unexpected))
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- a success response the signature leaves without a readable assertion
    -- carries no identity, so there is nobody to authenticate as
    if not name_id then
        ngx.log(ngx.ERR, "no name id in response from IdP")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local session_expires = saml.doc_session_expires(doc)
    local expires
    if session_expires then
        expires, err = parse_iso8601_utc_time(session_expires)
        if err then
            -- ngx.say would commit the response, leaving ngx.exit unable to set
            -- a status and the caller a 200 carrying this string
            ngx.log(ngx.ERR, "unreadable SessionNotOnOrAfter ", loggable(session_expires),
                " in response from IdP: ", err)
            ngx.exit(500)
        end
        ngx.log(ngx.INFO, "login callback: session_expires=",
            os.date("!%Y-%m-%d %TZ", expires))
    end


    -- the last gate: everything that can still refuse this login has run, so
    -- the assertion is spent only where it actually authenticates somebody
    if self.replay_dict then
        local unused, used_reason = spend_assertions(self.replay_dict, opts, assertions,
            expected, now)
        if not unused then
            ngx.log(ngx.ERR, "response from IdP rejected: ", loggable(used_reason))
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end

    sess:set("authenticated", true)
    sess:set("name_id", name_id)
    sess:set("session_index", session_index)
    sess:set("attrs", attrs)
    sess:set("issuer", issuer)
    sess:set("expires", expires)

    -- clear temporary authentication state no longer needed after successful login
    sess:set("saml_state", nil)
    sess:set("saml_request_id", nil)
    sess:set("request_uri", nil)
    sess:save()

    ngx.log(ngx.INFO, "login finish: name_id=", loggable(name_id))

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
            ngx.log(ngx.WARN, "issuer different: issuer=", loggable(issuer),
                ", data.issuer=", saved_issuer)
        end

        local saved_name_id = sess:get("name_id")
        if name_id ~= saved_name_id then
            ngx.log(ngx.WARN, "name_id different: name_id=", loggable(name_id),
                ", data.name_id=", saved_name_id)
        end

        local saved_session_index = sess:get("session_index")
        if session_index ~= saved_session_index then
            ngx.log(ngx.WARN, "session_index different: session_index=",
                loggable(session_index), ", data.session_index=", saved_session_index)
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
            ngx.log(ngx.ERR, "IdP returned non-success status: ", loggable(status_code))
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
    obj.idp_issuers = issuer_set(opts.idp_issuers)
    -- read once, and raised rather than returned so a mistyped name names
    -- itself. A message built as an argument to assert is built on every
    -- successful call too, and a non-string one fails on the concatenation
    -- rather than on the option.
    if opts.replay_dict ~= nil then
        if type(opts.replay_dict) ~= "string" then
            error("replay_dict must be the name of a lua_shared_dict", 2)
        end
        obj.replay_dict = ngx.shared[opts.replay_dict]
        if obj.replay_dict == nil then
            error("no lua_shared_dict named " .. opts.replay_dict, 2)
        end
        -- it is half the key, and tostring would turn a missing one into the
        -- literal nil that two deployments would then share
        if type(opts.sp_issuer) ~= "string" then
            error("sp_issuer must be a string to track assertions", 2)
        end
        -- zero means never expire to lua_shared_dict, and a number arriving
        -- from YAML or the environment as text compares against nothing
        if opts.replay_ttl ~= nil and
            (type(opts.replay_ttl) ~= "number" or opts.replay_ttl < 1) then
            error("replay_ttl must be a positive number of seconds", 2)
        end
    end
    local cookie_secure, cookie_same_site
    if opts.auth_protocol_binding_method == "HTTP-POST" then
        cookie_secure = true
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
