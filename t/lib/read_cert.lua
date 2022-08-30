local _M = {}

local function split(text, chunk_size)
    local s = {}
    for i=1, #text, chunk_size do
        s[#s+1] = text:sub(i, i + chunk_size - 1)
    end
    return s
end

function _M.read_cert(str)
    local t = split(str, 64)
    table.insert(t, 1, "-----BEGIN CERTIFICATE-----")
    table.insert(t, "-----END CERTIFICATE-----")
    return string.format(table.concat(t, "\n"))
end

local function read_whole_file(file)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end

function _M.read_cert_file(file)
    return _M.read_cert(read_whole_file(file))
end

return _M
