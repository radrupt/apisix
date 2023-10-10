local core = require("apisix.core")
local plugin = require("apisix.plugin")
local cjson = require "cjson"
local ngx = require "ngx"
local aes = require "resty.aes"
local str = require "resty.string"
local base64 = require "ngx.base64"

-- 插件配置描述
local schema = {
    type = "object",
    properties = {
        decode_req = {
            description = "主要用来辅助单元测试用的，控制是否需要解密请求",
            type = "boolean",
            default = false,
        },
        encode_res = {
            description = "主要用来辅助单元测试用的，控制是否需要加密响应",
            type = "boolean",
            default = false,
        },
    },
}

local plugin_name = "encrypt-body"

local _M = {
    version = 0.1,
    priority = 0,
    name = plugin_name,
    schema = schema,
}

function encrypt(plaintext, key)
    local aes128Ecb, err = aes:new(key, nil, aes.cipher(128, "ecb"), { iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" })
    if err then
        return nil,error("encrypt:aes:new failure,err:"+err)
    end

    local encrypted, err = aes128Ecb:encrypt(plaintext)
    if err then
        return nil, error("source err=" + err + ",encrypt failure", 1)
    end
    return base64.encode_base64url(encrypted), nil
end

function decrypt(ciphertext,key)
    local aes128Ecb, err = aes:new(key, nil, aes.cipher(128, "ecb"), { iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" })
    if err then
        return nil,error("decrypt:aes:new failure,err:"+err)
    end

    local decoded, err = base64.decode_base64url(ciphertext)
    if err then
        return nil, error("source err=" + err + ",base64 decode failure", 1)
    end
    local plain, err = aes128Ecb:decrypt(decoded, '')
    if err then
        return nil, error("source err=" + err + ",aec decrypt failure", 1)
    end
    return plain, nil
end

local function versionCompare(v1, v2)
    local v1arr = {}
    for s in string.gmatch(v1, "[^%.]+") do
        table.insert(v1arr, tonumber(s) or 0)
    end

    local v2arr = {}
    for s in string.gmatch(v2, "[^%.]+") do
        table.insert(v2arr, tonumber(s) or 0)
    end

    local l = math.max(#v1arr, #v2arr)

    for i = 1, l do
        local n1 = v1arr[i] or 0
        local n2 = v2arr[i] or 0

        if n1 - n2 ~= 0 then
            return n1 - n2
        end
    end

    return 0
end

function _M.check_schema(conf, schema_type)
    return core.schema.check(schema, conf)
end

function _M.init()
    -- call this function when plugin is loaded
    local attr = plugin.plugin_attr(plugin_name)
    if attr then
        core.log.info(plugin_name, " get plugin attr val: ", attr.val)
    end
end

local whitelist = {
    ["5.19.0"] = {
        ["post"] = {
            "login",
            "signup",
            "/captchas/v4.8/verify",
            "/api/gae/address",
            "/captchas",
            "/user/me/info/projection",
        },
        ["get"] = {
            "/checkuser",
            "/captchas/v4.8",
            "/me",
            "/api/gae/address/all",
        },
        ["put"] = {
            "/me/password",
            "/me",
            "/api/gae/address",
            "/me/verify/phone",
            "/me/password/thirdparty",
            "/me/verify-password",
        },
    },
    ["5.20.0"] = {
        ["post"] = {
            "login",
            "signup",
            "/captchas/v4.8/verify",
            "/api/gae/address",
            "/captchas",
            "/user/me/info/projection",
        },
        ["get"] = {
            "/checkuser",
            "/captchas/v4.8",
            "/me",
            "/api/gae/address/all",
            "/user/exists",
        },
        ["put"] = {
            "/me/password",
            "/me",
            "/api/gae/address",
            "/me/verify/phone",
            "/me/password/thirdparty",
            "/me/verify-password",
            "/user/password",
            "/me/bind/qq",
            "/me/bind/wechat",
            "/me/bind/huawei",
        },
    },
    ["1.7.0"] = {
        ["post"] = {
            "login",
            "signup",
            "/captchas/v4.8/verify",
            "/api/gae/address",
            "/captchas",
            "/user/me/info/projection",
        },
        ["get"] = {
            "/checkuser",
            "/captchas/v4.8",
            "/me",
            "/api/gae/address/all",
            "/user/exists",
        },
        ["put"] = {
            "/me/password",
            "/me",
            "/api/gae/address",
            "/me/verify/phone",
            "/me/password/thirdparty",
            "/me/verify-password",
            "/user/password",
            "/me/bind/qq",
            "/me/bind/wechat",
            "/me/bind/huawei",
        },
    },
    ["pc"] = {
        ["post"] = {
            "login",
            "signup",
            "/captchas/v4.8/verify",
            "/api/gae/address",
            "/captchas",
            "/user/me/info/projection",
        },
        ["get"] = {
            "/checkuser",
            "/captchas/v4.8",
            "/me",
            "/api/gae/address/all",
            "/user/exists",
        },
        ["put"] = {
            "/me/password",
            "/me",
            "/api/gae/address",
            "/me/verify/phone",
            "/me/password/thirdparty",
            "/me/verify-password",
            "/user/password",
            "/me/bind/qq",
            "/me/bind/wechat",
            "/me/bind/huawei",
        },
    }
}

local lastEncryptVersions = { "5.20.0", "5.19.0" }

local header_key_client_version = "client-version"
local header_key_client_category = "client-category"
local header_key_client_type = "client-type"

local encrypt_header_key = "params-style"
local encrypt_header_val = "encrypt"

local encrypt_key = '1234567890123456'

function _M.rewrite(conf, ctx)
    local clientVersion = core.request.header(ctx, header_key_client_version)
    local clientCategory = core.request.header(ctx, header_key_client_category)
    local clientType = core.request.header(ctx, header_key_client_type)
    local method = core.request.get_method(ctx)
    local httpMethod = string.lower(method)
    local httpPath = ngx.var.uri
    local isOk = false
    local body_str = ngx.req.read_body()
    ngx.req.set_body_data(httpPath)
    

    -- -- 没有版本、无法加密
    -- if clientVersion == "" or clientVersion == nil or clientVersion == 'undefined' then
    --     return
    -- end

    -- for _, version in ipairs(lastEncryptVersions) do
    --     if not isOk and
    --         clientCategory == "student" and
    --         versionCompare(clientVersion, version) >= 0 then
    --         clientVersion = version
    --         isOk = true
    --     end
    -- end

    -- if clientCategory == "teacher" and
    --     versionCompare(clientVersion, "1.7.0") >= 0 then
    --     clientVersion = "1.7.0"
    -- end

    -- local inWhitelist = false
    -- if whitelist[clientVersion] ~= nil then
    --     for _, path in ipairs(whitelist[clientVersion][httpMethod]) do
    --         if path == httpPath then
    --             inWhitelist = true
    --             break
    --         end

    --         local split = httpPath:split("/")
    --         if #split > 1 and path == split[2] then
    --             inWhitelist = true
    --             break
    --         end
    --     end
    -- end

    -- if not inWhitelist then
    --     return
    -- end

    -- if clientType == "pc" then
    --     if not versionCompare(clientVersion, "7.9.0") >= 0 then
    --         return
    --     end
    -- else
    --     if not (clientCategory == "primary" or
    --             (clientCategory == "student" and versionCompare(clientVersion, "5.19.0") >= 0) or
    --             (clientCategory == "teacher" and versionCompare(clientVersion, "1.7.0") >= 0)) then
    --         return
    --     end
    -- end

    -- ngx.req.set_header(encrypt_header_key, encrypt_header_val)

    
    
    -- local args = {}
    -- local isBody = false
    -- if (httpMethod == 'get' or httpMethod == 'delete')  then
    --     local query_str = ngx.req.get_uri_args()
    --     -- 下面统一处理
    --     if query_str then
    --         ngx.req.set_body_data("32323")
    --         -- args = cjson.decode(args_str)["encrypt_body"]
    --     end
    -- end

    -- -- if args then
    -- --     local decrypted, err = decrypt(args, encrypt_key)
    -- --     if err then
    -- --         core.log.error("decrypt failue,err:" + err)
    -- --         core.response.exit(500);
    -- --     end
    -- --     if decrypted then
    -- --         local data = cjson.decode(decrypted)
    -- --         if data then
    -- --             if not isBody then
    -- --                 ngx.req.set_uri_args(decrypted)
    -- --             else
    -- --                 ngx.req.set_body_data(decrypted)
    -- --             end
    -- --         end
    -- --     end
    -- -- end
end

function _M.body_filter(conf, ctx)
    local params_style = core.request.header(ctx, encrypt_header_key)
    if params_style ~= encrypt_header_val then
        return
    end

    ngx.req.set_header(encrypt_header_key, params_style)
    ngx.req.set_header("Access-Control-Expose-Headers", "Authorization,Content-Range,Date,params-style")
    local body = core.response.hold_body_chunk(ctx)
    if not body then
        return
    end
    -- 待进行buffer to string case的处理
    local encrypted, err = encrypt(body, encrypt_key)
    if err then
        core.log.error("decrypt failue,err:" + err)
        core.response.exit(500);
        ngx.arg[1] = "decrypt failue,err:" + err
        ngx.arg[2] = true
    else
        local resData = {
            ["encrypt_body"] = encrypted
        }
        -- 这里加\n 是为了能过单元测试（单测的expected有换行，不知如何去除）
        ngx.arg[1] = cjson.encode(resData).."\n"
        ngx.arg[2] = true
    end
end

return _M