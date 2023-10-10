#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
use t::APISIX 'no_plan';

repeat_each(1);
no_long_string();
no_root_location();
no_shuffle();
log_level('debug');
run_tests;

__DATA__

=== TEST 1: sanity
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.yangcong-encrypt")
            local ok, err = plugin.check_schema({i = 1, s = "s", t = {1}})
            if not ok then
                ngx.say(err)
            end

            ngx.say("done")
        }
    }
--- request
GET /t
--- response_body
done

=== TEST 2: enable yangcong-encrypt plugin using admin api
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                        "plugins": {
                            "yangcong-encrypt": {
                                "i": 11,
                                "ip": "127.0.0.1",
                                "port": 1981
                            }
                        },
                        "upstream": {
                            "nodes": {
                                "127.0.0.1:1980": 1
                            },
                            "type": "roundrobin"
                        },
                        "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- request
GET /t
--- response_body
passed

=== TEST 3: 单独测试 yangcong-encrypt plugin body_filter 加密逻辑，待增加更多的加密case
--- config
    location /t {
        content_by_lua_block {
            -- trigger body_filter_by_lua_block, 需要保留content_by_lua_block 才能触发body_filter_by_lua_block
            -- Nginx uses a separate buf to mark the end of the stream,
            -- hence when ngx.arg[2] == true, ngx.arg[1] will be equal to "".
            -- To avoid something unexpected, here we add a test to verify
            -- this situation via mock.
            local core = require("apisix.core")
            core.request.set_header(ngx.ctx, "params-style", "encrypt")
            local t = ngx.arg
            local metatable = getmetatable(t)
            local count = 0
            setmetatable(t, {__index = function(t, idx)
                return '{"status":"OK"}'
            end,
            __newindex = metatable.__newindex})
        }
        body_filter_by_lua_block {
            local plugin = require("apisix.plugins.yangcong-encrypt")
            local core = require("apisix.core")
            -- To avoid something unexpected, here we add a test to verify
            ngx.ctx._plugin_name = "test"
            -- core.response.set_header('Content-Type', 'application/json; charset=utf-8')
            plugin.body_filter({}, ngx.ctx)
        }
    }
--- request
GET /t
--- response_body
{"encrypt_body":"VNWkIy4EPJnB6AIO-ogODg"}


=== TEST 4: 单独测试 yangcong-encrypt plugin rewrite 解密逻辑，待增加更多的解密case
--- config
    location /t {
        rewrite_by_lua_block {
            local plugin = require("apisix.plugins.yangcong-encrypt")
            ngx.ctx._plugin_name = "test"
            plugin.rewrite({}, ngx.ctx)
        }
        content_by_lua_block {
            local core = require("apisix.core")
            local body = core.request.get_body()
            ngx.say(body)
        }
    }
--- request
GET /t
--- response_body
32323
