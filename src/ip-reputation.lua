-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

local http = require('socket.http')
local url = require('socket.url')
local ltn12 = require('ltn12')
local cjson = require('cjson')
local hawk = require('hawk')

local config = { -- config params set via configure
   base_url = nil,
   id = nil,
   key = nil,
   algorithm = 'sha256',
}

local computed_config = { -- config params computed from config
   host = nil,
   post = nil,
}

-- private function for parsing the port out of a URL
function get_port(parsed_url)
   if parsed_url['port'] then
      return parsed_url['port']
   elseif parsed_url['scheme'] and parsed_url['scheme'] == 'http' then
      return 80
   elseif parsed_url['scheme'] and parsed_url['scheme'] == 'https' then
      return 443
   else
      error('No scheme or port found for base_url.')
   end
end

-- sets client config values; must be called before making requests
-- example usage:
--
-- configure({
--    base_url = "http://localhost:8080", -- tigerblood service url w/o slash
--    id = "root", -- hawk ID
--    key = "toor", -- hawk key
-- })
--
function configure(new_config)
   config['base_url'] = new_config['base_url'];
   config['id'] = new_config['id'];
   config['key'] = new_config['key'];
   config['algorithm'] = new_config['algorithm'] or 'sha256';

   local parsed_base = url.parse(new_config['base_url'])
   computed_config['host'] = parsed_base['host']
   computed_config['port'] = get_port(parsed_base)
end


-- private function for making hawk-signed HTTP requests
function json_request(method, uri, body)
   local body_json = ''
   if body then
      body_json = cjson.encode(body)
   end

   local headers = {
      Authorization = hawk.header(
         config,
         {
            method = method,
            host = computed_config['host'],
            port = computed_config['port'],
            resource = uri,
         },
         {
            payload = body_json,
            content_type = 'application/json'
      }),
      Host = computed_config['host'] .. ':' .. computed_config['port'],
      ['Content-Type'] = 'application/json',
      ['Content-Length'] = #body_json,
   }

   local response = {}
   local r, code, resp_headers = http.request {
      method = method,
      url = config.base_url .. uri,
      headers = headers,
      source = ltn12.source.string(body_json),
      sink = ltn12.sink.table(response)
   }

   return {
      r = r,
      status_code = code,
      body = table.concat(response),
      headers = resp_headers,
   }
end

-- gets reputation for an IP
function get(ip)
  return json_request('GET', '/' .. ip)
end

-- records reputation for an IP
function add(ip, reputation)
  return json_request('POST', '/', {ip = ip, reputation = reputation})
end

-- updates an IP's reputation
function update(ip, reputation)
   return json_request('PUT', '/' .. ip, {reputation = reputation})
end

-- removes an IP's reputation
function remove(ip)
  return json_request('DELETE', '/' .. ip)
end

-- records a violation from an IP
function send_violation(ip, violation_type)
   return json_request('PUT', '/violations/' .. ip, {ip = ip, violation = violation_type})
end

return {
   configure = configure,
   get = get,
   add = add,
   update = update,
   remove = remove,
   send_violation = send_violation,
   hawk = hawk,
}
