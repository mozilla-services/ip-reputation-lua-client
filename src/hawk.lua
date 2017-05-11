-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.


local string = require("string")
local digest = require("openssl").digest
local hmac = require("openssl").hmac
local random = require("openssl").random
local mime = require("mime")


local function url_escape(s)
   return s:gsub('+', '-'):gsub('/', '_'):gsub('=', '')
end

-- returns a url safe base 64 nonce
local function nonce(size)
   return url_escape(mime.b64(random(size)))
end

-- openssl supports more just sha256 for now
local function supported_hash(algorithm)
   return algorithm == 'sha256'
end

-- hash the normalized hawk payload string
local function hash_payload(payload, algorithm, content_type)
   local normalized = 'hawk.1.payload'
   if content_type then
      normalized = normalized .. "\n" .. string.lower(content_type)
   end
   if payload then
      normalized = normalized .. "\n" .. payload
   end
   normalized = normalized .. "\n"

   if not supported_hash(algorithm) then
      error("Unsupported algorithm.")
   end

   return mime.b64(digest.digest(algorithm, normalized, true)) -- digest w/ true to return binary
end


-- returns a normalized
local function normalize_string(artifacts)
   local normalized = {
      'hawk.1.header',
      artifacts.ts,
      artifacts.nonce,
      string.upper(artifacts.method),
      artifacts.resource,
      string.lower(artifacts.host),
      artifacts.port
   }

   if artifacts.hash then
      table.insert(normalized, artifacts.hash)
   else
      table.insert(normalized, '')
   end

   if artifacts.ext then
      local ext = artifacts.ext:gsub('\\', '\\\\'):gsub('\n', '\\n')
      table.insert(normalized, ext)
   else
      table.insert(normalized, '')
   end

   if artifacts.app then
      table.insert(normalized, artifacts.app)
      if artifacts.dlg then
	 table.insert(normalized, artifacts.dlg)
      else
	 table.insert(normalized, '')
      end
   end

   return table.concat(normalized, "\n") .. "\n"
end

local function calculate_mac(credentials, artifacts)
   local normalized = normalize_string(artifacts)

   if not supported_hash(credentials.algorithm) then
      error("Unsupported algorithm.")
   end

   return mime.b64(hmac.hmac(credentials.algorithm, normalized, credentials.key, true)) -- true to return binary
end


-- returns a hawk Authorization header
local function header(credentials, artifacts, options)
   local mac_artifacts = {
      method = artifacts.method,
      host = artifacts.host,
      port = artifacts.port,
      resource = artifacts.resource,
      ts = artifacts.ts or os.time(),
      nonce = artifacts.nonce or nonce(6), -- six b64 chars
      app = artifacts.app,
      dlg = artifacts.dlg,
   }

   if options.ext then
      mac_artifacts.ext = options.ext
   end

   if options.payload then
      mac_artifacts.hash = hash_payload(options.payload, credentials.algorithm, options.content_type)
   end

   local mac = calculate_mac(credentials, mac_artifacts)

   local header = 'Hawk id="' .. credentials.id .. '", ts="' .. mac_artifacts.ts .. '", nonce="' .. mac_artifacts.nonce .. '"'

   if mac_artifacts.hash then
      header = header .. ', hash="' .. mac_artifacts.hash .. '"'
   end
   if options.ext then
      header = header .. ', ext="' .. mac_artifacts.ext .. '"'
   end

   header = header .. ', mac="' .. mac .. '"'

   return header
end

return {
   header = header
}
