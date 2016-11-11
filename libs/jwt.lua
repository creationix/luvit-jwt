--[[lit-meta
  name = "creationix/jwt"
  description = "JSON Web Token for Luvit"
  tags = {"sso", "oauth", "jwt"}
  version = "1.0.0"
  license = "MIT"
  author = { name = "Tim Caswell" }
]]


local HMAC = require('openssl').hmac
local JSON = require('json')
local BASE64 = require('base64url')
local jsonStringify = JSON.stringify
local jsonParse = JSON.parse
local base64Encode = BASE64.encode
local base64Decode = BASE64.decode

local supportedAlgorithms = {
  HS256 = true,
  RS256 = true,
  none = true
}

local function normalizeAlgorithm(options)
  -- Logic to try to guess and/or validate algorithm
  assert(not (options.secret and options.key),
    "key and secret are exclusive options")
  local algorithm = options.algorithm
  if options.secret then
    if not algorithm then
      algorithm = "HS256"
    end
    assert(string.find(algorithm, "^HS"),
      "Secret is only used for HS* algorithms")
  end
  if options.key then
    if not algorithm then
      algorithm = "RS256"
    end
    assert(string.find(algorithm, "^RS"),
      "key is only used for RS* algorithms")
  end
  assert(algorithm, "you must set algorithm, or key or secret")
  assert(type(algorithm) == "string",
    "Algorithm must be a string")
  assert(supportedAlgorithms[algorithm], "Sorry, not a supported algorithm")
  return algorithm
end

local function calculateSignature(message, algorithm, options)
  if algorithm == "none" then
    return ""
  elseif algorithm == "HS256" then
    return base64Encode(
      HMAC.hmac("sha256", message, options.secret, true)
    )
  elseif algorithm == "RS256" then
    error "TODO: Implement RSA signing"
  end
end

-- options.algorithm (default: HS256 or RS256 depending on secret or key)
-- options.expiresIn (ms till expiration)
-- options.notBefore (ms till valid)
-- options.audience
-- options.issuer
-- options.jwtid
-- options.subject
-- options.noTimestamp
-- options.header
-- options.secret (for HS*)
-- options.key (for RS*)
-- exp, nbf, aud and sub can also appear in payload instead
local function sign(payload, options)
  assert(payload, "Missing payload")
  assert(options, "Missing options")

  local algorithm = normalizeAlgorithm(options)

  local header = options.header or {
    typ = "JWT",
    alg = algorithm
  }

  -- Registered Claim Names
  local now = os.time()
  local data = {
    iss = options.issuer,
    sub = options.subject,
    aud = options.audience,
    jti = options.jwtid,
  }
  if options.expiresIn then
    assert(type(options.expiresIn) == "number",
      "expiresIn should be ms from now")
    data.exp = now + options.expiresIn
  end
  if options.notBefore then
    assert(type(options.notBefore) == "number",
      "notBefore should be ms from now")
    data.nbf = now + options.notBefore
  end
  if not options.noTimestamp then
    data.iat = now
  end

  for claim, value in pairs(payload) do
    assert(data[claim] == nil, "Payload conflict")
    data[claim] = value
  end

  local message =
    base64Encode(jsonStringify(header)) ..
    "." ..
    base64Encode(jsonStringify(data))

  return message .. '.' .. calculateSignature(message, algorithm, options)
end

local function verify(token, options)
  local algorithm = normalizeAlgorithm(options)
  local message, signature = assert(
    string.match(token, "^([^.]+%.[^.]+)%.([^.]*)$"))
  local expected = calculateSignature(message, algorithm, options)
  if expected ~= signature then
    return nil, "Signature validation failure"
  end
  local header, payload = string.match(message, "^([^.]+)%.([^.]+)$")
  header = jsonParse(base64Decode(header))
  if header.alg ~= algorithm then
    return nil, "Algorithm mismatch in header"
  end
  payload = jsonParse(base64Decode(payload))
  local now = os.time()
  if payload.exp and payload.exp <= now then
    return nil, "Token expired"
  end
  if payload.nbf and now < payload.nbf then
    return nil, "Token not valid yet"
  end

  return payload
end

return {
  sign = sign,
  verify = verify
}
