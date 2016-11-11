# luvit-jwt

A Simple [JWT][] library for luvit

JSON Web Tokens are an open, industry standard RFC 7519 method for representing
claims securely between two parties.

This library makes it easy to create and consume such tokens.  Currently only
the `none` and `HS256` algorithms are supported, but more can be easily added
if there is interest.  Simply file an issue with the algorithm you need.

## JWT.sign(payload, options) -> token

This function is used to create JWT tokens.

```lua
local JWT = require('jwt')

local sharedSecret = "w5zo4ffbizy7etsfgeewmi-ekiov4rdcm75dkbufgiv34n29"

local token = JWT.sign({
  sub = "tim@creationix.com", -- Claim the user subject
  iss = "https://luvit.io/"   -- Issued by luvit.io
}, {
  expiresIn = 60 * 60, -- Expires in an hour
  secret = sharedSecret
})
```

This has the following options.

 - `options.algorithm` - Signature algorithm to use.  Can be `none` for no
   signature. Defaults to `HS256` or `RS256` depending on `options.secret` or
   `options.key`)
 - `options.secret` - Shared secret for HMAC signature mode (`HS*`).
 - `options.key` - Private RSA key for RSA mode (`RS*`).
 - `options.expiresIn` - Set `payload.exp` to now plus this many seconds.
 - `options.notBefore` - Set `payload.nbf` to now plus this many seconds.
 - `options.noTimestamp` - Disable automatic `payload.iat` timestamp if true.
 - `options.audience` - Becomes `payload.aud`
 - `options.issuer` - Becomes `payload.iss`
 - `options.jwtid` - Becomes `payload.jti`
 - `options.subject` - Becomes `payload.sub`
 - `options.header` - Optionally set a manual header.
 - `exp`, `nbf`, `aud` and `sub` can also appear directly in payload instead.

## JWT.verify(token, options) -> payload

Verify a token.  Options here is a subset of the `JWT.sign` options.  In
particular it cares about `options.key`, `options.secret` and
`options.algorithm`.

```lua
-- Continued from above
local payload = assert(JWT.verify(token, {
  secret = sharedSecret
}))
```

Verify will generally not throw an error if the token is invalid in any way.
Rather it will return `nil` followed by an error message.

[JWT]: https://jwt.io/
