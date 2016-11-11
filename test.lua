local JWT = require('jwt')
local verify = JWT.verify
local sign = JWT.sign

local sharedSecret = "w5zo4ffbizy7etsfgeewmi-ekiov4rdcm75dkbufgiv34n29"
local token = sign({
  sub = "tim@creationix.com",
  iss = "https://luvit.io/"
}, {
  expiresIn = 60 * 60, -- Expires in an hour
  secret = sharedSecret
})

p(token)

p(verify(token, {
  secret = sharedSecret
}))
