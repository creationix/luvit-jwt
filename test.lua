local PKEY = require('openssl').pkey
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

local privateKey = PKEY.read([[
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtp0N1i/1J53r0pAkGTn8X6wKdXgcDHv4lDWxrNc9v98Qhg+i
xi3KFwku3pCmFYuVRqCZtqYQF/c+cEDPAolkHsqT2RqUsBmDSF5nZf4zAyOo4B25
EDO36rB2oWkd9rcaw6oGElymolzjtV2tTtNEwQHhFJfr2MeCcE2pIPra4P5p2Ug1
mFKrpGvF9yN8ACtEYHdiZyx637j9ESB5531otfqBWfUguMZWcFdikpwQa1NSi57l
75Ayig0ksPcq2RclJuumqrtgPJYEN0aYSsI50JQPwL0ZWrgi02zt7KYeHY/NoWbz
GPjHRNUM4n1S0wS2963wjF/3M5pAzxrtIzb5wwIDAQABAoIBACH1RKxu0JzkXgUS
7tOOF+NGn89GXZjouMn+ziKBCCeU+IKlh7RosWrlN0UGCwx4n3K5zLvNV7LNNFw1
gQlMuUSMkT/PFJVGuUYM4Bd0VNIhoHbEsDRWGb5XwEe1v2+wjxaRmH1zoz0QHvwM
Bn1hBikKC2wD8ESonRX7KxdJ7sfl1ycxKEYDcdahyNsgqIXnkaJUXIFnPo+WVGsL
5EcFlA4keeQuUulj29KHbeEX+sOKLGSLutoyYD7cSCRh6EDtf9QiC8SbsS5kYPo1
f1LbTxmZJ7dH5HkQBQRZ5h8iEeMu/+YjdhcWVGQGKocWlKocQvsJAkEf8vWyFkcQ
UByLW5ECgYEA2ymCdO5Wi0pe5NcSw4zm+ZGZHddjDxtHc5WEsf9qqBgOv0krpemZ
1FynWPWTNr4wgM1aQi57vLnsYxQueUcfsEOlMstZ2cb/teXz8/zH3ljcUfjnuadw
VScZwoLX0BRrbyd5C2Xu6yjWeRlovL3Tl0HZp/sn44lkqE9XX4t1NjkCgYEA1U7d
hYdPVY7uKIwmvfvopxxL4WsYNxZ+xUzM+FkhabiQ/Y/ORGOF4lbWqLOpNohrOnbI
O9wxoNQLhOmEjs8JRlijZ/2OkQYIl319Cq4sDvHcue1mgmc1Gz2P41HwZamBERZa
dY/zHwxKkLv4bCPrLAjYWkBiO+t5VzAzqIvmT9sCgYBEQMcqF1fIhV7MMdbcI7OD
Ib7ntj5ZZAt6iaQLsxnKQ8PD+sunHfsUUc6kO8afE9gTJODpH4TVn6loqc5XYrkR
sd9u1DmlQv477eNtptmv+0iSFsxD20t2mXjCRPFlEhbrRQXDcPlZLxysFieyMAQH
ZTCdyfAAQregWyVA0jOssQKBgAcCwpEi816Shg1bHeLcprbnXS8ZgAA/gwclEQ+Q
jmKVKF7NHTBuPPZFeGSvEv6x2SRgxxAAmrj4fzBtJGg1Mc7YFvbSBJ+LnTitbTCu
rNAI7wJFZTsf/UTZ7yK/jLEqsw1GuM5oXstEcibzpqSXQaF+4O2GdDQX9zMAaJI/
luBFAoGBAMTY5pC9XJlmUv3rmWS78kNfDMQklo7sOlVd7dADQkt1R29auB9QAn0I
HU7gfOGsA7GmIAkkiv+AtY+It9Vn7jZU3tJvs/YBLnCeWXAv9npkblxARfMTHFkE
zT08SGK7Ex4OXKwwK64kCQqmU1Tt0vjxufyPyhjPAMwpdEsomiIu
-----END RSA PRIVATE KEY-----
]], true)

local token2 = sign({
  sub = "tim@creationix.com",
  iss = "https://luvit.io/"
}, {
  expiresIn = 60 * 60, -- Expires in an hour
  privateKey = privateKey
})

p(token2)

p(verify(token2, {
  privateKey = privateKey
}))

-- TODO: implement code to verify signature with only public key
