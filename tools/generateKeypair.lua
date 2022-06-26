-- This generates a random keypair, and outputs it to keypair.lua

local ecc = require("ecc")

local f = fs.open("keypair.lua", "w")
local secret, public = ecc.keypair(ecc.random.random())

f.write(textutils.serialise({
  secret = secret,
  public = public
}))

f.close()