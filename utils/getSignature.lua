local ecc = require("utils.ecc")
local common = require("utils.common")

local signServerPublic = {}
local signServerPort = 12345

return function(name)
  return common.transmitGetResp(signServerPort, signServerPublic, "retrieveSignature", { signature = name }).certificate
end