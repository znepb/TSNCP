local ecc = require("utils.ecc")
local common = require("utils.common")
local getSignature = require("utils.getSignature")
local standardPort = 10000

return function(server)
  local result

  xpcall(function()
    local certificate = getSignature(server)
    local response
    local attempts = 0
    local private, public = ecc.keypair(ecc.random.random())
    print("Retrieved certificate from central server")

    repeat
      response = common.transmitGetResp(standardPort, certificate.publicKey, "hello", {
        public = public
      }, server)
      attempts = attempts + 1
    until common.compareCertificate(response.certificate, certificate) or attempts >= common.RECONNECTION_MAX_ATTEMPTS

    if common.compareCertificate(response.certificate, certificate) then
      print("Validation success! ID is", response.id)

      local id, remotePublic = response.id, response.public
      local sharedSecret = ecc.exchange(private, response.public)

      local response = common.secureTransmit(standardPort, private, response.public, response.id, sharedSecret, {
        message = "verify"
      }, server)

      result = {
        publicKey = public, 
        privateKey = private, 
        remotePublicKey = remotePublic, 
        id = id, 
        shared = sharedSecret
      }

      print("Verified with remote server!")
    else
      error("Validation failed!")
    end
  end, function(err)
    printError(err)
  end)

  if result then
    return result
  end
end