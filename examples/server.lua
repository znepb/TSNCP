-- A simple server that echos what is sent to it with the event "echo"

local server = require("server-bundle")
local keys = require("keys")
local certificate = require("certificate")

local newServer = server:new(certificate, keys.public, keys.private)

newServer:addSecuredEvent("echo", function(data, id)
  return {
    message = "echoReply",
    data = data
  }
end)

newServer:start()