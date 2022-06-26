-- A simple server that echos what is sent to it with the event "echo", and sends a message "whatup dawg? " .. os.epoch("utc") to all clients every 5 seconds.

local server = require("server")
local keys = require("keys")
local certificate = require("certificate")

local newServer = server:new(certificate, keys.public, keys.private)

newServer:addSecuredEvent("echo", function(data, id)
  return {
    message = "echoReply",
    data = data
  }
end)

parallel.waitForAll(function()
  newServer:start()
end, function()
  while true do
    for i, v in pairs(newServer:getSessions()) do
      newServer:transmitSecure({
        message = "basic",
        data = {
          text = "whatup dawg? " .. os.epoch("utc")
        }
      }, i)
    end
    sleep(5)
  end
end)