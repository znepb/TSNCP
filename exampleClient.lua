local handshake = require(".utils.handshake")
local common = require(".utils.common")

-- Handshakes with the server. Data is a table containing:
--[[
  {
    publicKey: The local public key
    privateKey: The local private key
    remotePublicKey: The public key of the remote server
    id: This session's ID
    shared: The secret shared between the server and client
  }
]]

local start = os.epoch('utc')

local data = handshake("echo.tol")
print("ID", data.id)
print("Handshake took " .. os.epoch('utc') - start .. " msec")

term.write("Enter some text to echo: ")
local text = read()

local response = common.secureTransmit(10000, data.privateKey, data.remotePublicKey, data.id, data.shared, {
  message = "echo",
  data = {
    text = text
  }
}, "echo.tol")

print("Response from server:", response.data.text)
