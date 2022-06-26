local port = 12345
local modem = peripheral.find("modem")

local ecc = require("common.ecc")
local key = require("keys")

modem.open(port)

local events = {
  retrieveCertificate = function(data)
    print(data.certificate)
    assert(data.certificate, ":Invalid certificate")

    local sigPath = ("/certificate/%s.lua"):format(data.certificate)
    assert(fs.exists(sigPath), ":Invalid certificate: not found")

    local f = fs.open(sigPath, "r")
    local data = textutils.unserialize(f.readAll())
    f.close()

    print("[SS NFO] Got certificate", data.name)

    return {
      status = "success",
      certificate = data
    }
  end
}

local function secureTransmit(t, i, d)
  local serialized = textutils.serialise(d)
  local signed = ecc.sign(key.private, serialized)
  
  modem.transmit(port, port, {
    v = 1,
    t = "resp",
    i = i,
    s = signed,
    d = serialized
  })
end

print("[SS NFO] Ready")
while true do
  local event, side, channel, replyChannel, message, distance = os.pullEvent("modem_message")
  print("[SS NFO] Request from " .. distance .. " blocks away")

  if channel == port and replyChannel == port then
    if type(message) == "table" then
      if message.v == 1 then
        if message.t and message.i and message.d then
          if events[message.t] then
            xpcall(function()
              local data = events[message.t](message.d)
              secureTransmit("resp", message.i, data)
            end, function(err)
              printError("[SS ERR] Errored", err:sub(2))
              if err:sub(1, 1) == ":" then
                secureTransmit("resp", message.i, 
                  {
                    status = "error",
                    message = err:sub(2)
                  }
                )
              else
                secureTransmit("resp", message.i, 
                  {
                    status = "error",
                    message = "Internal error"
                  }
                )
              end
            end)
          else
            modem.transmit(port, port, {
              t = "resp",
              i = message.i,
              d = {
                type = "error",
                message = "Invalid method"
              }
            })
          end
        end
      end
    end
  end
end