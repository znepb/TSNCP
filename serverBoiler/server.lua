-- Standard port for communication is 10000
local port = 10000
local modem = peripheral.find("modem")

-- Load configs and ECC
local certificate = require("certificate")
local key = require("keys")
local ecc = require("ecc")

local private, public = ecc.keypair(ecc.random.random())

-- Session data storage
local sessions = {}

modem.open(port)

-- Utility for generating nonces
local function genNonce(size)
  local n = {}
  for i = 1, size do n[#n+1] = math.random(0, 255) end
  return n
end

-- These events can fire even if a user hasn't been authenticated
local events = {
  hello = function(data)
    local id = math.random(1, 200000000)
    local shared = ecc.exchange(private, data.public)

    sessions[id] = {
      status = "ready",
      clientPublic = data.public,
      shared = shared
    }
    
    return {
      status = "success",
      certificate = certificate,
      public = public,
      id = id
    }
  end
}

-- These are events which fire after a user has been authenticated
local securedEvents = {
  -- Required event
  verify = function(data, id)
    return {
      message = "verifySucces"
    }
  end,
  -- Example echo function
  echo = function(data, id)
    return {
      message = "echoReply",
      data = data
    }
  end
}

--- Transmits a signed message
-- @param t string The type of message
-- @param i string The ID the server is resonding to
-- @param d table The data to send
-- @param[opt] use The key to use, this should be a private key
local function secureTransmit(t, i, d, use)
  local serialized = textutils.serialise(d)
  local signed = ecc.sign(use or key.private, serialized)
  
  modem.transmit(port, port, {
    t = t,
    i = i,
    s = signed,
    d = serialized
  })
end

--- Transmits a message to an authenticated client
-- @param d table The data to send
-- @param i number The session ID that this message is intended for
-- @param[opt] r number The ID the server is responding to
local function authenticatedTransmit(d, i, r)
  local use = sessions[i].shared

  local data = textutils.serialise(d)
  local nonce = genNonce(12)
  local crypted = ecc.chacha20.crypt(data, use, nonce)
  
  modem.transmit(port, port, {
    a = true,
    o = server,
    n = nonce,
    h = string.char(unpack(ecc.sha256.digest(string.char(unpack(use)) .. string.char(unpack(nonce))))),
    i = i,
    r = r,
    s = ecc.sign(private, crypted),
    c = crypted
  })
end

-- Main event loop, this shouldn't have to be changed
print("[OS NFO] Ready, running as " .. certificate.server)
while true do
  local event, side, channel, replyChannel, message, distance = os.pullEvent("modem_message")

  print("[OS NFO] Request from " .. distance .. " blocks away")

  if channel == port and replyChannel == port then
    if type(message) == "table" then
      if not message.a then
        if message.t and message.i and message.d and message.o == certificate.server then
          if events[message.t] then
            print("Executing event " .. message.t)
            xpcall(function()
              local data, toUse = events[message.t](message.d)
              secureTransmit("resp", message.i, data, toUse)
            end, function(err)
              print("Event Error!")
              print(err)
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
      else
        xpcall(function()
          local session = sessions[message.i]
          local localHash = string.char(unpack(ecc.sha256.digest(string.char(unpack(session.shared)) .. string.char(unpack(message.n)))))

          if message.h == localHash then
            local isValid = ecc.verify(session.clientPublic, message.c, message.s)

            if isValid then
              local crypted = string.char(unpack(ecc.chacha20.crypt(message.c, session.shared, message.n)))
              local data = textutils.unserialise(crypted)

              print("[OS NFO] Executing " .. data.message .. " for validated client " .. message.i)
              authenticatedTransmit(securedEvents[data.message](data.data), message.i, message.r)
            end
          end
        end, function(err)
          printError("[OS ERR] Authed message handeler error:")
          printError(err)
        end)
      end
    end
  end
end