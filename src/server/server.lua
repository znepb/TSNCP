--- Utilities for a simple server, including creation, events, and transmission.
-- @module server

local ecc = require("ecc")
local utils = require("utils")

local Server = {}
local Server_mt = {__index = Server}

--- Creates a new server with the provided information.
-- @param certificate table The certificate that the server will use.
-- @param publicKey table The public key of the server.
-- @param privateKey table The private key of the server.
-- @param[opt] modem table The modem that will be used while communicating. If this is not provided, it will be gotten via peripheral.find
-- @param[opt] port number The port number to use, this should usually be 10000, which is the default.
-- @return table The new server.
function Server:new(certificate, publicKey, privateKey, modem, port)
  local instancePrivate, instancePublic = ecc.keypair(ecc.random.random())

  return setmetatable({
    certificate = certificate,
    serverKeys = {
      private = privateKey,
      public = publicKey
    },
    instanceKeys = {
      private = instancePrivate,
      public = instancePublic
    },
    securedEvents = {},
    events = {},
    modem = modem or peripheral.find("modem"),
    port = port or 10000,
    sessions = {}
  }, Server_mt)
end

--- Adds a secured function. This will only be available if a client has been authenticated.
-- @param name string The name of the function.
-- @param func function The function to add.
function Server:addSecuredEvent(name, func)
  self.securedEvents[name] = func
end

--- Adds a function to the list of events. This will be available to all clients.
-- @param name string The name of the function.
-- @param func function The function to add.
function Server:addEvent(name, func)
  self.events[name] = func
end

--- Transmits a signed message
-- @param t string The type of message
-- @param i string The ID the server is resonding to
-- @param d table The data to send
function Server:transmit(t, i, d)
  local serialized = textutils.serialise(d)
  local signed = ecc.sign(self.serverKeys.private, serialized)
  
  self.modem.transmit(self.port, self.port, {
    v = 1,
    t = t,
    o = self.certificate.name,
    i = i,
    s = signed,
    d = serialized
  })
end

--- Transmits a message to an authenticated client
-- @param dat table The data to send
-- @param id number The session ID that this message is intended for
-- @param[opt] reply number The ID the server is responding to
-- @param[opt] key string The key to use for encryption
function Server:transmitSecure(dat, id, reply, key)
  if key == nil then key = self.sessions[id].shared end

  local data = textutils.serialise(dat)
  local nonce = utils.genNonce(12)
  local crypted = ecc.chacha20.crypt(data, key, nonce)
  local timestamp = os.epoch("utc")
  
  self.modem.transmit(self.port, self.port, {
    v = 1,
    a = true,
    o = self.certificate.name,
    n = nonce,
    t = timestamp,
    h = utils.byteArrayToString(ecc.sha256.digest(utils.byteArrayToString(key) .. utils.byteArrayToString(nonce) .. timestamp)),
    i = id,
    r = reply,
    s = ecc.sign(self.instanceKeys.private, crypted),
    c = crypted
  })
end

--- Gets all active sessions.
-- @return table The sessions.
function Server:getSessions()
  return self.sessions
end

--- Removes all timestamps that are held to prevent replay attacks. This runs every time the server receives an event.
function Server:flushTimestamps()
  local now = os.epoch("utc")
  
  for _, s in pairs(self.sessions) do
    for t, _ in pairs(s.timestamps) do
      if t + 250 < now then
        s.timestamps[t] = nil
      end
    end
  end
end

--- Starts the party.
function Server:start()
  self:addEvent("hello", function(self, data)
    local id = utils.uuid()
    local shared = ecc.exchange(self.instanceKeys.private, data.public)

    self.sessions[id] = {
      status = "ready",
      clientPublic = data.public,
      shared = shared,
      timestamps = {}
    }
    
    return {
      status = "success",
      certificate = self.certificate,
      public = self.instanceKeys.public,
      id = id
    }
  end)

  self:addSecuredEvent("verify", function(data, id)
    print("[OS NFO] Client " .. id .. " has connected!")

    return {
      message = "verifySuccess"
    }
  end)

  self:addSecuredEvent("goodbye", function(data, id)
    print("[OS NFO] Client " .. id .. " has disconnected.")

    local key = self.sessions[id].shared
    self.sessions[id] = nil

    return {
      message = "goodbye"
    }, key
  end)

  self.modem.open(self.port)

  print("[OS NFO] Ready, running as " .. self.certificate.name)
  while true do
    local event, side, channel, replyChannel, message, distance = os.pullEvent("modem_message")

    print("[OS NFO] Request from " .. distance .. " blocks away")

    if channel == self.port and replyChannel == self.port then
      if type(message) == "table" then
        if message.v == 1 then
          if not message.a then
            -- Message is not authenticated
            if message.t and message.i and message.d and message.o == self.certificate.name then
              if self.events[message.t] then
                print("[OS NFO] Executing event " .. message.t)
                xpcall(function()
                  local data = self.events[message.t](self, message.d)
                  self:transmit("resp", message.i, data)
                end, function(err)
                  printError("[OS ERR] Event Error!")
                  printError("[OS ERR] " .. err)
                  if err:sub(1, 1) == ":" then
                    self:transmit("resp", message.i, 
                      {
                        status = "error",
                        message = err:sub(2)
                      }
                    )
                  else
                    self:transmit("resp", message.i, 
                      {
                        status = "error",
                        message = "Internal error"
                      }
                    )
                  end
                end)
              else
                self:transmit("resp", message.i, 
                  {
                    type = "error",
                    message = "Invalid method"
                  }
                )
              end
            end
          else
            -- Message is authenticated
            xpcall(function()
              local session = self.sessions[message.i]
              local now = os.epoch("utc")

              if message.t + 250 < now then return end
              if session.timestamps[message.t] then return end

              if session then
                local localHash = utils.bats(ecc.sha256.digest(utils.bats(session.shared) .. utils.bats(message.n) .. message.t))
                if message.h == localHash then
                  local isValid = ecc.verify(session.clientPublic, message.c, message.s)

                  if isValid then
                    local crypted = utils.byteArrayToString(ecc.chacha20.crypt(message.c, session.shared, message.n))
                    local data = textutils.unserialise(crypted)

                    print("[OS NFO] Executing " .. data.message .. " for validated client " .. message.i)

                    self.sessions[message.i].timestamps[message.t] = true
                    local data, key = self.securedEvents[data.message](data.data, message.i)
                    self:transmitSecure(data, message.i, message.r, key)
                  else
                    print("[OS NFO] Invalid signature!")
                  end
                else
                  print("[OS NFO] Invalid hash!")
                end
              end
            end, function(err)
              printError("[OS ERR] Authed message handeler error:")
              printError("[OS ERR] " .. err)
            end)
          end
        end
      end
    end

    self:flushTimestamps()
  end
end

return Server