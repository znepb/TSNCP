--- Utilities for a simple client. A /.public.lua file containing a Byte Array of the certificate authority's public key is required.
-- @module client

local ecc = require("common.ecc")
local utils = require("common.utils")

local Client = {}
local Client_mt = {__index = Client}

--- Creates a client, ready to connect.
-- @param server string The server to connect to.
-- @param[opt] modem table The modem to use in communication. If this is not provided, it will be gotten via peripheral.find.
-- @param[opt] verbose boolean Whether to print out information about the connection.
-- @return table The new server.
function Client:new(server, modem, verbose)
  local instancePrivate, instancePublic = ecc.keypair(ecc.random.random())

  if not fs.exists(".public.lua") then
    error("/.public.lua is missing")
  end

  return setmetatable({
    verbose = verbose,
    server = server,
    modem = modem or peripheral.find("modem"),
    private = instancePrivate,
    public = instancePublic,
    connected = false,
    messageConnections = {}
  }, Client_mt)
end

function Client:verboseLog( ... )
  if self.verbose then
    print(...)
  end
end

--- Connects to the server.
-- @return boolean True if the connection was successful, false otherwise.
function Client:connect()
  self:verboseLog("Fetching certificate of " .. self.server .. "...")
  local certificate, retrivedLocally = utils.getCertificate(self.server, self.modem)

  if certificate == nil then
    return false, "Connection failed: Server certificate is invalid."
  end

  self.certificate = certificate
  self:verboseLog("Fetched, retrieved locally is " .. tostring(retrivedLocally))

  local response = utils.transmitInsecure(certificate.publicKey, self.modem, "hello", {
    public = self.public,
  }, self.server)

  self:verboseLog("Remote connection completed")

  if response == nil then
    return false, "Connection failed: Server certificate is invalid."
  elseif utils.compareCertificate(response.certificate, certificate) then
    self:verboseLog("Connected! ID is " .. response.id)

    local id, remotePublic = response.id, response.public
    local sharedSecret = ecc.exchange(self.private, response.public)
    
    self:verboseLog("Got shared secret")

    self.remotePublic = remotePublic
    self.id = id
    self.shared = sharedSecret
    self.connected = true

    self.modem.open(10000)

    local response = self:transmit(
      {
        message = "verify"
      }
    )

    self:verboseLog("Verified with remote server!")

    return true
  else
    return false, "Connection failed: Server certificate is invalid."
  end
end

--- Throws some data out into the wild and gives you the request ID.
-- @param data table The data to transmit.
-- @param[opt] string The request ID. This will be random if not provided.
-- @return string The request UUID.
function Client:transmitRaw(data, requestID)
  if self.connected == false then error('Not connected!') end

  local nonce = utils.genNonce(12)
  local hash = utils.bats(ecc.sha256.digest(utils.bats(self.shared) .. utils.bats(nonce)))
  local requestID = requestID or utils.uuid()
  local stringified = textutils.serialise(data)

  local crypted = ecc.chacha20.crypt(stringified, self.shared, nonce)

  self.modem.transmit(10000, 10000, {
    v = 1,
    a = true,
    o = self.server,
    n = nonce,
    h = hash,
    r = requestID,
    i = self.id,
    s = ecc.sign(self.private, crypted),
    c = crypted
  })

  return requestID
end

--- Transmits data to the server, and hopefully returns the response.
-- @param data table The data to transmit.
-- @return table The response. This will be nil if it failed, with an error message.
-- @return string An error message if the request failed.
function Client:transmit(data)
  local attempts = 0
  local signedBad = 0
  local retry = true
  local requestID = utils.uuid()

  local response, error = nil, nil

  repeat
    if retry or signedBad % 5 == 0 then
      retry = false
      self:transmitRaw(data, requestID)
    end

    parallel.waitForAny(function()
      local event, side, channel, reply, message, distance = os.pullEvent("modem_message")

      if message.v ~= 1 then return end
      if target and message.o and message.o ~= self.server then return end
      if channel == 10000 and message.r == requestID and message.a == true and message.i == self.id then
        local hash = utils.bats(ecc.sha256.digest(utils.bats(self.shared) .. utils.bats(message.n)))

        if message.h == hash then
          local isValid = ecc.verify(self.remotePublic, message.c, message.s)

          if isValid then
            local data = utils.bats(ecc.chacha20.crypt(message.c, self.shared, message.n))
            response = textutils.unserialise(data)
            attempts = utils.RECONNECTION_MAX_ATTEMPTS + 1
          else
            retry = true
            attempts = attempts + 1
          end
        end
      end
    end, function()
      sleep(utils.TIMEOUT_SECONDS / utils.RECONNECTION_MAX_ATTEMPTS)
      retry = true
      attempts = attempts + 1
    end)
  until attempts >= utils.RECONNECTION_MAX_ATTEMPTS or signedBad >= utils.BAD_SIGNED_MAX_ATTEMPTS

  return response
end

--- Disconnects from the server.
-- @return boolean True if the disconnection was successful, false otherwise.
-- @return table The goodbye packet from the server.
function Client:disconnect()
  local response = self:transmit(
    {
      message = "goodbye"
    }
  )

  self.modem.close(10000)
  return response.message == "goodbye", response
end

--- Decrypts a message.
-- @param message table The message to decrypt.
-- @return table The decrypted message. This will be nil if it wasn't in the right format.
function Client:decryptMessage(message)
  if message.v ~= 1 then return end
  if message.o ~= self.server then return end
  if message.a == true and message.i == self.id then
    local hash = utils.bats(ecc.sha256.digest(utils.bats(self.shared) .. utils.bats(message.n)))
  
    if message.h == hash then
      local isValid = ecc.verify(self.remotePublic, message.c, message.s)
  
      if isValid then
        local data = utils.bats(ecc.chacha20.crypt(message.c, self.shared, message.n))
        response = textutils.unserialise(data)
        
        return response
      end
    end
  end

  return nil
end

--- Connects a function to when a message is received.
function Client:onMessage(name, func)
  self.messageConnections[name] = func
end

--- Runs the client.
function Client:run()
  while true do
    local event, side, channel, reply, message, distance = os.pullEvent("modem_message")
    
    local decryptedMessage = self:decryptMessage(message)

    if decryptedMessage then
      for name, func in pairs(self.messageConnections) do
        if decryptedMessage.message == name then
          func(decryptedMessage)
        end
      end
    end
  end
end

return Client