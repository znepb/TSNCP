--- Some basic utility functions.
-- @module utils

local RECONNECTION_MAX_ATTEMPTS = 5
local BAD_SIGNED_MAX_ATTEMPTS = 10
local TIMEOUT_SECONDS = 30

local ecc = require("ecc")

--- Converts a byte array to a string
-- @param byteArray table The byte array
-- @return string The string
local function byteArrayToString(byteArray)
  return string.char(unpack(byteArray))
end

--- Generates a nonce with the given size.
-- @param size number The size of the nonce to generate.
-- @return table The generated nonce.
local function genNonce(size)
  local n = {}
  for i = 1, size do n[#n+1] = math.random(0, 255) end
  return n
end

--- Generates a uuid
-- @return string The uuid
local function uuid()
  local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
  return string.gsub(template, '[xy]', function (c)
    local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
    return string.format('%x', v)
  end)
end

--- Compares two certificates
-- @param a table The first certificate
-- @param b table The second certificate
-- @return boolean True if the certificates are equal, false otherwise.
local function compareCertificate(a, b)
  if a.owner ~= b.owner or a.name ~= b.name or a.issuer ~= b.issuer then return false, "Bad meta" end

  for i, v in pairs(a.publicKey) do
    if b.publicKey[i] ~= v then
      return false, "Bad public key"
    end
  end

  return true
end

local function transmitInsecure(publicKey, modem, type, data, target, port)
  local attempts = 0
  local signedBad = 0
  local retry = true

  local response

  local identifier = uuid()

  local port = port or 10000

  modem.open(port)

  repeat
    if retry or signedBad % 5 == 0 then
      retry = false
      modem.transmit(port, port, {
        v = 1,
        t = type,
        i = identifier,
        o = target,
        d = data
      })
    end

    parallel.waitForAny(function()
      local event, side, channel, reply, message, distance = os.pullEvent("modem_message")

      if message.v ~= 1 then return end
      if target and message.o and message.o ~= target then return end
      if channel == port and message.i == identifier and message.t == "resp" then
        local isValid = ecc.verify(publicKey, message.d, message.s)

        if isValid then
          response = textutils.unserialise(message.d)
          attempts = RECONNECTION_MAX_ATTEMPTS + 1
        else
          signedBad = signedBad + 1
        end
      end
    end, function()
      sleep(TIMEOUT_SECONDS / RECONNECTION_MAX_ATTEMPTS)
      retry = true
      attempts = attempts + 1
    end)
  until attempts >= RECONNECTION_MAX_ATTEMPTS or signedBad >= BAD_SIGNED_MAX_ATTEMPTS

  modem.close(port)

  return response
end

--- Gets a certificate.
-- @param name string The name of the certificate.
-- @param modem table The modem to use if no certificate is cached locally.
-- @param forceRemote boolean Whether to force the retrieval of the certificate.
-- @return table The certificate.
-- @return boolean True if the certificate was retrieved locally, false otherwise.
local function getCertificate(name, modem, forceRemote)
  if fs.exists(".certificateCache/" .. name .. ".lua") and force ~= true then
    local f = fs.open(".certificateCache/" .. name .. ".lua", "r")
    local certificate = textutils.unserialise(f.readAll())
    f.close()

    if certificate.expirationDate and certificate.expirationDate < (os.epoch('utc') / 1000) then
      fs.delete(".certificateCache/" .. name .. ".lua")
    else
      return certificate.certificate, true
    end
  elseif fs.exists(".certificateCache/" .. name .. ".lua") and force == true then
    fs.delete(".certificateCache/" .. name .. ".lua")
  elseif not fs.exists(".certificateCache") then
    fs.makeDir(".certificateCache")
  end

  local publicFile = fs.open("/.public.lua", "r")
  local publicKey = textutils.unserialise(publicFile.readAll())
  publicFile.close()

  local certificate = transmitInsecure(publicKey, modem, "retrieveCertificate", 
    {
      certificate = name
    }, 
  nil, 12345)

  local f = fs.open(".certificateCache/" .. name .. ".lua", "w")
  f.write(textutils.serialise({
    certificate = certificate.certificate,
    expirationDate = os.epoch('utc') / 1000 + (7 * 24 * 60 * 60)
  }))
  f.close()

  return certificate.certificate, false
end

return {
  byteArrayToString = byteArrayToString,
  genNonce = genNonce,
  uuid = uuid,
  compareCertificate = compareCertificate,
  getCertificate = getCertificate,
  transmitInsecure = transmitInsecure,
  bats = byteArrayToString,
  RECONNECTION_MAX_ATTEMPTS = RECONNECTION_MAX_ATTEMPTS,
  BAD_SIGNED_MAX_ATTEMPTS = BAD_SIGNED_MAX_ATTEMPTS,
  TIMEOUT_SECONDS = TIMEOUT_SECONDS
}