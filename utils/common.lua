local signServerPort = 12345
local RECONNECTION_MAX_ATTEMPTS = 5
local modem = peripheral.find("modem")
local ecc = require("utils.ecc")

local function genNonce(size)
  local n = {}
  for i = 1, size do n[#n+1] = math.random(0, 255) end
  return n
end

local function transmitGetResp(port, publicKey, t, d, o)
  local attempts = 0
  local response
  local retry = true

  local i = math.random(1, 1000000000)

  modem.open(port)

  repeat
    if retry then
      retry = false
      modem.transmit(port, port, {
        t = t,
        i = i,
        o = o,
        d = d
      })
    end

    parallel.waitForAny(function()
      local event, side, channel, reply, message, distance = os.pullEvent("modem_message")

      if o and message.o and message.o ~= o then retry = true end
      if channel == port and message.i == i and message.t == "resp" then
        local isValid = ecc.verify(publicKey, message.d, message.s)

        if isValid then
          response = textutils.unserialise(message.d)
          attempts = RECONNECTION_MAX_ATTEMPTS + 1
        else
          retry = true
          attempts = attempts + 1
        end
      end
    end, function()
      sleep(5)
      retry = true
      attempts = attempts + 1
    end)
  until attempts >= RECONNECTION_MAX_ATTEMPTS

  return response
end

local function secureTransmit(port, localPrivateKey, remotePublic, id, shared, d, o)
  local attempts = 0
  local response
  local retry = true

  local i = math.random(1, 1000000000)

  modem.open(port)

  repeat
    local data = textutils.serialise(d)
    local nonce = genNonce(12)
    local crypted = ecc.chacha20.crypt(data, shared, nonce)

    if retry then
      retry = false
      modem.transmit(port, port, {
        a = true, -- Authenticated?
        o = o, -- Orgin
        n = nonce, -- Nonce
        h = string.char(unpack(ecc.sha256.digest(string.char(unpack(shared)) .. string.char(unpack(nonce))))),
        r = i,
        i = id,
        s = ecc.sign(localPrivateKey, crypted), -- Signed
        c = crypted -- Crypted data
      })
    end

    parallel.waitForAny(function()
      local event, side, channel, reply, message, distance = os.pullEvent("modem_message")

      if message.o ~= o then retry = true end
      if channel == port and message.r == i and message.a == true then
        local hash = string.char(unpack(ecc.sha256.digest(string.char(unpack(shared)) .. string.char(unpack(message.n)))))

        if message.h == hash then
          local isValid = ecc.verify(remotePublic, message.c, message.s)

          if isValid then
            local data = string.char(unpack(ecc.chacha20.crypt(message.c, shared, message.n)))
            response = textutils.unserialise(data)
            attempts = RECONNECTION_MAX_ATTEMPTS + 1
          else
            retry = true
            attempts = attempts + 1
          end
        end
      end
    end, function()
      sleep(5)
      retry = true
      attempts = attempts + 1
    end)
  until attempts >= RECONNECTION_MAX_ATTEMPTS

  return response
end

local function compareCertificate(a, b)
  if a.owner ~= b.owner or a.name ~= b.name or a.issuer ~= b.issuer then return false, "Bad meta" end

  for i, v in pairs(a.publicKey) do
    if b.publicKey[i] ~= v then
      return false, "Bad public key"
    end
  end

  return true
end

return {
  secureTransmit = secureTransmit,
  transmitGetResp = transmitGetResp,
  compareCertificate = compareCertificate,
  RECONNECTION_MAX_ATTEMPTS = RECONNECTION_MAX_ATTEMPTS
}