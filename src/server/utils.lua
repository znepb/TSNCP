--- Some basic utility functions.
-- @module utils

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

return {
  byteArrayToString = byteArrayToString,
  genNonce = genNonce,
  uuid = uuid
}