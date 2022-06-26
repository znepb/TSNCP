-- Companion client to the server.

local Client = require("client")

local client = Client:new("echo.tol", nil, true)
client:connect()

local response = client:transmit({
  message = "echo",
  data = {
    message = "Hello, world!"
  }
})

print(textutils.serialise(response))

client:onMessage("basic", function(data)
  print(data.data.text)
end)

parallel.waitForAll(
  function()
    client:run()
  end
)