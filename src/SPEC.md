# TSNCP Packet Information

TSNCP uses 5 types of packets:

- Certificate Server Request
- Certificate Server Response
- Orgin Server Request
- Orgin Server Response
- Authenticated Packet

Certificate server requests occur on port 12345, and orgin server requests occur on port 10000.

**This document outlines spec v1**

## Object Outlines

### ByteArray

This is an array of bytes from ECC. See [here](https://www.computercraft.info/forums2/index.php?/topic/29803-elliptic-curve-cryptography/).

### Certificate

A basic ceritifcate, which contains some metadata of the server, and the server's public key.  
An example certificate is shown below:

```lua
{
  name = "bezos.tol",
  owner = "Jeffery Bezos",
  issuer = "Amazon",
  publicKey = { ... } -- a ByteArray
}
```

## Request Outlines

### Certificate Authority Server Request

Certificate Authority server requests are identical to orgin server requests, except they have a required `t` (type) and `d` (data) arguments, and no `o` (orgin) argument.

```lua
{
  v = 1,
  t = "retrieveCertificate",
  i = any, -- Any kind of unique identifier
  d = {
    certificate = string
  }
}
```

### Certificate Authority Server Response

Basic response from the Certificate Authority. Simmilarly to the Certificate Authority Server Request, `t` will always be constant, `resp` in this case, and no `o` entry is present,

```lua
{
  v = 1,
  t = "resp",
  i = any, -- This will be the same as the identifier on the initial packet
  s = ByteArray, -- A signed version of the serialized table, d. The client should already know the public key of the certificate authority so this can be vertified.
  d = string -- A serialized table containing a certificate, outlined above. Note that this is not encrypted, as no handshake has taken place.
}
```

### Orgin Server Request

Unencrypted requests should only be used during handshake. These are identical to the Certificate Authority Server Request packets, but with a `o` (orgin) argument, customizable `d` (data) and `t` (type).

```lua
{
  v = 1,
  t = string, -- The type of message
  i = any, -- A unique identifier to search for responses
  o = string, -- The target server's name in the certificate.
  d = any -- Some data
}
```

### Orgin Server Response

Again, identical to the certificate authority's response, but with an `o` (orgin) argument, and customizable `d` (data) and `t` (type).

```lua
{
  v = 1,
  t = string, -- The type of message. It is reccomended that this not be the same as the request type, as responses lack a header saying they are a response.
  i = any, -- This will be the same as the identifier in the request packet
  o = string, -- The server's name in the certificate.
  s = ByteArray, -- d, but signed so it can validated.
  d = string -- A serialized table, or string, with the data. This won't be encrypted.
}
```

### Authenticated Packet

The client and server use the same packet structure to communicate when authenticated.
Both the client and server should remember nonces that have been used to prevent replay attacks.

```lua
{
  v = 1,
  a = true, -- Tells the receiver this packet is encrypted
  o = string, -- The target server's name in the certificate.
  n = ByteArray, -- A 12 byte ByteArray that chacha20 will use to crypt the data.
  h = string, -- The hash of the shared token and the nonce, in this format: char(unpack(sha256(char(unpack(shared)) .. char(unpack(nonce))))),
  r = string, -- A unique identifier for the request
  i = string, -- A unique identifier for the session
  s = { ... }, -- Signed data
  c = { ... } -- An encrypted string
}
```

## Opening Connections (Handshake)

To open a connection, the client sends a `hello` request to the server, with the client's public key. An example is shown below:

```lua
{
  v = 1,
  t = "hello",
  i = "3eb4cb1b-45aa-407b-a9bb-1ffeb85c2600",
  o = "bezos.tol",
  d = {
    public = { ... } -- A byte array.
  }
}
```

If the server is online, the client will receive this response:

```lua
{
  v = 1,
  t = "resp",
  i = "3eb4cb1b-45aa-407b-a9bb-1ffeb85c2600",
  o = "bezos.tol",
  s = { ... }, -- The d argument signed
  d = { -- Note that this will be a string, not a table.
    status = "success",
    certificate = Certificate, -- The server's certificate, so it can be verified wit the Certificate Authority
    public = { ... }, -- The server instance's public key.
    id = "9b83e490-2d5e-494d-989b-c35deac9721c" -- The session's ID.
  }
}
```

After this, the client and server will create a shared key via [Diffe-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange). To verify that they have come to the same result, the client will send one last packet to the server, with a message `verify`. Below is shown this packet, unencrypted.

```lua
{
  v = 1,
  a = true,
  o = "bezos.tol",
  n = ByteArray, -- 12 bytes
  h = string, -- The hash of the shared token and the nonce
  r = "c1ae6ea5-74d4-4fea-a152-24cffdf001fe", -- Request ID
  i = "9b83e490-2d5e-494d-989b-c35deac9721c", -- Session ID
  s = { ... }, -- Signed data
  c = { -- Note the data shown here is unencrypted. This will also be a string when unencrypted, but is shown as a table here for simplicity.
    message = "verify"
  }
}
```

Finally, if the verification was a success, the client will receive a packet, with the message. `verifySuccess`.

```lua
{
  v = 1,
  a = true,
  o = "bezos.tol",
  n = ByteArray, -- 12 bytes
  h = string, -- The hash of the shared token and the nonce
  r = "c1ae6ea5-74d4-4fea-a152-24cffdf001fe",
  i = "9b83e490-2d5e-494d-989b-c35deac9721c",
  s = { ... }, -- Signed data
  c = { -- Note the data shown here is unencrypted. This will also be a string when unencrypted, but is shown as a table here for simplicity.
    message = "verifySuccess"
  }
}
```

Now the client and server can communicate securely!

## Ending Connections

The client will send an authenticated packet, with the message `goodbye`. To confirm this, the server will respond with a packet with `goodbye` as well.

## Antiipated Changes (pre-1.0)

- ~~All packets will be given a `v` (version) entry, a number showing the version of the packet.~~
- ~~All appearances of `signature` will be changed to `certificate`, where nessecary.~~
