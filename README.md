# Tiktin Secure Network Communication Protocol

The Tiktin Secure Network Communication Protocol (TSNCP) is a network protocol in ComputerCraft built for the Tiktin Minecraft Server.

TSNCP is set apart from other ComputerCraft network protocols by using asymetric encryption for authentication, similar to TLS/SSL. It uses a central certificate authority to allow a domain to be accessed from any computer, as long as they have the certificate of the certificate authority. TSNCP features secure encryption via Chacha20, written by Anavrins, and ECC, by PG231.

Replay attacks are prevented by marking timestamps that a message was sent within it's hash, and preventing that timestamp from being used ever again.

Some simple, object-oriented APIs and examples are included to help you make servers and clients using the protocol. Documentation for those can be found here: https://znepb.github.io/TSNCP/

## Building

Building the server's function (and in the future, client's functions) can be done using [luabundler](https://github.com/Benjamin-Dobell/luabundler).

### Server

```bash
$ luabundler bundle src/server/server.lua -p "src/common/?.lua" -p "src/server/?.lua" -o build/server.lua
```

### Client

```bash
$ luabundler bundle src/client/client.lua -p "src/common/?.lua" -p "src/client/?.lua" -o build/client.lua
```

## Docgen

```bash
$ ./illuaminate doc-gen
```
