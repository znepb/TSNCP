# Tiktin Secure Network Communication Protocol

The Tiktin Secure Network Communication Protocol
(TSNCP) is a network protocol in ComputerCraft
intended for use on the Tiktin Minecraft server.

Documentation coming soon!

## Building

Building the server's function (and in the future, client's functions) can be done using [luabundler](https://github.com/Benjamin-Dobell/luabundler).

### Server

```bash
$ luabundler bundle src/server/server.lua -p "src/common/?.lua" -p "src/server/?.lua" -o build/server.lua
```

## Docgen

```bash
$ ./illuaminate doc-gen
```

## Todo List

- [x] ~~Certificate Server~~
- [x] ~~Orgin Server~~
- [x] ~~Client Utils and such~~
- [x] ~~Rebuild server~~
- [ ] Rebuild client
- [ ] Documentation
- [ ] Better utilities
- [ ] Certificate caching
