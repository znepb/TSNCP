-- Elliptic Curve Cryptography in Computercraft

---- Update (Jun  4 2021)
-- Fix compatibility with CraftOS-PC
---- Update (Jul 30 2020)
-- Make randomModQ and use it instead of hashing from random.random()
---- Update (Feb 10 2020)
-- Make a more robust encoding/decoding implementation
---- Update (Dec 30 2019)
-- Fix rng not accumulating entropy from loop
-- (older versions should be fine from other sources + stored in disk)
---- Update (Dec 28 2019)
-- Slightly better integer multiplication and squaring
-- Fix global variable declarations in modQ division and verify() (no security concerns)
-- Small tweaks from SquidDev's illuaminate (https://github.com/SquidDev/illuaminate/)

local byteTableMT = {
    __tostring = function(a) return string.char(unpack(a)) end,
    __index = {
        toHex = function(self) return ("%02x"):rep(#self):format(unpack(self)) end,
        isEqual = function(self, t)
            if type(t) ~= "table" then return false end
            if #self ~= #t then return false end
            local ret = 0
            for i = 1, #self do
                ret = bit32.bor(ret, bit32.bxor(self[i], t[i]))
            end
            return ret == 0
        end
    }
}

-- SHA-256, HMAC and PBKDF2 functions in ComputerCraft
-- By Anavrins
-- For help and details, you can PM me on the CC forums
-- You may use this code in your projects without asking me, as long as credit is given and this header is kept intact
-- http://www.computercraft.info/forums2/index.php?/user/12870-anavrins
-- http://pastebin.com/6UV4qfNF
-- Last update: October 10, 2017
local sha256 = (function()
    local mod32 = 2^32
    local band    = bit32 and bit32.band or bit.band
    local bnot    = bit32 and bit32.bnot or bit.bnot
    local bxor    = bit32 and bit32.bxor or bit.bxor
    local blshift = bit32 and bit32.lshift or bit.blshift
    local upack   = unpack

    local function rrotate(n, b)
        local s = n/(2^b)
        local f = s%1
        return (s-f) + f*mod32
    end
    local function brshift(int, by) -- Thanks bit32 for bad rshift
        local s = int / (2^by)
        return s - s%1
    end

    local H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    }

    local K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }

    local function counter(incr)
        local t1, t2 = 0, 0
        if 0xFFFFFFFF - t1 < incr then
            t2 = t2 + 1
            t1 = incr - (0xFFFFFFFF - t1) - 1       
        else t1 = t1 + incr
        end
        return t2, t1
    end

    local function BE_toInt(bs, i)
        return blshift((bs[i] or 0), 24) + blshift((bs[i+1] or 0), 16) + blshift((bs[i+2] or 0), 8) + (bs[i+3] or 0)
    end

    local function preprocess(data)
        local len = #data
        local proc = {}
        data[#data+1] = 0x80
        while #data%64~=56 do data[#data+1] = 0 end
        local blocks = math.ceil(#data/64)
        for i = 1, blocks do
            proc[i] = {}
            for j = 1, 16 do
                proc[i][j] = BE_toInt(data, 1+((i-1)*64)+((j-1)*4))
            end
        end
        proc[blocks][15], proc[blocks][16] = counter(len*8)
        return proc
    end

    local function digestblock(w, C)
        for j = 17, 64 do
            local s0 = bxor(bxor(rrotate(w[j-15], 7), rrotate(w[j-15], 18)), brshift(w[j-15], 3))
            local s1 = bxor(bxor(rrotate(w[j-2], 17), rrotate(w[j-2], 19)), brshift(w[j-2], 10))
            w[j] = (w[j-16] + s0 + w[j-7] + s1)%mod32
        end
        local a, b, c, d, e, f, g, h = upack(C)
        for j = 1, 64 do
            local S1 = bxor(bxor(rrotate(e, 6), rrotate(e, 11)), rrotate(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local temp1 = (h + S1 + ch + K[j] + w[j])%mod32
            local S0 = bxor(bxor(rrotate(a, 2), rrotate(a, 13)), rrotate(a, 22))
            local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
            local temp2 = (S0 + maj)%mod32
            h, g, f, e, d, c, b, a = g, f, e, (d+temp1)%mod32, c, b, a, (temp1+temp2)%mod32
        end
        C[1] = (C[1] + a)%mod32
        C[2] = (C[2] + b)%mod32
        C[3] = (C[3] + c)%mod32
        C[4] = (C[4] + d)%mod32
        C[5] = (C[5] + e)%mod32
        C[6] = (C[6] + f)%mod32
        C[7] = (C[7] + g)%mod32
        C[8] = (C[8] + h)%mod32
        return C
    end

    local function toBytes(t, n)
        local b = {}
        for i = 1, n do
            b[(i-1)*4+1] = band(brshift(t[i], 24), 0xFF)
            b[(i-1)*4+2] = band(brshift(t[i], 16), 0xFF)
            b[(i-1)*4+3] = band(brshift(t[i], 8), 0xFF)
            b[(i-1)*4+4] = band(t[i], 0xFF)
        end
        return setmetatable(b, byteTableMT)
    end

    local function digest(data)
        data = data or ""
        data = type(data) == "table" and {upack(data)} or {tostring(data):byte(1,-1)}

        data = preprocess(data)
        local C = {upack(H)}
        for i = 1, #data do C = digestblock(data[i], C) end
        return toBytes(C, 8)
    end

    local function hmac(data, key)
        local data = type(data) == "table" and {upack(data)} or {tostring(data):byte(1,-1)}
        local key = type(key) == "table" and {upack(key)} or {tostring(key):byte(1,-1)}

        local blocksize = 64

        key = #key > blocksize and digest(key) or key

        local ipad = {}
        local opad = {}
        local padded_key = {}

        for i = 1, blocksize do
            ipad[i] = bxor(0x36, key[i] or 0)
            opad[i] = bxor(0x5C, key[i] or 0)
        end

        for i = 1, #data do
            ipad[blocksize+i] = data[i]
        end

        ipad = digest(ipad)

        for i = 1, blocksize do
            padded_key[i] = opad[i]
            padded_key[blocksize+i] = ipad[i]
        end

        return digest(padded_key)
    end

    local function pbkdf2(pass, salt, iter, dklen)
        local salt = type(salt) == "table" and salt or {tostring(salt):byte(1,-1)}
        local hashlen = 32
        local dklen = dklen or 32
        local block = 1
        local out = {}

        while dklen > 0 do
            local ikey = {}
            local isalt = {upack(salt)}
            local clen = dklen > hashlen and hashlen or dklen

            isalt[#isalt+1] = band(brshift(block, 24), 0xFF)
            isalt[#isalt+1] = band(brshift(block, 16), 0xFF)
            isalt[#isalt+1] = band(brshift(block, 8), 0xFF)
            isalt[#isalt+1] = band(block, 0xFF)

            for j = 1, iter do
                isalt = hmac(isalt, pass)
                for k = 1, clen do ikey[k] = bxor(isalt[k], ikey[k] or 0) end
                if j % 200 == 0 then os.queueEvent("PBKDF2", j) coroutine.yield("PBKDF2") end
            end
            dklen = dklen - clen
            block = block+1
            for k = 1, clen do out[#out+1] = ikey[k] end
        end

        return setmetatable(out, byteTableMT)
    end

    return {
        digest = digest,
        hmac = hmac,
        pbkdf2 = pbkdf2
    }
end)()

-- Chacha20 cipher in ComputerCraft
-- By Anavrins
-- For help and details, you can PM me on the CC forums
-- You may use this code in your projects without asking me, as long as credit is given and this header is kept intact
-- http://www.computercraft.info/forums2/index.php?/user/12870-anavrins
-- http://pastebin.com/GPzf9JSa
-- Last update: April 17, 2017
local chacha20 = (function()
    local bxor = bit32.bxor
    local band = bit32.band
    local blshift = bit32.lshift
    local brshift = bit32.arshift

    local mod = 2^32
    local tau = {("expand 16-byte k"):byte(1,-1)}
    local sigma = {("expand 32-byte k"):byte(1,-1)}

    local function rotl(n, b)
        local s = n/(2^(32-b))
        local f = s%1
        return (s-f) + f*mod
    end

    local function quarterRound(s, a, b, c, d)
        s[a] = (s[a]+s[b])%mod; s[d] = rotl(bxor(s[d], s[a]), 16)
        s[c] = (s[c]+s[d])%mod; s[b] = rotl(bxor(s[b], s[c]), 12)
        s[a] = (s[a]+s[b])%mod; s[d] = rotl(bxor(s[d], s[a]), 8)
        s[c] = (s[c]+s[d])%mod; s[b] = rotl(bxor(s[b], s[c]), 7)
        return s
    end

    local function hashBlock(state, rnd)
        local s = {unpack(state)}
        for i = 1, rnd do
            local r = i%2==1
            s = r and quarterRound(s, 1, 5,  9, 13) or quarterRound(s, 1, 6, 11, 16)
            s = r and quarterRound(s, 2, 6, 10, 14) or quarterRound(s, 2, 7, 12, 13)
            s = r and quarterRound(s, 3, 7, 11, 15) or quarterRound(s, 3, 8,  9, 14)
            s = r and quarterRound(s, 4, 8, 12, 16) or quarterRound(s, 4, 5, 10, 15)
        end
        for i = 1, 16 do s[i] = (s[i]+state[i])%mod end
        return s
    end

    local function LE_toInt(bs, i)
        return (bs[i+1] or 0)+
        blshift((bs[i+2] or 0), 8)+
        blshift((bs[i+3] or 0), 16)+
        blshift((bs[i+4] or 0), 24)
    end

    local function initState(key, nonce, counter)
        local isKey256 = #key == 32
        local const = isKey256 and sigma or tau
        local state = {}

        state[ 1] = LE_toInt(const, 0)
        state[ 2] = LE_toInt(const, 4)
        state[ 3] = LE_toInt(const, 8)
        state[ 4] = LE_toInt(const, 12)

        state[ 5] = LE_toInt(key, 0)
        state[ 6] = LE_toInt(key, 4)
        state[ 7] = LE_toInt(key, 8)
        state[ 8] = LE_toInt(key, 12)
        state[ 9] = LE_toInt(key, isKey256 and 16 or 0)
        state[10] = LE_toInt(key, isKey256 and 20 or 4)
        state[11] = LE_toInt(key, isKey256 and 24 or 8)
        state[12] = LE_toInt(key, isKey256 and 28 or 12)

        state[13] = counter
        state[14] = LE_toInt(nonce, 0)
        state[15] = LE_toInt(nonce, 4)
        state[16] = LE_toInt(nonce, 8)

        return state
    end

    local function serialize(state)
        local r = {}
        for i = 1, 16 do
            r[#r+1] = band(state[i], 0xFF)
            r[#r+1] = band(brshift(state[i], 8), 0xFF)
            r[#r+1] = band(brshift(state[i], 16), 0xFF)
            r[#r+1] = band(brshift(state[i], 24), 0xFF)
        end
        return r
    end

    local function crypt(data, key, nonce, cntr, round)
        assert(type(key) == "table", "ChaCha20: Invalid key format ("..type(key).."), must be table")
        assert(type(nonce) == "table", "ChaCha20: Invalid nonce format ("..type(nonce).."), must be table")
        assert(#key == 16 or #key == 32, "ChaCha20: Invalid key length ("..#key.."), must be 16 or 32")
        assert(#nonce == 12, "ChaCha20: Invalid nonce length ("..#nonce.."), must be 12")

        local data = type(data) == "table" and {unpack(data)} or {tostring(data):byte(1,-1)}
        cntr = tonumber(cntr) or 1
        round = tonumber(round) or 20

        local out = {}
        local state = initState(key, nonce, cntr)
        local blockAmt = math.floor(#data/64)
        for i = 0, blockAmt do
            local ks = serialize(hashBlock(state, round))
            state[13] = (state[13]+1) % mod

            local block = {}
            for j = 1, 64 do
                block[j] = data[((i)*64)+j]
            end
            for j = 1, #block do
                out[#out+1] = bxor(block[j], ks[j])
            end

            if i % 1000 == 0 then
                os.queueEvent("")
                os.pullEvent("")
            end
        end
        return setmetatable(out, byteTableMT)
    end

    return {
        crypt = crypt
    }
end)()

-- random.lua - Random Byte Generator
local random = (function()
    local entropy = ""
    local accumulator = ""
    local entropyPath = "/.random"

    local function feed(data)
        accumulator = accumulator .. (data or "")
    end

    local function digest()
        entropy = tostring(sha256.digest(entropy .. accumulator))
        accumulator = ""
    end

    if fs.exists(entropyPath) then
        local entropyFile = fs.open(entropyPath, "rb")
        feed(entropyFile.readAll())
        entropyFile.close()
    end

    feed("init")
    feed(tostring(math.random(1, 2^31 - 1)))
    feed("|")
    feed(tostring(math.random(1, 2^31 - 1)))
    feed("|")
    feed(tostring(math.random(1, 2^4)))
    feed("|")
    feed(tostring(os.epoch("utc")))
    feed("|")
    for _ = 1, 10000 do
        feed(tostring({}):sub(-8))
    end
    digest()
    feed(tostring(os.epoch("utc")))
    digest()

    local function save()
        feed("save")
        feed(tostring(os.epoch("utc")))
        feed(tostring({}))
        digest()

        local entropyFile = fs.open(entropyPath, "wb")
        entropyFile.write(tostring(sha256.hmac("save", entropy)))
        entropy = tostring(sha256.digest(entropy))
        entropyFile.close()
    end
    save()

    local function seed(data)
        feed("seed")
        feed(tostring(os.epoch("utc")))
        feed(tostring({}))
        feed(data)
        digest()
        save()
    end

    local function random()
        feed("random")
        feed(tostring(os.epoch("utc")))
        feed(tostring({}))
        digest()
        save()

        local result = sha256.hmac("out", entropy)
        entropy = tostring(sha256.digest(entropy))
        
        return result
    end

    return {
        seed = seed,
        save = save,
        random = random
    }
end)()

-- Big integer arithmetic for 168-bit (and 336-bit) numbers
-- Numbers are represented as little-endian tables of 24-bit integers
local arith = (function()
    local function isEqual(a, b)
        return (
            a[1] == b[1]
            and a[2] == b[2]
            and a[3] == b[3]
            and a[4] == b[4]
            and a[5] == b[5]
            and a[6] == b[6]
            and a[7] == b[7]
        )
    end

    local function compare(a, b)
        for i = 7, 1, -1 do
            if a[i] > b[i] then
                return 1
            elseif a[i] < b[i] then
                return -1
            end
        end

        return 0
    end

    local function add(a, b)
        -- c7 may be greater than 2^24 before reduction
        local c1 = a[1] + b[1]
        local c2 = a[2] + b[2]
        local c3 = a[3] + b[3]
        local c4 = a[4] + b[4]
        local c5 = a[5] + b[5]
        local c6 = a[6] + b[6]
        local c7 = a[7] + b[7]

        if c1 > 0xffffff then
            c2 = c2 + 1
            c1 = c1 - 0x1000000
        end
        if c2 > 0xffffff then
            c3 = c3 + 1
            c2 = c2 - 0x1000000
        end
        if c3 > 0xffffff then
            c4 = c4 + 1
            c3 = c3 - 0x1000000
        end
        if c4 > 0xffffff then
            c5 = c5 + 1
            c4 = c4 - 0x1000000
        end
        if c5 > 0xffffff then
            c6 = c6 + 1
            c5 = c5 - 0x1000000
        end
        if c6 > 0xffffff then
            c7 = c7 + 1
            c6 = c6 - 0x1000000
        end
        
        return {c1, c2, c3, c4, c5, c6, c7}
    end

    local function sub(a, b)
        -- c7 may be negative before reduction
        local c1 = a[1] - b[1]
        local c2 = a[2] - b[2]
        local c3 = a[3] - b[3]
        local c4 = a[4] - b[4]
        local c5 = a[5] - b[5]
        local c6 = a[6] - b[6]
        local c7 = a[7] - b[7]

        if c1 < 0 then
            c2 = c2 - 1
            c1 = c1 + 0x1000000
        end
        if c2 < 0 then
            c3 = c3 - 1
            c2 = c2 + 0x1000000
        end
        if c3 < 0 then
            c4 = c4 - 1
            c3 = c3 + 0x1000000
        end
        if c4 < 0 then
            c5 = c5 - 1
            c4 = c4 + 0x1000000
        end
        if c5 < 0 then
            c6 = c6 - 1
            c5 = c5 + 0x1000000
        end
        if c6 < 0 then
            c7 = c7 - 1
            c6 = c6 + 0x1000000
        end
        
        return {c1, c2, c3, c4, c5, c6, c7}
    end

    local function rShift(a)
        local c1 = a[1]
        local c2 = a[2]
        local c3 = a[3]
        local c4 = a[4]
        local c5 = a[5]
        local c6 = a[6]
        local c7 = a[7]

        c1 = c1 / 2
        c1 = c1 - c1 % 1
        c1 = c1 + (c2 % 2) * 0x800000
        c2 = c2 / 2
        c2 = c2 - c2 % 1
        c2 = c2 + (c3 % 2) * 0x800000
        c3 = c3 / 2
        c3 = c3 - c3 % 1
        c3 = c3 + (c4 % 2) * 0x800000
        c4 = c4 / 2
        c4 = c4 - c4 % 1
        c4 = c4 + (c5 % 2) * 0x800000
        c5 = c5 / 2
        c5 = c5 - c5 % 1
        c5 = c5 + (c6 % 2) * 0x800000
        c6 = c6 / 2
        c6 = c6 - c6 % 1
        c6 = c6 + (c7 % 2) * 0x800000
        c7 = c7 / 2
        c7 = c7 - c7 % 1

        return {c1, c2, c3, c4, c5, c6, c7}
    end

    local function addDouble(a, b)
        -- a and b are 336-bit integers (14 words)
        local c1 = a[1] + b[1]
        local c2 = a[2] + b[2]
        local c3 = a[3] + b[3]
        local c4 = a[4] + b[4]
        local c5 = a[5] + b[5]
        local c6 = a[6] + b[6]
        local c7 = a[7] + b[7]
        local c8 = a[8] + b[8]
        local c9 = a[9] + b[9]
        local c10 = a[10] + b[10]
        local c11 = a[11] + b[11]
        local c12 = a[12] + b[12]
        local c13 = a[13] + b[13]
        local c14 = a[14] + b[14]

        if c1 > 0xffffff then
            c2 = c2 + 1
            c1 = c1 - 0x1000000
        end
        if c2 > 0xffffff then
            c3 = c3 + 1
            c2 = c2 - 0x1000000
        end
        if c3 > 0xffffff then
            c4 = c4 + 1
            c3 = c3 - 0x1000000
        end
        if c4 > 0xffffff then
            c5 = c5 + 1
            c4 = c4 - 0x1000000
        end
        if c5 > 0xffffff then
            c6 = c6 + 1
            c5 = c5 - 0x1000000
        end
        if c6 > 0xffffff then
            c7 = c7 + 1
            c6 = c6 - 0x1000000
        end
        if c7 > 0xffffff then
            c8 = c8 + 1
            c7 = c7 - 0x1000000
        end
        if c8 > 0xffffff then
            c9 = c9 + 1
            c8 = c8 - 0x1000000
        end
        if c9 > 0xffffff then
            c10 = c10 + 1
            c9 = c9 - 0x1000000
        end
        if c10 > 0xffffff then
            c11 = c11 + 1
            c10 = c10 - 0x1000000
        end
        if c11 > 0xffffff then
            c12 = c12 + 1
            c11 = c11 - 0x1000000
        end
        if c12 > 0xffffff then
            c13 = c13 + 1
            c12 = c12 - 0x1000000
        end
        if c13 > 0xffffff then
            c14 = c14 + 1
            c13 = c13 - 0x1000000
        end

        return {c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14}
    end

    local function mult(a, b, half_multiply)
        local a1, a2, a3, a4, a5, a6, a7 = unpack(a)
        local b1, b2, b3, b4, b5, b6, b7 = unpack(b)
        
        local c1 = a1 * b1
        local c2 = a1 * b2 + a2 * b1
        local c3 = a1 * b3 + a2 * b2 + a3 * b1
        local c4 = a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1
        local c5 = a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1
        local c6 = a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1
        local c7 = a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2
                   + a7 * b1
        local c8, c9, c10, c11, c12, c13, c14
        if not half_multiply then
            c8 = a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2
            c9 = a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3
            c10 = a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4
            c11 = a5 * b7 + a6 * b6 + a7 * b5
            c12 = a6 * b7 + a7 * b6
            c13 = a7 * b7
            c14 = 0
        else
            c8 = 0
        end

        local temp
        temp = c1
        c1 = c1 % 0x1000000
        c2 = c2 + (temp - c1) / 0x1000000
        temp = c2
        c2 = c2 % 0x1000000
        c3 = c3 + (temp - c2) / 0x1000000
        temp = c3
        c3 = c3 % 0x1000000
        c4 = c4 + (temp - c3) / 0x1000000
        temp = c4
        c4 = c4 % 0x1000000
        c5 = c5 + (temp - c4) / 0x1000000
        temp = c5
        c5 = c5 % 0x1000000
        c6 = c6 + (temp - c5) / 0x1000000
        temp = c6
        c6 = c6 % 0x1000000
        c7 = c7 + (temp - c6) / 0x1000000
        temp = c7
        c7 = c7 % 0x1000000
        if not half_multiply then
            c8 = c8 + (temp - c7) / 0x1000000
            temp = c8
            c8 = c8 % 0x1000000
            c9 = c9 + (temp - c8) / 0x1000000
            temp = c9
            c9 = c9 % 0x1000000
            c10 = c10 + (temp - c9) / 0x1000000
            temp = c10
            c10 = c10 % 0x1000000
            c11 = c11 + (temp - c10) / 0x1000000
            temp = c11
            c11 = c11 % 0x1000000
            c12 = c12 + (temp - c11) / 0x1000000
            temp = c12
            c12 = c12 % 0x1000000
            c13 = c13 + (temp - c12) / 0x1000000
            temp = c13
            c13 = c13 % 0x1000000
            c14 = c14 + (temp - c13) / 0x1000000
        end

        return {c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14}
    end

    local function square(a)
        -- returns a 336-bit integer (14 words)
        local a1, a2, a3, a4, a5, a6, a7 = unpack(a)
        
        local c1 = a1 * a1
        local c2 = a1 * a2 * 2
        local c3 = a1 * a3 * 2 + a2 * a2
        local c4 = a1 * a4 * 2 + a2 * a3 * 2
        local c5 = a1 * a5 * 2 + a2 * a4 * 2 + a3 * a3
        local c6 = a1 * a6 * 2 + a2 * a5 * 2 + a3 * a4 * 2
        local c7 = a1 * a7 * 2 + a2 * a6 * 2 + a3 * a5 * 2 + a4 * a4
        local c8 = a2 * a7 * 2 + a3 * a6 * 2 + a4 * a5 * 2
        local c9 = a3 * a7 * 2 + a4 * a6 * 2 + a5 * a5
        local c10 = a4 * a7 * 2 + a5 * a6 * 2
        local c11 = a5 * a7 * 2 + a6 * a6
        local c12 = a6 * a7 * 2
        local c13 = a7 * a7
        local c14 = 0

        local temp
        temp = c1
        c1 = c1 % 0x1000000
        c2 = c2 + (temp - c1) / 0x1000000
        temp = c2
        c2 = c2 % 0x1000000
        c3 = c3 + (temp - c2) / 0x1000000
        temp = c3
        c3 = c3 % 0x1000000
        c4 = c4 + (temp - c3) / 0x1000000
        temp = c4
        c4 = c4 % 0x1000000
        c5 = c5 + (temp - c4) / 0x1000000
        temp = c5
        c5 = c5 % 0x1000000
        c6 = c6 + (temp - c5) / 0x1000000
        temp = c6
        c6 = c6 % 0x1000000
        c7 = c7 + (temp - c6) / 0x1000000
        temp = c7
        c7 = c7 % 0x1000000
        c8 = c8 + (temp - c7) / 0x1000000
        temp = c8
        c8 = c8 % 0x1000000
        c9 = c9 + (temp - c8) / 0x1000000
        temp = c9
        c9 = c9 % 0x1000000
        c10 = c10 + (temp - c9) / 0x1000000
        temp = c10
        c10 = c10 % 0x1000000
        c11 = c11 + (temp - c10) / 0x1000000
        temp = c11
        c11 = c11 % 0x1000000
        c12 = c12 + (temp - c11) / 0x1000000
        temp = c12
        c12 = c12 % 0x1000000
        c13 = c13 + (temp - c12) / 0x1000000
        temp = c13
        c13 = c13 % 0x1000000
        c14 = c14 + (temp - c13) / 0x1000000

        return {c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14}
    end

    local function encodeInt(a)
        local enc = {}

        for i = 1, 7 do
            local word = a[i]
            for j = 1, 3 do
                enc[#enc + 1] = word % 256
                word = math.floor(word / 256)
            end
        end

        return enc
    end

    local function decodeInt(enc)
        local a = {}
        local encCopy = {}

        for i = 1, 21 do
            local byte = enc[i]
            assert(type(byte) == "number", "integer decoding failure")
            assert(byte >= 0 and byte <= 255, "integer decoding failure")
            assert(byte % 1 == 0, "integer decoding failure")
            encCopy[i] = byte
        end

        for i = 1, 21, 3 do
            local word = 0
            for j = 2, 0, -1 do
                word = word * 256
                word = word + encCopy[i + j]
            end
            a[#a + 1] = word
        end

        return a
    end

    local function mods(d, w)
        local result = d[1] % 2^w

        if result >= 2^(w - 1) then
            result = result - 2^w
        end

        return result
    end

    -- Represents a 168-bit number as the (2^w)-ary Non-Adjacent Form
    local function NAF(d, w)
        local t = {}
        local d = {unpack(d)}

        for i = 1, 168 do
            if d[1] % 2 == 1 then
                t[#t + 1] = mods(d, w)
                d = sub(d, {t[#t], 0, 0, 0, 0, 0, 0})
            else
                t[#t + 1] = 0
            end

            d = rShift(d)
        end

        return t
    end

    return {
        isEqual = isEqual,
        compare = compare,
        add = add,
        sub = sub,
        addDouble = addDouble,
        mult = mult,
        square = square,
        encodeInt = encodeInt,
        decodeInt = decodeInt,
        NAF = NAF
    }
end)()

-- Arithmetic on the finite field of integers modulo p
-- Where p is the finite field modulus
local modp = (function()
    local add = arith.add
    local sub = arith.sub
    local addDouble = arith.addDouble
    local mult = arith.mult
    local square = arith.square

    local p = {3, 0, 0, 0, 0, 0, 15761408}

    -- We're using the Montgomery Reduction for fast modular multiplication.
    -- https://en.wikipedia.org/wiki/Montgomery_modular_multiplication 
    -- r = 2^168
    -- p * pInverse = -1 (mod r)
    -- r2 = r * r (mod p)
    local pInverse = {5592405, 5592405, 5592405, 5592405, 5592405, 5592405, 14800213}
    local r2 = {13533400, 837116, 6278376, 13533388, 837116, 6278376, 7504076}

    local function multByP(a)
        local a1, a2, a3, a4, a5, a6, a7 = unpack(a)

        local c1 = a1 * 3
        local c2 = a2 * 3
        local c3 = a3 * 3
        local c4 = a4 * 3
        local c5 = a5 * 3
        local c6 = a6 * 3
        local c7 = a1 * 15761408
        c7 = c7 + a7 * 3
        local c8 = a2 * 15761408
        local c9 = a3 * 15761408
        local c10 = a4 * 15761408
        local c11 = a5 * 15761408
        local c12 = a6 * 15761408
        local c13 = a7 * 15761408
        local c14 = 0

        local temp
        temp = c1 / 0x1000000
        c2 = c2 + (temp - temp % 1)
        c1 = c1 % 0x1000000
        temp = c2 / 0x1000000
        c3 = c3 + (temp - temp % 1)
        c2 = c2 % 0x1000000
        temp = c3 / 0x1000000
        c4 = c4 + (temp - temp % 1)
        c3 = c3 % 0x1000000
        temp = c4 / 0x1000000
        c5 = c5 + (temp - temp % 1)
        c4 = c4 % 0x1000000
        temp = c5 / 0x1000000
        c6 = c6 + (temp - temp % 1)
        c5 = c5 % 0x1000000
        temp = c6 / 0x1000000
        c7 = c7 + (temp - temp % 1)
        c6 = c6 % 0x1000000
        temp = c7 / 0x1000000
        c8 = c8 + (temp - temp % 1)
        c7 = c7 % 0x1000000
        temp = c8 / 0x1000000
        c9 = c9 + (temp - temp % 1)
        c8 = c8 % 0x1000000
        temp = c9 / 0x1000000
        c10 = c10 + (temp - temp % 1)
        c9 = c9 % 0x1000000
        temp = c10 / 0x1000000
        c11 = c11 + (temp - temp % 1)
        c10 = c10 % 0x1000000
        temp = c11 / 0x1000000
        c12 = c12 + (temp - temp % 1)
        c11 = c11 % 0x1000000
        temp = c12 / 0x1000000
        c13 = c13 + (temp - temp % 1)
        c12 = c12 % 0x1000000
        temp = c13 / 0x1000000
        c14 = c14 + (temp - temp % 1)
        c13 = c13 % 0x1000000

        return {c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14}
    end

    -- Reduces a number from [0, 2p - 1] to [0, p - 1]
    local function reduceModP(a)
        -- a < p
        if a[7] < 15761408 or a[7] == 15761408 and a[1] < 3 then
            return {unpack(a)}
        end

        -- a > p
        local c1 = a[1]
        local c2 = a[2]
        local c3 = a[3]
        local c4 = a[4]
        local c5 = a[5]
        local c6 = a[6]
        local c7 = a[7]

        c1 = c1 - 3
        c7 = c7 - 15761408

        if c1 < 0 then
            c2 = c2 - 1
            c1 = c1 + 0x1000000
        end
        if c2 < 0 then
            c3 = c3 - 1
            c2 = c2 + 0x1000000
        end
        if c3 < 0 then
            c4 = c4 - 1
            c3 = c3 + 0x1000000
        end
        if c4 < 0 then
            c5 = c5 - 1
            c4 = c4 + 0x1000000
        end
        if c5 < 0 then
            c6 = c6 - 1
            c5 = c5 + 0x1000000
        end
        if c6 < 0 then
            c7 = c7 - 1
            c6 = c6 + 0x1000000
        end

        return {c1, c2, c3, c4, c5, c6, c7}
    end

    local function addModP(a, b)
        return reduceModP(add(a, b))
    end

    local function subModP(a, b)
        local result = sub(a, b)

        if result[7] < 0 then
            result = add(result, p)
        end
        
        return result
    end

    -- Montgomery REDC algorithn
    -- Reduces a number from [0, p^2 - 1] to [0, p - 1]
    local function REDC(T)
        local m = mult(T, pInverse, true)
        local t = {unpack(addDouble(T, multByP(m)), 8, 14)}

        return reduceModP(t)
    end

    local function multModP(a, b)
        -- Only works with a, b in Montgomery form
        return REDC(mult(a, b))
    end

    local function squareModP(a)
        -- Only works with a in Montgomery form
        return REDC(square(a))
    end

    local function montgomeryModP(a)
        return multModP(a, r2)
    end

    local function inverseMontgomeryModP(a)
        local a = {unpack(a)}

        for i = 8, 14 do
            a[i] = 0
        end

        return REDC(a)
    end

    local ONE = montgomeryModP({1, 0, 0, 0, 0, 0, 0})

    local function expModP(base, exponentBinary)
        local base = {unpack(base)}
        local result = {unpack(ONE)}

        for i = 1, 168 do
            if exponentBinary[i] == 1 then
                result = multModP(result, base)
            end
            base = squareModP(base)
        end 

        return result
    end

    return {
        addModP = addModP,
        subModP = subModP,
        multModP = multModP,
        squareModP = squareModP,
        montgomeryModP = montgomeryModP,
        inverseMontgomeryModP = inverseMontgomeryModP,
        expModP = expModP
    }
end)()

-- Arithmetic on the Finite Field of Integers modulo q
-- Where q is the generator's subgroup order.
local modq = (function()
    local isEqual = arith.isEqual
    local compare = arith.compare
    local add = arith.add
    local sub = arith.sub
    local addDouble = arith.addDouble
    local mult = arith.mult
    local square = arith.square
    local encodeInt = arith.encodeInt
    local decodeInt = arith.decodeInt

    local modQMT

    local q = {9622359, 6699217, 13940450, 16775734, 16777215, 16777215, 3940351}
    local qMinusTwoBinary = {1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1}
    
    -- We're using the Montgomery Reduction for fast modular multiplication.
    -- https://en.wikipedia.org/wiki/Montgomery_modular_multiplication 
    -- r = 2^168
    -- q * qInverse = -1 (mod r)
    -- r2 = r * r (mod q)
    local qInverse = {15218585, 5740955, 3271338, 9903997, 9067368, 7173545, 6988392}
    local r2 = {1336213, 11071705, 9716828, 11083885, 9188643, 1494868, 3306114}

    -- Reduces a number from [0, 2q - 1] to [0, q - 1]
    local function reduceModQ(a)
        local result = {unpack(a)}

        if compare(result, q) >= 0 then
            result = sub(result, q)
        end

        return setmetatable(result, modQMT)
    end

    local function addModQ(a, b)
        return reduceModQ(add(a, b))
    end

    local function subModQ(a, b)
        local result = sub(a, b)

        if result[7] < 0 then
            result = add(result, q)
        end
        
        return setmetatable(result, modQMT)
    end

    -- Montgomery REDC algorithn
    -- Reduces a number from [0, q^2 - 1] to [0, q - 1]
    local function REDC(T)
        local m = {unpack(mult({unpack(T, 1, 7)}, qInverse, true), 1, 7)}
        local t = {unpack(addDouble(T, mult(m, q)), 8, 14)}

        return reduceModQ(t)
    end

    local function multModQ(a, b)
        -- Only works with a, b in Montgomery form
        return REDC(mult(a, b))
    end

    local function squareModQ(a)
        -- Only works with a in Montgomery form
        return REDC(square(a))
    end

    local function montgomeryModQ(a)
        return multModQ(a, r2)
    end

    local function inverseMontgomeryModQ(a)
        local a = {unpack(a)}

        for i = 8, 14 do
            a[i] = 0
        end

        return REDC(a)
    end

    local ONE = montgomeryModQ({1, 0, 0, 0, 0, 0, 0})

    local function expModQ(base, exponentBinary)
        local base = {unpack(base)}
        local result = {unpack(ONE)}

        for i = 1, 168 do
            if exponentBinary[i] == 1 then
                result = multModQ(result, base)
            end
            base = squareModQ(base)
        end 

        return result
    end

    local function intExpModQ(base, exponent)
        local base = {unpack(base)}
        local result = setmetatable({unpack(ONE)}, modQMT)

        if exponent < 0 then
            base = expModQ(base, qMinusTwoBinary)
            exponent = -exponent
        end

        while exponent > 0 do
            if exponent % 2 == 1 then
                result = multModQ(result, base)
            end
            base = squareModQ(base)
            exponent = exponent / 2
            exponent = exponent - exponent % 1
        end 

        return result
    end

    local function encodeModQ(a)
        local result = encodeInt(a)

        return setmetatable(result, byteTableMT)
    end

    local function decodeModQ(s)
        s = type(s) == "table" and {unpack(s, 1, 21)} or {tostring(s):byte(1, 21)}
        local result = decodeInt(s)
        result[7] = result[7] % q[7]

        return setmetatable(result, modQMT)
    end

    local function randomModQ()
        while true do
            local s = {unpack(random.random(), 1, 21)}
            local result = decodeInt(s)
            if result[7] < q[7] then
                return setmetatable(result, modQMT)
            end
        end
    end

    local function hashModQ(data)
        return decodeModQ(sha256.digest(data))
    end

    modQMT = {
        __index = {
            encode = function(self)
                return encodeModQ(self)
            end
        },

        __tostring = function(self)
            return self:encode():toHex()
        end,

        __add = function(self, other)
            if type(self) == "number" then
                return other + self
            end

            if type(other) == "number" then
                assert(other < 2^24, "number operand too big")
                other = montgomeryModQ({other, 0, 0, 0, 0, 0, 0})
            end

            return addModQ(self, other)
        end,

        __sub = function(a, b)
            if type(a) == "number" then
                assert(a < 2^24, "number operand too big")
                a = montgomeryModQ({a, 0, 0, 0, 0, 0, 0})
            end

            if type(b) == "number" then
                assert(b < 2^24, "number operand too big")
                b = montgomeryModQ({b, 0, 0, 0, 0, 0, 0})
            end

            return subModQ(a, b)
        end,

        __unm = function(self)
            return subModQ(q, self)
        end,

        __eq = function(self, other)
            return isEqual(self, other)
        end,

        __mul = function(self, other)
            if type(self) == "number" then
                return other * self
            end

            -- EC point
            -- Use the point's metatable to handle multiplication
            if type(other) == "table" and type(other[1]) == "table" then
                return other * self
            end

            if type(other) == "number" then
                assert(other < 2^24, "number operand too big")
                other = montgomeryModQ({other, 0, 0, 0, 0, 0, 0})
            end

            return multModQ(self, other)
        end,

        __div = function(a, b)
            if type(a) == "number" then
                assert(a < 2^24, "number operand too big")
                a = montgomeryModQ({a, 0, 0, 0, 0, 0, 0})
            end

            if type(b) == "number" then
                assert(b < 2^24, "number operand too big")
                b = montgomeryModQ({b, 0, 0, 0, 0, 0, 0})
            end

            local bInv = expModQ(b, qMinusTwoBinary)

            return multModQ(a, bInv)
        end,

        __pow = function(self, other)
            return intExpModQ(self, other)
        end
    }

    return {
        hashModQ = hashModQ,
        randomModQ = randomModQ,
        decodeModQ = decodeModQ,
        inverseMontgomeryModQ = inverseMontgomeryModQ
    }
end)()

-- Elliptic curve arithmetic
local curve = (function()
    ---- About the Curve Itself
    -- Field Size: 168 bits
    -- Field Modulus (p): 481 * 2^159 + 3
    -- Equation: x^2 + y^2 = 1 + 122 * x^2 * y^2
    -- Parameters: Edwards Curve with d = 122
    -- Curve Order (n): 351491143778082151827986174289773107581916088585564
    -- Cofactor (h): 4
    -- Generator Order (q): 87872785944520537956996543572443276895479022146391
    ---- About the Curve's Security
    -- Current best attack security: 81.777 bits (Small Subgroup + Rho)
    -- Rho Security: log2(0.884 * sqrt(q)) = 82.777 bits
    -- Transfer Security? Yes: p ~= q; k > 20
    -- Field Discriminant Security? Yes:
    --    t = 27978492958645335688000168
    --    s = 10
    --    |D| = 6231685068753619775430107799412237267322159383147 > 2^100
    -- Rigidity? No, not at all.
    -- XZ/YZ Ladder Security? No: Single coordinate ladders are insecure.
    -- Small Subgroup Security? No.
    -- Invalid Curve Security? Yes: Points are checked before every operation.
    -- Invalid Curve Twist Security? No: Don't use single coordinate ladders.
    -- Completeness? Yes: The curve is complete.
    -- Indistinguishability? Yes (Elligator 2), but not implemented.

    local isEqual = arith.isEqual
    local NAF = arith.NAF
    local encodeInt = arith.encodeInt
    local decodeInt = arith.decodeInt
    local multModP = modp.multModP
    local squareModP = modp.squareModP
    local addModP = modp.addModP
    local subModP = modp.subModP
    local montgomeryModP = modp.montgomeryModP
    local expModP = modp.expModP
    local inverseMontgomeryModQ = modq.inverseMontgomeryModQ
    
    local pointMT
    local ZERO = {0, 0, 0, 0, 0, 0, 0}
    local ONE = montgomeryModP({1, 0, 0, 0, 0, 0, 0})

    -- Curve Parameters
    local d = montgomeryModP({122, 0, 0, 0, 0, 0, 0})
    local p = {3, 0, 0, 0, 0, 0, 15761408}
    local pMinusTwoBinary = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1}
    local pMinusThreeOverFourBinary = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1}
    local G = {
        {6636044, 10381432, 15741790, 2914241, 5785600, 264923, 4550291},
        {13512827, 8449886, 5647959, 1135556, 5489843, 7177356, 8002203},
        {unpack(ONE)}
    }
    local O = {
        {unpack(ZERO)},
        {unpack(ONE)},
        {unpack(ONE)}
    }

    -- Projective Coordinates for Edwards curves for point addition/doubling.
    -- Points are represented as: (X:Y:Z) where x = X/Z and y = Y/Z
    -- The identity element is represented by (0:1:1)
    -- Point operation formulas are available on the EFD:
    -- https://www.hyperelliptic.org/EFD/g1p/auto-edwards-projective.html
    local function pointDouble(P1)
        -- 3M + 4S
        local X1, Y1, Z1 = unpack(P1)

        local b = addModP(X1, Y1)
        local B = squareModP(b)
        local C = squareModP(X1)
        local D = squareModP(Y1)
        local E = addModP(C, D)
        local H = squareModP(Z1)
        local J = subModP(E, addModP(H, H))
        local X3 = multModP(subModP(B, E), J)
        local Y3 = multModP(E, subModP(C, D))
        local Z3 = multModP(E, J)
        local P3 = {X3, Y3, Z3}

        return setmetatable(P3, pointMT)
    end

    local function pointAdd(P1, P2)
        -- 10M + 1S
        local X1, Y1, Z1 = unpack(P1)
        local X2, Y2, Z2 = unpack(P2)

        local A = multModP(Z1, Z2)
        local B = squareModP(A)
        local C = multModP(X1, X2)
        local D = multModP(Y1, Y2)
        local E = multModP(d, multModP(C, D))
        local F = subModP(B, E)
        local G = addModP(B, E)
        local X3 = multModP(A, multModP(F, subModP(multModP(addModP(X1, Y1), addModP(X2, Y2)), addModP(C, D))))
        local Y3 = multModP(A, multModP(G, subModP(D, C)))
        local Z3 = multModP(F, G)
        local P3 = {X3, Y3, Z3}

        return setmetatable(P3, pointMT)
    end

    local function pointNeg(P1)
        local X1, Y1, Z1 = unpack(P1)

        local X3 = subModP(ZERO, X1)
        local Y3 = {unpack(Y1)}
        local Z3 = {unpack(Z1)}
        local P3 = {X3, Y3, Z3}

        return setmetatable(P3, pointMT)
    end

    local function pointSub(P1, P2)
        return pointAdd(P1, pointNeg(P2))
    end

    -- Converts (X:Y:Z) into (X:Y:1) = (x:y:1)
    local function pointScale(P1)
        local X1, Y1, Z1 = unpack(P1)

        local A = expModP(Z1, pMinusTwoBinary)
        local X3 = multModP(X1, A)
        local Y3 = multModP(Y1, A)
        local Z3 = {unpack(ONE)}
        local P3 = {X3, Y3, Z3}

        return setmetatable(P3, pointMT)
    end

    local function pointIsEqual(P1, P2)
        local X1, Y1, Z1 = unpack(P1)
        local X2, Y2, Z2 = unpack(P2)

        local A1 = multModP(X1, Z2)
        local B1 = multModP(Y1, Z2)
        local A2 = multModP(X2, Z1)
        local B2 = multModP(Y2, Z1)

        return isEqual(A1, A2) and isEqual(B1, B2)
    end

    -- Checks if a projective point satisfies the curve equation
    local function pointIsOnCurve(P1)
        local X1, Y1, Z1 = unpack(P1)

        local X12 = squareModP(X1)
        local Y12 = squareModP(Y1)
        local Z12 = squareModP(Z1)
        local Z14 = squareModP(Z12)
        local a = addModP(X12, Y12)
        a = multModP(a, Z12)
        local b = multModP(d, multModP(X12, Y12))
        b = addModP(Z14, b)

        return isEqual(a, b)
    end

    local function pointIsInf(P1)
        return isEqual(P1[1], ZERO)
    end

    -- W-ary Non-Adjacent Form (wNAF) method for scalar multiplication:
    -- https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#w-ary_non-adjacent_form_(wNAF)_method
    local function scalarMult(multiplier, P1)
        -- w = 5
        local naf = NAF(multiplier, 5)
        local PTable = {P1}
        local P2 = pointDouble(P1)
        local Q = {{unpack(ZERO)}, {unpack(ONE)}, {unpack(ONE)}}

        for i = 3, 31, 2 do
            PTable[i] = pointAdd(PTable[i - 2], P2)
        end

        for i = #naf, 1, -1 do
            Q = pointDouble(Q)
            if naf[i] > 0 then
                Q = pointAdd(Q, PTable[naf[i]])
            elseif naf[i] < 0 then
                Q = pointSub(Q, PTable[-naf[i]])
            end
        end

        return setmetatable(Q, pointMT)
    end

    -- Lookup table 4-ary NAF method for scalar multiplication by G.
    -- Precomputations for the regular NAF method are done before the multiplication.
    local GTable = {G}
    for i = 2, 168 do
        GTable[i] = pointDouble(GTable[i - 1])
    end

    local function scalarMultG(multiplier)
        local naf = NAF(multiplier, 2)
        local Q = {{unpack(ZERO)}, {unpack(ONE)}, {unpack(ONE)}}

        for i = 1, 168 do
            if naf[i] == 1 then
                Q = pointAdd(Q, GTable[i])
            elseif naf[i] == -1 then
                Q = pointSub(Q, GTable[i])
            end
        end

        return setmetatable(Q, pointMT)
    end

    -- Point compression and encoding.
    -- Compresses curve points to 22 bytes.
    local function pointEncode(P1)
        P1 = pointScale(P1)
        local result = {}
        local x, y = unpack(P1)

        -- Encode y
        result = encodeInt(y)
        -- Encode one bit from x
        result[22] = x[1] % 2

        return setmetatable(result, byteTableMT)
    end

    local function pointDecode(enc)
        enc = type(enc) == "table" and {unpack(enc, 1, 22)} or {tostring(enc):byte(1, 22)}
        -- Decode y
        local y = decodeInt(enc)
        y[7] = y[7] % p[7]
        -- Find {x, -x} using curve equation
        local y2 = squareModP(y)
        local u = subModP(y2, ONE)
        local v = subModP(multModP(d, y2), ONE)
        local u2 = squareModP(u)
        local u3 = multModP(u, u2)
        local u5 = multModP(u3, u2)
        local v3 = multModP(v, squareModP(v))
        local w = multModP(u5, v3)
        local x = multModP(u3, multModP(v, expModP(w, pMinusThreeOverFourBinary)))
        -- Use enc[22] to find x from {x, -x}
        if x[1] % 2 ~= enc[22] then
            x = subModP(ZERO, x)
        end
        local P3 = {x, y, {unpack(ONE)}}

        return setmetatable(P3, pointMT)
    end

    pointMT = {
        __index = {
            isOnCurve = function(self)
                return pointIsOnCurve(self)
            end,

            isInf = function(self)
                return self:isOnCurve() and pointIsInf(self)
            end,

            encode = function(self)
                return pointEncode(self)
            end
        },

        __tostring = function(self)
            return self:encode():toHex()
        end,

        __add = function(P1, P2)
            assert(P1:isOnCurve(), "invalid point")
            assert(P2:isOnCurve(), "invalid point")
            
            return pointAdd(P1, P2)
        end,

        __sub = function(P1, P2)
            assert(P1:isOnCurve(), "invalid point")
            assert(P2:isOnCurve(), "invalid point")
            
            return pointSub(P1, P2)
        end,

        __unm = function(self)
            assert(self:isOnCurve(), "invalid point")
            
            return pointNeg(self)
        end,

        __eq = function(P1, P2)
            assert(P1:isOnCurve(), "invalid point")
            assert(P2:isOnCurve(), "invalid point")
            
            return pointIsEqual(P1, P2)
        end,

        __mul = function(P1, s)
            if type(P1) == "number" then
                return s * P1
            end

            if type(s) == "number" then
                assert(s < 2^24, "number multiplier too big")
                s = {s, 0, 0, 0, 0, 0, 0}
            else
                s = inverseMontgomeryModQ(s)
            end

            if P1 == G then
                return scalarMultG(s)
            else
                return scalarMult(s, P1)
            end
        end
    }

    G = setmetatable(G, pointMT)
    O = setmetatable(O, pointMT)

    return {
        G = G,
        O = O,
        pointDecode = pointDecode
    }
end)()

local function getNonceFromEpoch()
    local nonce = {}
    local epoch = os.epoch("utc")
    for i = 1, 12 do
        nonce[#nonce + 1] = epoch % 256
        epoch = epoch / 256
        epoch = epoch - epoch % 1
    end

    return nonce
end

local function encrypt(data, key)
    local encKey = sha256.hmac("encKey", key)
    local macKey = sha256.hmac("macKey", key)
    local nonce = getNonceFromEpoch()
    local ciphertext = chacha20.crypt(data, encKey, nonce)
    local result = nonce
    for i = 1, #ciphertext do
        result[#result + 1] = ciphertext[i]
    end
    local mac = sha256.hmac(result, macKey)
    for i = 1, #mac do
        result[#result + 1] = mac[i]
    end

    return setmetatable(result, byteTableMT)
end

local function decrypt(data, key)
    local data = type(data) == "table" and {unpack(data)} or {tostring(data):byte(1,-1)}
    local encKey = sha256.hmac("encKey", key)
    local macKey = sha256.hmac("macKey", key)
    local mac = sha256.hmac({unpack(data, 1, #data - 32)}, macKey)
    local messageMac = {unpack(data, #data - 31)}
    assert(mac:isEqual(messageMac), "invalid mac")
    local nonce = {unpack(data, 1, 12)}
    local ciphertext = {unpack(data, 13, #data - 32)}
    local result = chacha20.crypt(ciphertext, encKey, nonce)

    return setmetatable(result, byteTableMT)
end

local function keypair(seed)
    local x
    if seed then
        x = modq.hashModQ(seed)
    else
        x = modq.randomModQ()
    end
    local Y = curve.G * x

    local privateKey = x:encode()
    local publicKey = Y:encode()

    return privateKey, publicKey
end

local function exchange(privateKey, publicKey)
    local x = modq.decodeModQ(privateKey)
    local Y = curve.pointDecode(publicKey)

    local Z = Y * x

    local sharedSecret = sha256.digest(Z:encode())

    return sharedSecret
end

local function sign(privateKey, message)
    local message = type(message) == "table" and string.char(unpack(message)) or tostring(message)
    local privateKey = type(privateKey) == "table" and string.char(unpack(privateKey)) or tostring(privateKey)
    local x = modq.decodeModQ(privateKey)
    local k = modq.randomModQ()
    local R = curve.G * k
    local e = modq.hashModQ(message .. tostring(R))
    local s = k - x * e

    e = e:encode()
    s = s:encode()

    local result = e
    for i = 1, #s do
        result[#result + 1] = s[i]
    end

    return setmetatable(result, byteTableMT)
end

local function verify(publicKey, message, signature)
    local message = type(message) == "table" and string.char(unpack(message)) or tostring(message)
    local Y = curve.pointDecode(publicKey)
    local e = modq.decodeModQ({unpack(signature, 1, #signature / 2)})
    local s = modq.decodeModQ({unpack(signature, #signature / 2 + 1)})
    local Rv = curve.G * s + Y * e
    local ev = modq.hashModQ(message .. tostring(Rv))

    return ev == e
end

return {
    chacha20 = chacha20,
    sha256 = sha256,
    random = random,
    encrypt = encrypt,
    decrypt = decrypt,
    keypair = keypair,
    exchange = exchange,
    sign = sign,
    verify = verify
}