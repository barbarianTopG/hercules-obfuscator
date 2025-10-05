local AntiTamper = {}

function AntiTamper.process(code)
    local anti_tamper_code = [[
do
    local D = debug
    local T = type
    local P = pcall
    local X = xpcall
    local S = tostring
    local E = error
    local RG = rawget
    local RS = rawset
    local RE = rawequal
    local Pa = pairs
    local CG = collectgarbage
    local Sel = select
    local C = coroutine
    local GM = getmetatable
    local SM = setmetatable
    local G = getfenv and getfenv() or _G

    local function safe(p, ...)
        local ok, r = P(p, ...)
        return ok and r or nil
    end

    local function dbgOK()
        if T(D) ~= "table" then return false end
        for _, k in Pa{"getinfo","getlocal","getupvalue","traceback"} do
            if T(D[k]) ~= "function" then return false end
        end
        return true
    end

    if not dbgOK() then
        E("Tamper Detected! Reason: Debug library incomplete or sandboxed")
        return
    end

    local function isNative(f)
        local info = safe(D.getinfo, f)
        return info and info.what == "C"
    end

    local function checkMetatables()
        local targets = {string, table, math, os, G}
        for _, t in Pa(targets) do
            local mt = GM(t)
            if mt then
                for _, m in Pa{"__index","__newindex","__call","__metatable"} do
                    local f = mt[m]
                    if f and T(f) == "function" and not isNative(f) then
                        return false, "Metamethod tampered: " .. m
                    end
                end
            end
        end
        return true
    end

    local function checkNativeFuncs()
        local natives = {
            P,X,assert,E,print,RG,RS,RE,tonumber,S,T,
            Sel,next,ipairs,Pa,CG,GM,SM,
            loadstring,collectgarbage,
            D.getinfo,D.getlocal,D.getupvalue,D.traceback,
            C.create,C.resume,C.yield,C.status
        }
        for _, fn in Pa(natives) do
            if T(fn) == "function" and not isNative(fn) then
                return false, "Native function hooked: " .. S(fn)
            end
        end
        return true
    end

    local function checkGlobals()
        for _, k in Pa({"pcall","xpcall","type","tostring","string","table","debug","coroutine","math","os"}) do
            if T(G[k]) ~= T(_G[k]) then
                return false, "Global modified: " .. k
            end
        end
        return true
    end

    local function checkFuncs()
        for lvl = 2, 4 do
            local info = safe(D.getinfo, lvl, "f")
            if info and info.func then
                local u = 1
                while true do
                    local n, v = D.getupvalue(info.func, u)
                    if not n then break end
                    if T(v) == "function" then
                        local i = D.getinfo(v, "Sl")
                        if i and i.linedefined ~= i.lastlinedefined then
                            return false, "Suspicious upvalue: " .. n
                        end
                    end
                    u += 1
                end
            end
        end
        return true
    end

    local function run()
        local ok, reason = checkNativeFuncs()
        if not ok then return false, reason end
        ok, reason = checkMetatables()
        if not ok then return false, reason end
        ok, reason = checkGlobals()
        if not ok then return false, reason end
        ok, reason = checkFuncs()
        if not ok then return false, reason end
        return true
    end

    local ok, reason = run()
    if not ok then
          while true do
              E("Tamper Detected! Reason: " .. S(reason))
          end
    end
end
]]
    return anti_tamper_code .. "\n" .. code
end

return AntiTamper
