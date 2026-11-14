-- Global Post-Request Token Reconciliation & Concurrency Release
-- KEYS[1]: global_conc, KEYS[2]: global_tpm
-- ARGV[1]: token_delta, ARGV[2]: window_ttl_sec, ARGV[3]: limit_global_tpm, ARGV[4]: limit_global_conc

local delta = tonumber(ARGV[1]) or 0
local ttl   = tonumber(ARGV[2]) or 120
local limit_tpm  = tonumber(ARGV[3]) or 0
local limit_conc = tonumber(ARGV[4]) or 0

if limit_conc > 0 and KEYS[1] ~= "" then
    local conc = tonumber(redis.call("GET", KEYS[1]) or "0")
    if conc > 0 then
        redis.call("DECR", KEYS[1])
    end
end

if limit_tpm > 0 and delta ~= 0 and KEYS[2] ~= "" then
    local v = redis.call("INCRBY", KEYS[2], delta)
    if v < 0 then
        redis.call("SET", KEYS[2], 0, "EX", ttl)
    elseif redis.call("TTL", KEYS[2]) == -1 then
        redis.call("EXPIRE", KEYS[2], ttl)
    end
end

return 1
