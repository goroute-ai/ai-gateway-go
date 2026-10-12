-- Post-Request Token Reconciliation & Concurrency Release
-- KEYS[1]: key_conc, KEYS[2]: key_tpm, KEYS[3]: team_tpm, KEYS[4]: org_tpm
-- ARGV[1]: token_delta, ARGV[2]: window_ttl_sec

local delta = tonumber(ARGV[1])
local ttl   = tonumber(ARGV[2])

local conc = tonumber(redis.call("GET", KEYS[1]) or "0")
if conc > 0 then
    redis.call("DECR", KEYS[1])
end

if delta ~= 0 then
    for i = 2, 4 do
        if KEYS[i] ~= "" then
            local v = redis.call("INCRBY", KEYS[i], delta)
            if v < 0 then
                redis.call("SET", KEYS[i], 0, "EX", ttl)
            end
        end
    end
end

return 1
