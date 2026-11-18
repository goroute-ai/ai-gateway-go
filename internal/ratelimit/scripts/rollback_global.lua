-- Rollback global counters when a multi-phase admission rejects after global increment.
-- KEYS[1]: global_rpm, KEYS[2]: global_tpm, KEYS[3]: global_conc
-- ARGV[1]: limit_global_rpm, ARGV[2]: limit_global_tpm, ARGV[3]: limit_global_conc, ARGV[4]: estimated_tokens

local limit_rpm  = tonumber(ARGV[1]) or 0
local limit_tpm  = tonumber(ARGV[2]) or 0
local limit_conc = tonumber(ARGV[3]) or 0
local est_tokens = tonumber(ARGV[4]) or 1

local function decr_floor(key, delta)
    if key ~= "" and delta > 0 then
        local cur = tonumber(redis.call("GET", key) or "0")
        if cur > 0 then
            local v = redis.call("DECRBY", key, delta)
            if v < 0 then
                redis.call("SET", key, 0, "KEEPTTL")
            end
        end
    end
end

if limit_rpm > 0 then decr_floor(KEYS[1], 1) end
if limit_tpm > 0 then decr_floor(KEYS[2], est_tokens) end
if limit_conc > 0 then decr_floor(KEYS[3], 1) end

return 1
