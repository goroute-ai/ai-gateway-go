-- Atomic Global Rate Limiter (single {global} cluster slot)
-- KEYS[1]: global_rpm, KEYS[2]: global_tpm, KEYS[3]: global_conc
-- ARGV[1]: limit_global_rpm, ARGV[2]: limit_global_tpm, ARGV[3]: limit_global_conc
-- ARGV[4]: estimated_tokens, ARGV[5]: window_ttl_sec, ARGV[6]: conc_ttl_sec

local limit_rpm  = tonumber(ARGV[1]) or 0
local limit_tpm  = tonumber(ARGV[2]) or 0
local limit_conc = tonumber(ARGV[3]) or 0
local est_tokens = tonumber(ARGV[4]) or 1
local window_ttl = tonumber(ARGV[5]) or 120
local conc_ttl   = tonumber(ARGV[6]) or 300

local function check_quota(key, delta, limit, code)
    if limit > 0 then
        local cur = tonumber(redis.call("GET", key) or "0")
        if (cur + delta) > limit then
            return {0, code, cur, limit}
        end
    end
    return nil
end

local err
err = check_quota(KEYS[1], 1,          limit_rpm,  "GLOBAL_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[2], est_tokens, limit_tpm,  "GLOBAL_TPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[3], 1,          limit_conc, "GLOBAL_CONCURRENCY_EXCEEDED"); if err then return err end

local function incr_ttl(key, delta, ttl)
    local v = redis.call("INCRBY", key, delta)
    if v == delta then
        redis.call("EXPIRE", key, ttl)
    end
    return v
end

local new_rpm = 0
local new_tpm = 0
if limit_rpm > 0 then new_rpm = incr_ttl(KEYS[1], 1, window_ttl) end
if limit_tpm > 0 then new_tpm = incr_ttl(KEYS[2], est_tokens, window_ttl) end
if limit_conc > 0 then
    redis.call("INCRBY", KEYS[3], 1)
    redis.call("EXPIRE", KEYS[3], conc_ttl)
end

return {1, "OK", new_rpm, new_tpm}
