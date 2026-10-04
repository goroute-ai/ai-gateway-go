-- Atomic Global Rate Limiter (single {global} cluster slot, self-healing ZSET concurrency)
-- KEYS[1]: global_rpm, KEYS[2]: global_tpm, KEYS[3]: global_zconc
-- ARGV[1]: limit_global_rpm, ARGV[2]: limit_global_tpm, ARGV[3]: limit_global_conc
-- ARGV[4]: estimated_tokens, ARGV[5]: window_ttl_sec, ARGV[6]: conc_ttl_sec, ARGV[7]: request_id

local limit_rpm  = tonumber(ARGV[1]) or 0
local limit_tpm  = tonumber(ARGV[2]) or 0
local limit_conc = tonumber(ARGV[3]) or 0
local est_tokens = tonumber(ARGV[4]) or 1
local window_ttl = tonumber(ARGV[5]) or 120
local conc_ttl   = tonumber(ARGV[6]) or 300
local request_id = ARGV[7] or ""

local now = tonumber(redis.call("TIME")[1])
local retry_min = 60 - (now % 60)
if retry_min <= 0 then retry_min = 60 end

local function check_quota(key, delta, limit, code)
    if limit > 0 then
        local cur = tonumber(redis.call("GET", key) or "0")
        if (cur + delta) > limit then
            return {0, code, cur, limit, retry_min}
        end
    end
    return nil
end

local function check_conc(zkey, limit, code)
    if limit > 0 then
        redis.call("ZREMRANGEBYSCORE", zkey, "-inf", now)
        local cur = tonumber(redis.call("ZCARD", zkey) or "0")
        if (cur + 1) > limit then
            return {0, code, cur, limit, 5}
        end
    end
    return nil
end

local err
err = check_quota(KEYS[1], 1,          limit_rpm,  "GLOBAL_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[2], est_tokens, limit_tpm,  "GLOBAL_TPM_EXCEEDED");         if err then return err end
err = check_conc (KEYS[3],             limit_conc, "GLOBAL_CONCURRENCY_EXCEEDED"); if err then return err end

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
if limit_conc > 0 and request_id ~= "" then
    redis.call("ZADD", KEYS[3], now + conc_ttl, request_id)
    redis.call("EXPIRE", KEYS[3], conc_ttl + 60)
end

local rem_req = 0
if limit_rpm > 0 then
    rem_req = limit_rpm - new_rpm
    if rem_req < 0 then rem_req = 0 end
end
local rem_tok = 0
if limit_tpm > 0 then
    rem_tok = limit_tpm - new_tpm
    if rem_tok < 0 then rem_tok = 0 end
end

return {1, "OK", limit_rpm, rem_req, retry_min, limit_tpm, rem_tok, retry_min}
