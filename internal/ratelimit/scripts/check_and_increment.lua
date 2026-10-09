-- Atomic Single-Roundtrip Multi-Scope Rate Limiter & Budget Guard
-- KEYS[1]: key_rpm, KEYS[2]: key_tpm, KEYS[3]: key_conc, KEYS[4]: key_spend
-- KEYS[5]: team_rpm, KEYS[6]: team_tpm, KEYS[7]: team_spend
-- KEYS[8]: org_rpm,  KEYS[9]: org_tpm,  KEYS[10]: org_spend
-- ARGV[1]: limit_key_rpm,  ARGV[2]: limit_key_tpm,  ARGV[3]: limit_key_conc, ARGV[4]: max_key_budget_micros
-- ARGV[5]: limit_team_rpm, ARGV[6]: limit_team_tpm, ARGV[7]: max_team_budget_micros
-- ARGV[8]: limit_org_rpm,  ARGV[9]: limit_org_tpm,  ARGV[10]: max_org_budget_micros
-- ARGV[11]: estimated_tokens, ARGV[12]: window_ttl_sec, ARGV[13]: conc_ttl_sec

local est_tokens = tonumber(ARGV[11])
local window_ttl = tonumber(ARGV[12])
local conc_ttl   = tonumber(ARGV[13])

local function check_budget(key, max_b, code)
    if max_b > 0 then
        local cur = tonumber(redis.call("GET", key) or "0")
        if cur >= max_b then
            return {0, code, cur, max_b}
        end
    end
    return nil
end

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
err = check_budget(KEYS[4],  tonumber(ARGV[4]),  "KEY_BUDGET_EXCEEDED");  if err then return err end
err = check_budget(KEYS[7],  tonumber(ARGV[7]),  "TEAM_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[10], tonumber(ARGV[10]), "ORG_BUDGET_EXCEEDED");  if err then return err end

err = check_quota(KEYS[1], 1,          tonumber(ARGV[1]), "KEY_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[2], est_tokens, tonumber(ARGV[2]), "KEY_TPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[3], 1,          tonumber(ARGV[3]), "KEY_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[5], 1,          tonumber(ARGV[5]), "TEAM_RPM_EXCEEDED");        if err then return err end
err = check_quota(KEYS[6], est_tokens, tonumber(ARGV[6]), "TEAM_TPM_EXCEEDED");        if err then return err end
err = check_quota(KEYS[8], 1,          tonumber(ARGV[8]), "ORG_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[9], est_tokens, tonumber(ARGV[9]), "ORG_TPM_EXCEEDED");         if err then return err end

local function incr_ttl(key, delta, ttl)
    local v = redis.call("INCRBY", key, delta)
    if v == delta then
        redis.call("EXPIRE", key, ttl)
    end
    return v
end

local new_rpm = incr_ttl(KEYS[1], 1, window_ttl)
local new_tpm = incr_ttl(KEYS[2], est_tokens, window_ttl)
incr_ttl(KEYS[3], 1, conc_ttl)

if tonumber(ARGV[5]) > 0 then incr_ttl(KEYS[5], 1, window_ttl) end
if tonumber(ARGV[6]) > 0 then incr_ttl(KEYS[6], est_tokens, window_ttl) end
if tonumber(ARGV[8]) > 0 then incr_ttl(KEYS[8], 1, window_ttl) end
if tonumber(ARGV[9]) > 0 then incr_ttl(KEYS[9], est_tokens, window_ttl) end

return {1, "OK", new_rpm, new_tpm}
