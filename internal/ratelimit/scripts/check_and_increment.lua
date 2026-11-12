-- Atomic Single-Roundtrip Multi-Scope Rate Limiter & Budget Guard
-- KEYS[1]: key_rpm, KEYS[2]: key_tpm, KEYS[3]: key_conc, KEYS[4]: key_spend
-- KEYS[5]: team_rpm, KEYS[6]: team_tpm, KEYS[7]: team_spend
-- KEYS[8]: org_rpm,  KEYS[9]: org_tpm,  KEYS[10]: org_spend
-- ARGV[1]: limit_key_rpm,  ARGV[2]: limit_key_tpm,  ARGV[3]: limit_key_conc, ARGV[4]: max_key_budget_micros
-- ARGV[5]: limit_team_rpm, ARGV[6]: limit_team_tpm, ARGV[7]: max_team_budget_micros
-- ARGV[8]: limit_org_rpm,  ARGV[9]: limit_org_tpm,  ARGV[10]: max_org_budget_micros
-- ARGV[11]: estimated_tokens, ARGV[12]: window_ttl_sec, ARGV[13]: conc_ttl_sec
-- ARGV[14]: budget_reservation_micros, ARGV[15]: request_id, ARGV[16]: reservation_ttl_sec
-- KEYS[11..13]: key/team/org reservation sorted sets

local est_tokens = tonumber(ARGV[11])
local window_ttl = tonumber(ARGV[12])
local conc_ttl   = tonumber(ARGV[13])
local reserve = tonumber(ARGV[14]) or 0
local request_id = ARGV[15] or ""
local reservation_ttl = tonumber(ARGV[16]) or 3600
local now = tonumber(redis.call("TIME")[1])

local function check_budget(key, reservations, max_b, code)
    if max_b > 0 then
        local cur = tonumber(redis.call("GET", key) or "0")
        if reserve < 0 or request_id == "" then
            return {0, "BUDGET_ESTIMATE_REQUIRED", cur, max_b}
        end
        redis.call("ZREMRANGEBYSCORE", reservations, "-inf", now)
        if reserve > 0 and redis.call("ZSCORE", reservations, request_id .. "|" .. tostring(reserve)) then
            return {0, "BUDGET_RESERVATION_CONFLICT", cur, max_b}
        end
        local reserved = 0
        local active = redis.call("ZRANGE", reservations, 0, -1)
        for _, member in ipairs(active) do
            local amount = tonumber(string.match(member, "|(%d+)$"))
            if amount then reserved = reserved + amount end
        end
        if cur + reserved + reserve > max_b then
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
err = check_budget(KEYS[4],  KEYS[11], tonumber(ARGV[4]),  "KEY_BUDGET_EXCEEDED");  if err then return err end
err = check_budget(KEYS[7],  KEYS[12], tonumber(ARGV[7]), "TEAM_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[10], KEYS[13], tonumber(ARGV[10]), "ORG_BUDGET_EXCEEDED");  if err then return err end

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

if reserve > 0 then
    local member = request_id .. "|" .. tostring(reserve)
    local expires = now + reservation_ttl
    for i = 11, 13 do
        if tonumber(ARGV[(i - 11) * 3 + 4]) > 0 then
            redis.call("ZADD", KEYS[i], expires, member)
            redis.call("EXPIRE", KEYS[i], reservation_ttl + 60)
        end
    end
end

return {1, "OK", new_rpm, new_tpm}
