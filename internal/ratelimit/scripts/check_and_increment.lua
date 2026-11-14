-- Atomic Single-Roundtrip Multi-Scope Rate Limiter & Budget Guard
-- KEYS[1]:  key_rpm,  KEYS[2]:  key_tpm,  KEYS[3]:  key_conc,  KEYS[4]:  key_spend
-- KEYS[5]:  team_rpm, KEYS[6]:  team_tpm, KEYS[7]:  team_spend
-- KEYS[8]:  user_rpm, KEYS[9]:  user_tpm, KEYS[10]: user_conc, KEYS[11]: user_spend
-- KEYS[12]: org_rpm,  KEYS[13]: org_tpm,  KEYS[14]: org_spend
-- KEYS[15..17]: key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[18..20]: team_res_zset, team_res_sum, team_res_amounts
-- KEYS[21..23]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[24..26]: org_res_zset,  org_res_sum,  org_res_amounts
-- ARGV[1..4]:   limit_key_rpm,  limit_key_tpm,  limit_key_conc,  max_key_budget_micros
-- ARGV[5..7]:   limit_team_rpm, limit_team_tpm, max_team_budget_micros
-- ARGV[8..11]:  limit_user_rpm, limit_user_tpm, limit_user_conc, max_user_budget_micros
-- ARGV[12..14]: limit_org_rpm,  limit_org_tpm,  max_org_budget_micros
-- ARGV[15]: estimated_tokens, ARGV[16]: window_ttl_sec, ARGV[17]: conc_ttl_sec
-- ARGV[18]: budget_reservation_micros, ARGV[19]: request_id, ARGV[20]: reservation_ttl_sec

local est_tokens = tonumber(ARGV[15])
local window_ttl = tonumber(ARGV[16])
local conc_ttl   = tonumber(ARGV[17])
local reserve = tonumber(ARGV[18]) or 0
local request_id = ARGV[19] or ""
local reservation_ttl = tonumber(ARGV[20]) or 3600
local now = tonumber(redis.call("TIME")[1])

local function cleanup_expired(res_zset, res_sum, res_amounts)
    local expired = redis.call("ZRANGEBYSCORE", res_zset, "-inf", now)
    if #expired > 0 then
        local total_expired = 0
        for _, req_id in ipairs(expired) do
            local amt = tonumber(redis.call("HGET", res_amounts, req_id) or "0")
            if amt > 0 then
                total_expired = total_expired + amt
            end
            redis.call("HDEL", res_amounts, req_id)
        end
        redis.call("ZREMRANGEBYSCORE", res_zset, "-inf", now)
        if total_expired > 0 then
            local rem = redis.call("DECRBY", res_sum, total_expired)
            if rem < 0 then
                redis.call("SET", res_sum, 0)
            end
        end
    end
end

local function check_budget(spend_key, res_zset, res_sum, res_amounts, max_b, code)
    if max_b > 0 then
        local cur = tonumber(redis.call("GET", spend_key) or "0")
        if reserve <= 0 or request_id == "" then
            return {0, "BUDGET_ESTIMATE_REQUIRED", cur, max_b}
        end
        cleanup_expired(res_zset, res_sum, res_amounts)
        if redis.call("HEXISTS", res_amounts, request_id) == 1 then
            return {0, "BUDGET_RESERVATION_CONFLICT", cur, max_b}
        end
        local reserved = tonumber(redis.call("GET", res_sum) or "0")
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
err = check_budget(KEYS[4],  KEYS[15], KEYS[16], KEYS[17], tonumber(ARGV[4]),  "KEY_BUDGET_EXCEEDED");  if err then return err end
err = check_budget(KEYS[7],  KEYS[18], KEYS[19], KEYS[20], tonumber(ARGV[7]),  "TEAM_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[11], KEYS[21], KEYS[22], KEYS[23], tonumber(ARGV[11]), "USER_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[14], KEYS[24], KEYS[25], KEYS[26], tonumber(ARGV[14]), "ORG_BUDGET_EXCEEDED");  if err then return err end

err = check_quota(KEYS[1],  1,          tonumber(ARGV[1]),  "KEY_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[2],  est_tokens, tonumber(ARGV[2]),  "KEY_TPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[3],  1,          tonumber(ARGV[3]),  "KEY_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[5],  1,          tonumber(ARGV[5]),  "TEAM_RPM_EXCEEDED");        if err then return err end
err = check_quota(KEYS[6],  est_tokens, tonumber(ARGV[6]),  "TEAM_TPM_EXCEEDED");        if err then return err end
err = check_quota(KEYS[8],  1,          tonumber(ARGV[8]),  "USER_RPM_EXCEEDED");        if err then return err end
err = check_quota(KEYS[9],  est_tokens, tonumber(ARGV[9]),  "USER_TPM_EXCEEDED");        if err then return err end
err = check_quota(KEYS[10], 1,          tonumber(ARGV[10]), "USER_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[12], 1,          tonumber(ARGV[12]), "ORG_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[13], est_tokens, tonumber(ARGV[13]), "ORG_TPM_EXCEEDED");         if err then return err end

local function incr_ttl(key, delta, ttl)
    local v = redis.call("INCRBY", key, delta)
    if v == delta then
        redis.call("EXPIRE", key, ttl)
    end
    return v
end

local function incr_conc_ttl(key, delta, ttl)
    local v = redis.call("INCRBY", key, delta)
    redis.call("EXPIRE", key, ttl)
    return v
end

local new_rpm = incr_ttl(KEYS[1], 1, window_ttl)
local new_tpm = incr_ttl(KEYS[2], est_tokens, window_ttl)
incr_conc_ttl(KEYS[3], 1, conc_ttl)

if tonumber(ARGV[5]) > 0 then incr_ttl(KEYS[5], 1, window_ttl) end
if tonumber(ARGV[6]) > 0 then incr_ttl(KEYS[6], est_tokens, window_ttl) end
if tonumber(ARGV[8]) > 0 then incr_ttl(KEYS[8], 1, window_ttl) end
if tonumber(ARGV[9]) > 0 then incr_ttl(KEYS[9], est_tokens, window_ttl) end
if tonumber(ARGV[10]) > 0 then incr_conc_ttl(KEYS[10], 1, conc_ttl) end
if tonumber(ARGV[12]) > 0 then incr_ttl(KEYS[12], 1, window_ttl) end
if tonumber(ARGV[13]) > 0 then incr_ttl(KEYS[13], est_tokens, window_ttl) end

if reserve > 0 and request_id ~= "" then
    local expires = now + reservation_ttl
    local scopes = {
        {tonumber(ARGV[4]),  KEYS[15], KEYS[16], KEYS[17]},
        {tonumber(ARGV[7]),  KEYS[18], KEYS[19], KEYS[20]},
        {tonumber(ARGV[11]), KEYS[21], KEYS[22], KEYS[23]},
        {tonumber(ARGV[14]), KEYS[24], KEYS[25], KEYS[26]},
    }
    for _, sc in ipairs(scopes) do
        if sc[1] > 0 then
            redis.call("ZADD", sc[2], expires, request_id)
            redis.call("INCRBY", sc[3], reserve)
            redis.call("HSET", sc[4], request_id, reserve)
            redis.call("EXPIRE", sc[2], reservation_ttl + 60)
            redis.call("EXPIRE", sc[3], reservation_ttl + 60)
            redis.call("EXPIRE", sc[4], reservation_ttl + 60)
        end
    end
end

return {1, "OK", new_rpm, new_tpm}
