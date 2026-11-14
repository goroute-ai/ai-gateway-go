-- Atomic Single-Roundtrip Multi-Scope Rate Limiter & Budget Guard
-- KEYS[1]:  key_rpm,  KEYS[2]:  key_tpm,  KEYS[3]:  key_conc,  KEYS[4]:  key_spend
-- KEYS[5]:  team_rpm, KEYS[6]:  team_tpm, KEYS[7]:  team_conc, KEYS[8]:  team_spend
-- KEYS[9]:  user_rpm, KEYS[10]: user_tpm, KEYS[11]: user_conc, KEYS[12]: user_spend
-- KEYS[13]: org_rpm,  KEYS[14]: org_tpm,  KEYS[15]: org_conc,  KEYS[16]: org_spend
-- KEYS[17..19]: key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[20..22]: team_res_zset, team_res_sum, team_res_amounts
-- KEYS[23..25]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[26..28]: org_res_zset,  org_res_sum,  org_res_amounts
-- ARGV[1..5]:   limit_key_rpm,  limit_key_tpm,  limit_key_conc,  max_key_budget_micros,  key_spent_floor_micros
-- ARGV[6..10]:  limit_team_rpm, limit_team_tpm, limit_team_conc, max_team_budget_micros, team_spent_floor_micros
-- ARGV[11..15]: limit_user_rpm, limit_user_tpm, limit_user_conc, max_user_budget_micros, user_spent_floor_micros
-- ARGV[16..20]: limit_org_rpm,  limit_org_tpm,  limit_org_conc,  max_org_budget_micros,  org_spent_floor_micros
-- ARGV[21]: estimated_tokens, ARGV[22]: window_ttl_sec, ARGV[23]: conc_ttl_sec
-- ARGV[24]: budget_reservation_micros, ARGV[25]: request_id, ARGV[26]: reservation_ttl_sec

local est_tokens = tonumber(ARGV[21])
local window_ttl = tonumber(ARGV[22])
local conc_ttl   = tonumber(ARGV[23])
local reserve = tonumber(ARGV[24]) or 0
local request_id = ARGV[25] or ""
local reservation_ttl = tonumber(ARGV[26]) or 3600
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

local function check_budget(spend_key, res_zset, res_sum, res_amounts, max_b, db_floor, code)
    local redis_spent = tonumber(redis.call("GET", spend_key) or "0")
    local cur = math.max(redis_spent, db_floor)
    if cur > redis_spent then
        redis.call("SET", spend_key, cur)
    end
    if max_b > 0 then
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
err = check_budget(KEYS[4],  KEYS[17], KEYS[18], KEYS[19], tonumber(ARGV[4]) or 0,  tonumber(ARGV[5]) or 0,  "KEY_BUDGET_EXCEEDED");  if err then return err end
err = check_budget(KEYS[8],  KEYS[20], KEYS[21], KEYS[22], tonumber(ARGV[9]) or 0,  tonumber(ARGV[10]) or 0, "TEAM_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[12], KEYS[23], KEYS[24], KEYS[25], tonumber(ARGV[14]) or 0, tonumber(ARGV[15]) or 0, "USER_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[16], KEYS[26], KEYS[27], KEYS[28], tonumber(ARGV[19]) or 0, tonumber(ARGV[20]) or 0, "ORG_BUDGET_EXCEEDED");  if err then return err end

err = check_quota(KEYS[1],  1,          tonumber(ARGV[1]),  "KEY_RPM_EXCEEDED");          if err then return err end
err = check_quota(KEYS[2],  est_tokens, tonumber(ARGV[2]),  "KEY_TPM_EXCEEDED");          if err then return err end
err = check_quota(KEYS[3],  1,          tonumber(ARGV[3]),  "KEY_CONCURRENCY_EXCEEDED");  if err then return err end
err = check_quota(KEYS[5],  1,          tonumber(ARGV[6]),  "TEAM_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[6],  est_tokens, tonumber(ARGV[7]),  "TEAM_TPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[7],  1,          tonumber(ARGV[8]),  "TEAM_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[9],  1,          tonumber(ARGV[11]), "USER_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[10], est_tokens, tonumber(ARGV[12]), "USER_TPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[11], 1,          tonumber(ARGV[13]), "USER_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[13], 1,          tonumber(ARGV[16]), "ORG_RPM_EXCEEDED");          if err then return err end
err = check_quota(KEYS[14], est_tokens, tonumber(ARGV[17]), "ORG_TPM_EXCEEDED");          if err then return err end
err = check_quota(KEYS[15], 1,          tonumber(ARGV[18]), "ORG_CONCURRENCY_EXCEEDED");  if err then return err end

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

if tonumber(ARGV[6]) > 0 then incr_ttl(KEYS[5], 1, window_ttl) end
if tonumber(ARGV[7]) > 0 then incr_ttl(KEYS[6], est_tokens, window_ttl) end
if tonumber(ARGV[8]) > 0 then incr_conc_ttl(KEYS[7], 1, conc_ttl) end
if tonumber(ARGV[11]) > 0 then incr_ttl(KEYS[9], 1, window_ttl) end
if tonumber(ARGV[12]) > 0 then incr_ttl(KEYS[10], est_tokens, window_ttl) end
if tonumber(ARGV[13]) > 0 then incr_conc_ttl(KEYS[11], 1, conc_ttl) end
if tonumber(ARGV[16]) > 0 then incr_ttl(KEYS[13], 1, window_ttl) end
if tonumber(ARGV[17]) > 0 then incr_ttl(KEYS[14], est_tokens, window_ttl) end
if tonumber(ARGV[18]) > 0 then incr_conc_ttl(KEYS[15], 1, conc_ttl) end

if reserve > 0 and request_id ~= "" then
    local expires = now + reservation_ttl
    local scopes = {
        {tonumber(ARGV[4]),  KEYS[17], KEYS[18], KEYS[19]},
        {tonumber(ARGV[9]),  KEYS[20], KEYS[21], KEYS[22]},
        {tonumber(ARGV[14]), KEYS[23], KEYS[24], KEYS[25]},
        {tonumber(ARGV[19]), KEYS[26], KEYS[27], KEYS[28]},
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
