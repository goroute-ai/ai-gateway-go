-- Atomic Single-Roundtrip Multi-Scope Rate Limiter & Budget Guard
-- KEYS[1]:  key_rpm,  KEYS[2]:  key_tpm,  KEYS[3]:  key_zconc,  KEYS[4]:  key_spend
-- KEYS[5]:  team_rpm, KEYS[6]:  team_tpm, KEYS[7]:  team_zconc, KEYS[8]:  team_spend
-- KEYS[9]:  user_rpm, KEYS[10]: user_tpm, KEYS[11]: user_zconc, KEYS[12]: user_spend
-- KEYS[13]: org_rpm,  KEYS[14]: org_tpm,  KEYS[15]: org_zconc,  KEYS[16]: org_spend
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
local retry_min = 60 - (now % 60)
if retry_min <= 0 then retry_min = 60 end

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
            return {0, "BUDGET_ESTIMATE_REQUIRED", cur, max_b, 5}
        end
        cleanup_expired(res_zset, res_sum, res_amounts)
        if redis.call("HEXISTS", res_amounts, request_id) == 1 then
            return {0, "BUDGET_RESERVATION_CONFLICT", cur, max_b, 5}
        end
        local reserved = tonumber(redis.call("GET", res_sum) or "0")
        if cur + reserved + reserve > max_b then
            return {0, code, cur + reserved, max_b, 60}
        end
    end
    return nil
end

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
err = check_budget(KEYS[4],  KEYS[17], KEYS[18], KEYS[19], tonumber(ARGV[4]) or 0,  tonumber(ARGV[5]) or 0,  "KEY_BUDGET_EXCEEDED");  if err then return err end
err = check_budget(KEYS[8],  KEYS[20], KEYS[21], KEYS[22], tonumber(ARGV[9]) or 0,  tonumber(ARGV[10]) or 0, "TEAM_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[12], KEYS[23], KEYS[24], KEYS[25], tonumber(ARGV[14]) or 0, tonumber(ARGV[15]) or 0, "USER_BUDGET_EXCEEDED"); if err then return err end
err = check_budget(KEYS[16], KEYS[26], KEYS[27], KEYS[28], tonumber(ARGV[19]) or 0, tonumber(ARGV[20]) or 0, "ORG_BUDGET_EXCEEDED");  if err then return err end

err = check_quota(KEYS[1],  1,          tonumber(ARGV[1])  or 0, "KEY_RPM_EXCEEDED");          if err then return err end
err = check_quota(KEYS[2],  est_tokens, tonumber(ARGV[2])  or 0, "KEY_TPM_EXCEEDED");          if err then return err end
err = check_conc (KEYS[3],              tonumber(ARGV[3])  or 0, "KEY_CONCURRENCY_EXCEEDED");  if err then return err end
err = check_quota(KEYS[5],  1,          tonumber(ARGV[6])  or 0, "TEAM_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[6],  est_tokens, tonumber(ARGV[7])  or 0, "TEAM_TPM_EXCEEDED");         if err then return err end
err = check_conc (KEYS[7],              tonumber(ARGV[8])  or 0, "TEAM_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[9],  1,          tonumber(ARGV[11]) or 0, "USER_RPM_EXCEEDED");         if err then return err end
err = check_quota(KEYS[10], est_tokens, tonumber(ARGV[12]) or 0, "USER_TPM_EXCEEDED");         if err then return err end
err = check_conc (KEYS[11],             tonumber(ARGV[13]) or 0, "USER_CONCURRENCY_EXCEEDED"); if err then return err end
err = check_quota(KEYS[13], 1,          tonumber(ARGV[16]) or 0, "ORG_RPM_EXCEEDED");          if err then return err end
err = check_quota(KEYS[14], est_tokens, tonumber(ARGV[17]) or 0, "ORG_TPM_EXCEEDED");          if err then return err end
err = check_conc (KEYS[15],             tonumber(ARGV[18]) or 0, "ORG_CONCURRENCY_EXCEEDED");  if err then return err end

local function incr_ttl(key, delta, ttl)
    local v = redis.call("INCRBY", key, delta)
    if v == delta then
        redis.call("EXPIRE", key, ttl)
    end
    return v
end

local function acquire_conc_slot(zkey, ttl)
    if request_id == "" then
        return
    end
    redis.call("ZADD", zkey, now + ttl, request_id)
    redis.call("EXPIRE", zkey, ttl + 60)
end

local tight_lim_req, tight_rem_req = 0, 0
local tight_lim_tok, tight_rem_tok = 0, 0
local function track_req(limit, val)
    if limit > 0 then
        local rem = limit - val
        if rem < 0 then rem = 0 end
        if tight_lim_req == 0 or rem < tight_rem_req then
            tight_lim_req = limit
            tight_rem_req = rem
        end
    end
end
local function track_tok(limit, val)
    if limit > 0 then
        local rem = limit - val
        if rem < 0 then rem = 0 end
        if tight_lim_tok == 0 or rem < tight_rem_tok then
            tight_lim_tok = limit
            tight_rem_tok = rem
        end
    end
end

local lim_k_rpm, lim_k_tpm, lim_k_conc = tonumber(ARGV[1]) or 0, tonumber(ARGV[2]) or 0, tonumber(ARGV[3]) or 0
local new_rpm = incr_ttl(KEYS[1], 1, window_ttl)
local new_tpm = incr_ttl(KEYS[2], est_tokens, window_ttl)
track_req(lim_k_rpm, new_rpm)
track_tok(lim_k_tpm, new_tpm)
if lim_k_conc > 0 then acquire_conc_slot(KEYS[3], conc_ttl) end

local lim_t_rpm, lim_t_tpm, lim_t_conc = tonumber(ARGV[6]) or 0, tonumber(ARGV[7]) or 0, tonumber(ARGV[8]) or 0
if lim_t_rpm > 0 then track_req(lim_t_rpm, incr_ttl(KEYS[5], 1, window_ttl)) end
if lim_t_tpm > 0 then track_tok(lim_t_tpm, incr_ttl(KEYS[6], est_tokens, window_ttl)) end
if lim_t_conc > 0 then acquire_conc_slot(KEYS[7], conc_ttl) end

local lim_u_rpm, lim_u_tpm, lim_u_conc = tonumber(ARGV[11]) or 0, tonumber(ARGV[12]) or 0, tonumber(ARGV[13]) or 0
if lim_u_rpm > 0 then track_req(lim_u_rpm, incr_ttl(KEYS[9], 1, window_ttl)) end
if lim_u_tpm > 0 then track_tok(lim_u_tpm, incr_ttl(KEYS[10], est_tokens, window_ttl)) end
if lim_u_conc > 0 then acquire_conc_slot(KEYS[11], conc_ttl) end

local lim_o_rpm, lim_o_tpm, lim_o_conc = tonumber(ARGV[16]) or 0, tonumber(ARGV[17]) or 0, tonumber(ARGV[18]) or 0
if lim_o_rpm > 0 then track_req(lim_o_rpm, incr_ttl(KEYS[13], 1, window_ttl)) end
if lim_o_tpm > 0 then track_tok(lim_o_tpm, incr_ttl(KEYS[14], est_tokens, window_ttl)) end
if lim_o_conc > 0 then acquire_conc_slot(KEYS[15], conc_ttl) end

if reserve > 0 and request_id ~= "" then
    local expires = now + reservation_ttl
    local scopes = {
        {tonumber(ARGV[4])  or 0, KEYS[17], KEYS[18], KEYS[19]},
        {tonumber(ARGV[9])  or 0, KEYS[20], KEYS[21], KEYS[22]},
        {tonumber(ARGV[14]) or 0, KEYS[23], KEYS[24], KEYS[25]},
        {tonumber(ARGV[19]) or 0, KEYS[26], KEYS[27], KEYS[28]},
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

return {1, "OK", tight_lim_req, tight_rem_req, retry_min, tight_lim_tok, tight_rem_tok, retry_min}
