-- Check remaining budget availability without creating a reservation.
-- KEYS[1]:  key_spend,  KEYS[2..4]:   key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[5]:  team_spend, KEYS[6..8]:   team_res_zset, team_res_sum, team_res_amounts
-- KEYS[9]:  user_spend, KEYS[10..12]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[13]: org_spend,  KEYS[14..16]: org_res_zset,  org_res_sum,  org_res_amounts
-- ARGV[1..2]: max_key_budget,  key_spent_floor
-- ARGV[3..4]: max_team_budget, team_spent_floor
-- ARGV[5..6]: max_user_budget, user_spent_floor
-- ARGV[7..8]: max_org_budget,  org_spent_floor

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

local scopes = {
    {KEYS[1],  KEYS[2],  KEYS[3],  KEYS[4],  tonumber(ARGV[1]) or 0, tonumber(ARGV[2]) or 0, "KEY_BUDGET_EXCEEDED"},
    {KEYS[5],  KEYS[6],  KEYS[7],  KEYS[8],  tonumber(ARGV[3]) or 0, tonumber(ARGV[4]) or 0, "TEAM_BUDGET_EXCEEDED"},
    {KEYS[9],  KEYS[10], KEYS[11], KEYS[12], tonumber(ARGV[5]) or 0, tonumber(ARGV[6]) or 0, "USER_BUDGET_EXCEEDED"},
    {KEYS[13], KEYS[14], KEYS[15], KEYS[16], tonumber(ARGV[7]) or 0, tonumber(ARGV[8]) or 0, "ORG_BUDGET_EXCEEDED"},
}

for _, sc in ipairs(scopes) do
    local spend_key, res_zset, res_sum, res_amounts, max_b, db_floor, code = sc[1], sc[2], sc[3], sc[4], sc[5], sc[6], sc[7]
    if max_b > 0 then
        local redis_spent = tonumber(redis.call("GET", spend_key) or "0")
        local cur = math.max(redis_spent, db_floor)
        if cur > redis_spent then
            redis.call("SET", spend_key, cur)
        end
        cleanup_expired(res_zset, res_sum, res_amounts)
        local reserved = tonumber(redis.call("GET", res_sum) or "0")
        if cur + reserved >= max_b then
            return {0, code, cur, max_b}
        end
    end
end

return {1, "OK"}
