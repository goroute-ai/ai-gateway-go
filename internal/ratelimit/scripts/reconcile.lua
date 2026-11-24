-- Post-Request Token Reconciliation & Self-Healing ZSET Concurrency Release
-- KEYS[1]: key_zconc, KEYS[2]: team_zconc, KEYS[3]: user_zconc, KEYS[4]: org_zconc
-- KEYS[5]: key_tpm,   KEYS[6]: team_tpm,   KEYS[7]: user_tpm,   KEYS[8]: org_tpm
-- KEYS[9..11]:  key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[12..14]: team_res_zset, team_res_sum, team_res_amounts
-- KEYS[15..17]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[18..20]: org_res_zset,  org_res_sum,  org_res_amounts
-- KEYS[21..24]: key_spend, team_spend, user_spend, org_spend
-- KEYS[25] (optional): idempotency key shared with record_spend.lua (gw:spend:applied:{org:<orgID>}:<event_id>)
-- ARGV[1]: token_delta, ARGV[2]: window_ttl_sec
-- ARGV[3]: request_id, ARGV[4]: actual cost micros (-1 releases without charge, -2 leaves for outbox), ARGV[5]: reserved amount

local delta = tonumber(ARGV[1])
local ttl   = tonumber(ARGV[2])
local request_id = ARGV[3] or ""
local actual_cost = tonumber(ARGV[4]) or -1

local function release_conc(key)
    if key ~= "" and request_id ~= "" then
        redis.call("ZREM", key, request_id)
    end
end

release_conc(KEYS[1])
release_conc(KEYS[2])
release_conc(KEYS[3])
release_conc(KEYS[4])

if delta ~= 0 then
    for i = 5, 8 do
        if KEYS[i] ~= "" then
            if not (delta < 0 and redis.call("EXISTS", KEYS[i]) == 0) then
                local v = redis.call("INCRBY", KEYS[i], delta)
                if v < 0 then
                    redis.call("SET", KEYS[i], 0, "EX", ttl)
                elseif redis.call("TTL", KEYS[i]) == -1 then
                    redis.call("EXPIRE", KEYS[i], ttl)
                end
            end
        end
    end
end

if request_id ~= "" and actual_cost ~= -2 then
    local apply_spend = (actual_cost >= 0)
    local idemp_key = KEYS[25]
    if apply_spend and idemp_key and idemp_key ~= "" then
        local set_res = redis.call("SET", idemp_key, "1", "NX", "EX", 86400)
        if not set_res then
            apply_spend = false
        end
    end
    local scopes = {
        {KEYS[9],  KEYS[10], KEYS[11], KEYS[21]},
        {KEYS[12], KEYS[13], KEYS[14], KEYS[22]},
        {KEYS[15], KEYS[16], KEYS[17], KEYS[23]},
        {KEYS[18], KEYS[19], KEYS[20], KEYS[24]},
    }
    for _, sc in ipairs(scopes) do
        local res_zset, res_sum, res_amounts, spend_key = sc[1], sc[2], sc[3], sc[4]
        if res_amounts ~= "" then
            local amt = tonumber(redis.call("HGET", res_amounts, request_id) or "0")
            local removed = redis.call("HDEL", res_amounts, request_id)
            redis.call("ZREM", res_zset, request_id)
            if removed > 0 and amt > 0 then
                local new_sum = redis.call("DECRBY", res_sum, amt)
                if new_sum < 0 then
                    redis.call("SET", res_sum, 0)
                end
            end
            if removed > 0 and apply_spend and actual_cost > 0 and spend_key ~= "" then
                local v = redis.call("INCRBY", spend_key, actual_cost)
                if v < 0 then
                    redis.call("SET", spend_key, 0)
                end
            end
        end
    end
end

return 1
