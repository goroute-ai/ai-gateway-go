-- Post-Request Token Reconciliation & Concurrency Release
-- KEYS[1]: key_conc, KEYS[2]: user_conc
-- KEYS[3]: key_tpm,  KEYS[4]: team_tpm, KEYS[5]: user_tpm, KEYS[6]: org_tpm
-- KEYS[7..9]:   key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[10..12]: team_res_zset, team_res_sum, team_res_amounts
-- KEYS[13..15]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[16..18]: org_res_zset,  org_res_sum,  org_res_amounts
-- KEYS[19..22]: key_spend, team_spend, user_spend, org_spend
-- ARGV[1]: token_delta, ARGV[2]: window_ttl_sec
-- ARGV[3]: request_id, ARGV[4]: actual cost micros (-1 releases without charge, -2 leaves for outbox), ARGV[5]: reserved amount

local delta = tonumber(ARGV[1])
local ttl   = tonumber(ARGV[2])
local request_id = ARGV[3] or ""
local actual_cost = tonumber(ARGV[4]) or -1

local function decr_conc(key)
    if key ~= "" then
        local conc = tonumber(redis.call("GET", key) or "0")
        if conc > 0 then
            redis.call("DECR", key)
        end
    end
end

decr_conc(KEYS[1])
decr_conc(KEYS[2])

if delta ~= 0 then
    for i = 3, 6 do
        if KEYS[i] ~= "" then
            local v = redis.call("INCRBY", KEYS[i], delta)
            if v < 0 then
                redis.call("SET", KEYS[i], 0, "EX", ttl)
            elseif redis.call("TTL", KEYS[i]) == -1 then
                redis.call("EXPIRE", KEYS[i], ttl)
            end
        end
    end
end

if request_id ~= "" and actual_cost ~= -2 then
    local scopes = {
        {KEYS[7],  KEYS[8],  KEYS[9],  KEYS[19]},
        {KEYS[10], KEYS[11], KEYS[12], KEYS[20]},
        {KEYS[13], KEYS[14], KEYS[15], KEYS[21]},
        {KEYS[16], KEYS[17], KEYS[18], KEYS[22]},
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
            if removed > 0 and actual_cost >= 0 and spend_key ~= "" then
                local v = redis.call("INCRBY", spend_key, actual_cost)
                if v < 0 then
                    redis.call("SET", spend_key, 0)
                end
            end
        end
    end
end

return 1
