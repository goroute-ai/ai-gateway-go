-- Atomic Batch Enqueued Token Hold Release (Key, Team, User, Org)
-- KEYS[1..3]:   key_zset,  key_sum,  key_amounts
-- KEYS[4..6]:   team_zset, team_sum, team_amounts
-- KEYS[7..9]:   user_zset, user_sum, user_amounts
-- KEYS[10..12]: org_zset,  org_sum,  org_amounts
-- KEYS[13]:     meta_key
-- ARGV[1]: batch_id

local batch_id = ARGV[1] or ""
if batch_id == "" then
    return 0
end

local scopes = {
    {KEYS[1],  KEYS[2],  KEYS[3]},
    {KEYS[4],  KEYS[5],  KEYS[6]},
    {KEYS[7],  KEYS[8],  KEYS[9]},
    {KEYS[10], KEYS[11], KEYS[12]},
}

for _, sc in ipairs(scopes) do
    local zset_key, sum_key, amounts_key = sc[1], sc[2], sc[3]
    if zset_key ~= "" and sum_key ~= "" and amounts_key ~= "" then
        local amt = tonumber(redis.call("HGET", amounts_key, batch_id) or "0")
        local removed = redis.call("HDEL", amounts_key, batch_id)
        redis.call("ZREM", zset_key, batch_id)
        if removed > 0 and amt > 0 then
            local rem = redis.call("DECRBY", sum_key, amt)
            if rem < 0 then
                redis.call("SET", sum_key, 0)
            end
        end
    end
end

if KEYS[13] ~= "" then
    redis.call("DEL", KEYS[13])
end

return 1
