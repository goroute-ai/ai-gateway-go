-- Atomic spend accounting and O(1) reservation settlement.
-- KEYS[1..4]: key/team/user/org spend counters;
-- KEYS[5..7]:   key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[8..10]:  team_res_zset, team_res_sum, team_res_amounts
-- KEYS[11..13]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[14..16]: org_res_zset,  org_res_sum,  org_res_amounts
-- KEYS[17] (optional): idempotency key in the same organization hash slot.
-- ARGV[1]: request id; ARGV[2]: actual cost in integer micro-dollars; ARGV[3]: event id (falls back to request_id).
local request_id = ARGV[1] or ""
local actual_cost = tonumber(ARGV[2]) or 0
local event_id = ARGV[3] or ""
if event_id == "" then
    event_id = request_id
end

local apply_spend = true
if event_id ~= "" and KEYS[17] and KEYS[17] ~= "" then
    local set_res = redis.call("SET", KEYS[17], "1", "NX", "EX", 86400)
    if not set_res then
        apply_spend = false
    end
end

local function has_entity_id(key)
    return key ~= "" and
        string.sub(key, -5) ~= ":key:" and
        string.sub(key, -6) ~= ":team:" and
        string.sub(key, -6) ~= ":user:" and
        string.sub(key, -5) ~= ":org:"
end

for i = 1, 4 do
    local spend_key = KEYS[i]
    if apply_spend and has_entity_id(spend_key) then
        if actual_cost > 0 then redis.call("INCRBY", spend_key, actual_cost) end
    end
    if request_id ~= "" then
        local base = 4 + (i - 1) * 3
        local res_zset, res_sum, res_amounts = KEYS[base + 1], KEYS[base + 2], KEYS[base + 3]
        if has_entity_id(res_zset) then
            local amt = tonumber(redis.call("HGET", res_amounts, request_id) or "0")
            local removed = redis.call("HDEL", res_amounts, request_id)
            redis.call("ZREM", res_zset, request_id)
            if removed > 0 and amt > 0 then
                local rem = redis.call("DECRBY", res_sum, amt)
                if rem < 0 then
                    redis.call("SET", res_sum, 0)
                end
            end
        end
    end
end
if not apply_spend then
    return 0
end
return 1
