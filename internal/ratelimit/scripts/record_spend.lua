-- Atomic spend accounting and reservation settlement.
-- KEYS[1..3]: key/team/org spend counters; KEYS[4..6]: reservation sorted sets.
-- ARGV[1]: request id; ARGV[2]: actual cost in integer micro-dollars.
local request_id = ARGV[1] or ""
local actual_cost = tonumber(ARGV[2]) or 0
for i = 1, 3 do
    local spend_key = KEYS[i]
    if spend_key ~= "gw:spend:key:" and spend_key ~= "gw:spend:team:" and spend_key ~= "gw:spend:org:" then
        if actual_cost > 0 then redis.call("INCRBY", spend_key, actual_cost) end
    end
    if request_id ~= "" then
        local reservation_key = KEYS[i + 3]
        local members = redis.call("ZRANGE", reservation_key, 0, -1)
        local prefix = request_id .. "|"
        for _, member in ipairs(members) do
            if string.sub(member, 1, string.len(prefix)) == prefix then
                redis.call("ZREM", reservation_key, member)
            end
        end
    end
end
return 1
