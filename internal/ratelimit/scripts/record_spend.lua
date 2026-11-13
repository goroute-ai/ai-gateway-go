-- Atomic spend accounting and reservation settlement.
-- KEYS[1..3]: key/team/org spend counters; KEYS[4..6]: reservation sorted sets;
-- KEYS[7] (optional): idempotency key in the same organization hash slot.
-- ARGV[1]: request id; ARGV[2]: actual cost in integer micro-dollars; ARGV[3]: event id (falls back to request_id).
local request_id = ARGV[1] or ""
local actual_cost = tonumber(ARGV[2]) or 0
local event_id = ARGV[3] or ""
if event_id == "" then
    event_id = request_id
end

local apply_spend = true
if event_id ~= "" and KEYS[7] and KEYS[7] ~= "" then
    local set_res = redis.call("SET", KEYS[7], "1", "NX", "EX", 86400)
    if not set_res then
        apply_spend = false
    end
end

for i = 1, 3 do
    local spend_key = KEYS[i]
    if apply_spend and string.sub(spend_key, -5) ~= ":key:" and string.sub(spend_key, -6) ~= ":team:" and string.sub(spend_key, -5) ~= ":org:" then
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
if not apply_spend then
    return 0
end
return 1
