-- Renew budget reservation lease for long-running requests.
-- KEYS[1..3]: key/team/org reservation sorted sets.
-- ARGV[1]: request_id; ARGV[2]: ttl_sec.
local request_id = ARGV[1] or ""
local ttl_sec = tonumber(ARGV[2]) or 3600
if request_id == "" or ttl_sec <= 0 then
    return 0
end

local now = tonumber(redis.call("TIME")[1])
local expires = now + ttl_sec
local prefix = request_id .. "|"
local renewed = 0

for i = 1, 3 do
    local reservation_key = KEYS[i]
    if reservation_key and reservation_key ~= "" and
       reservation_key ~= "gw:budget:reservations:key:" and
       reservation_key ~= "gw:budget:reservations:team:" and
       reservation_key ~= "gw:budget:reservations:org:" then
        local members = redis.call("ZRANGE", reservation_key, 0, -1)
        for _, member in ipairs(members) do
            if string.sub(member, 1, string.len(prefix)) == prefix then
                redis.call("ZADD", reservation_key, expires, member)
                redis.call("EXPIRE", reservation_key, ttl_sec + 60)
                renewed = renewed + 1
            end
        end
    end
end

return renewed
