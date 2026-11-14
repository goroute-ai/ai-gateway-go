-- Renew budget reservation lease for long-running requests in O(1).
-- KEYS[1..3]:   key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[4..6]:   team_res_zset, team_res_sum, team_res_amounts
-- KEYS[7..9]:   user_res_zset, user_res_sum, user_res_amounts
-- KEYS[10..12]: org_res_zset,  org_res_sum,  org_res_amounts
-- ARGV[1]: request_id; ARGV[2]: ttl_sec.
local request_id = ARGV[1] or ""
local ttl_sec = tonumber(ARGV[2]) or 3600
if request_id == "" or ttl_sec <= 0 then
    return 0
end

local now = tonumber(redis.call("TIME")[1])
local expires = now + ttl_sec
local renewed = 0

local function has_entity_id(key)
    return key and key ~= "" and
        string.sub(key, -5) ~= ":key:" and
        string.sub(key, -6) ~= ":team:" and
        string.sub(key, -6) ~= ":user:" and
        string.sub(key, -5) ~= ":org:"
end

for i = 0, 3 do
    local base = i * 3
    local res_zset, res_sum, res_amounts = KEYS[base + 1], KEYS[base + 2], KEYS[base + 3]
    if has_entity_id(res_zset) then
        if redis.call("ZSCORE", res_zset, request_id) then
            redis.call("ZADD", res_zset, expires, request_id)
            redis.call("EXPIRE", res_zset, ttl_sec + 60)
            redis.call("EXPIRE", res_sum, ttl_sec + 60)
            redis.call("EXPIRE", res_amounts, ttl_sec + 60)
            renewed = renewed + 1
        end
    end
end

return renewed
