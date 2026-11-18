-- Renew descriptor budget reservation leases in O(1) per descriptor.
-- Every key in KEYS MUST carry the same {org:<orgID>} Redis Cluster hash tag.
-- KEYS[idx*3 + 1..3]: res_zset, res_sum, res_amounts
-- ARGV[1]: count
-- ARGV[2]: request_id
-- ARGV[3]: ttl_sec

local count = tonumber(ARGV[1]) or 0
local request_id = ARGV[2] or ""
local ttl_sec = tonumber(ARGV[3]) or 3600
if count <= 0 or request_id == "" or ttl_sec <= 0 then
    return 0
end

local now = tonumber(redis.call("TIME")[1])
local expires = now + ttl_sec
local renewed = 0

for idx = 0, count - 1 do
    local kbase = idx * 3
    local res_zset = KEYS[kbase + 1]
    local res_sum = KEYS[kbase + 2]
    local res_amounts = KEYS[kbase + 3]
    if res_zset ~= "" and redis.call("ZSCORE", res_zset, request_id) then
        redis.call("ZADD", res_zset, expires, request_id)
        redis.call("EXPIRE", res_zset, ttl_sec + 60)
        redis.call("EXPIRE", res_sum, ttl_sec + 60)
        redis.call("EXPIRE", res_amounts, ttl_sec + 60)
        renewed = renewed + 1
    end
end

return renewed
