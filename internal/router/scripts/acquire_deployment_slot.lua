-- Atomic self-healing ZSET concurrency lease acquisition per physical deployment.
-- KEYS[1]: gw:router:dep_slots:<depID>
-- ARGV[1]: now unix seconds
-- ARGV[2]: lease TTL seconds
-- ARGV[3]: max_parallel (> 0)
-- ARGV[4]: unique slot lease ID
local zkey = KEYS[1]
local now = tonumber(ARGV[1]) or 0
local ttl = tonumber(ARGV[2]) or 300
local max_parallel = tonumber(ARGV[3]) or 0
local slot_id = ARGV[4] or ""

if max_parallel <= 0 or slot_id == "" then
    return {1, 0}
end

redis.call("ZREMRANGEBYSCORE", zkey, "-inf", now)
local cur = tonumber(redis.call("ZCARD", zkey) or "0")
if cur >= max_parallel then
    return {0, cur}
end

redis.call("ZADD", zkey, now + ttl, slot_id)
redis.call("EXPIRE", zkey, ttl + 60)
return {1, cur + 1}
