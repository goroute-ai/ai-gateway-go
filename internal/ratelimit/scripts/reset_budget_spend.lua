-- Reset one spend counter exactly once for a durable budget-reset event.
-- KEYS[1]: organization-tagged spend counter; KEYS[2]: same-slot reset marker.
-- ARGV[1]: stable budget reset event ID; ARGV[2]: marker TTL in seconds.
local event_id = ARGV[1] or ""
local ttl = tonumber(ARGV[2]) or 7776000
if event_id == "" then
    return redis.error_reply("missing budget reset event ID")
end
local applied = redis.call("SET", KEYS[2], event_id, "NX", "EX", ttl)
if not applied then
    return 0
end
redis.call("DEL", KEYS[1])
return 1
