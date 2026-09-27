-- Release an acquired deployment concurrency lease.
-- KEYS[1]: gw:router:dep_slots:<depID>
-- ARGV[1]: unique slot lease ID
local zkey = KEYS[1]
local slot_id = ARGV[1] or ""

if slot_id == "" then
    return 0
end

return redis.call("ZREM", zkey, slot_id)
