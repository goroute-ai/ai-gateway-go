-- Post-Request Token Reconciliation & Concurrency Release
-- KEYS[1]: key_conc, KEYS[2]: key_tpm, KEYS[3]: team_tpm, KEYS[4]: org_tpm
-- ARGV[1]: token_delta, ARGV[2]: window_ttl_sec
-- KEYS[5..7]: key/team/org budget reservations, KEYS[8..10]: key/team/org spend
-- ARGV[3]: request_id, ARGV[4]: actual cost micros (-1 releases without charge), ARGV[5]: reserved amount

local delta = tonumber(ARGV[1])
local ttl   = tonumber(ARGV[2])
local request_id = ARGV[3] or ""
local actual_cost = tonumber(ARGV[4]) or -1
local reserved_cost = tonumber(ARGV[5]) or 0

local conc = tonumber(redis.call("GET", KEYS[1]) or "0")
if conc > 0 then
    redis.call("DECR", KEYS[1])
end

if delta ~= 0 then
    for i = 2, 4 do
        if KEYS[i] ~= "" then
            local v = redis.call("INCRBY", KEYS[i], delta)
            if v < 0 then
                redis.call("SET", KEYS[i], 0, "EX", ttl)
            end
        end
    end
end

if request_id ~= "" and actual_cost ~= -2 then
    local member = request_id .. "|" .. tostring(reserved_cost)
    local reservations = {KEYS[5], KEYS[6], KEYS[7]}
    local spends = {KEYS[8], KEYS[9], KEYS[10]}
    for i = 1, 3 do
        local removed = redis.call("ZREM", reservations[i], member)
        if removed > 0 and actual_cost >= 0 and spends[i] ~= "" then
            redis.call("INCRBY", spends[i], actual_cost)
        end
    end
end

return 1
