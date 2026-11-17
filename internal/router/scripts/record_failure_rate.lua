local window_ms = tonumber(ARGV[2]) or 60000
if window_ms <= 0 then
    window_ms = 60000
end

local reqs = redis.call('INCR', KEYS[1])
if reqs == 1 or redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], window_ms)
    if reqs == 1 then
        redis.call('DEL', KEYS[2])
    end
end

local fails = 0
local is_fail = tonumber(ARGV[1])
if is_fail and is_fail > 0 then
    fails = redis.call('INCR', KEYS[2])
    local req_ttl = redis.call('PTTL', KEYS[1])
    if req_ttl <= 0 then
        req_ttl = window_ms
    end
    if fails == 1 or redis.call('PTTL', KEYS[2]) < 0 then
        redis.call('PEXPIRE', KEYS[2], req_ttl)
    end
else
    fails = tonumber(redis.call('GET', KEYS[2]) or '0') or 0
end

return {reqs, fails}
