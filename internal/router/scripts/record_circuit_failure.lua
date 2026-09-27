local state = redis.call('GET', KEYS[1])
if state == 'open' then
    if ARGV[4] ~= '' and redis.call('GET', KEYS[3]) == ARGV[4] then
        redis.call('SET', KEYS[2], 'open', 'PX', ARGV[3])
        redis.call('DEL', KEYS[3])
        if KEYS[4] then
            redis.call('DEL', KEYS[4])
        end
        return 2
    end
    return 0
end

local failures = redis.call('INCR', KEYS[4])
if failures == 1 or redis.call('PTTL', KEYS[4]) < 0 then
    redis.call('PEXPIRE', KEYS[4], ARGV[2])
end
if failures >= tonumber(ARGV[1]) then
    redis.call('SET', KEYS[1], 'open')
    redis.call('SET', KEYS[2], 'open', 'PX', ARGV[3])
    redis.call('DEL', KEYS[3], KEYS[4])
    return 1
end
return 0
