local state = redis.call('GET', KEYS[1])
if state ~= 'open' then
    return 1
end

if redis.call('EXISTS', KEYS[2]) == 1 then
    return 0
end

local acquired = redis.call('SET', KEYS[3], ARGV[1], 'NX', 'PX', ARGV[2])
if acquired then
    return 2
end
return 0
