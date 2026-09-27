if redis.call('GET', KEYS[1]) ~= 'open' or redis.call('GET', KEYS[3]) ~= ARGV[1] then
    return 0
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
if KEYS[4] then
    redis.call('DEL', KEYS[4])
end
return 1
