if redis.call('GET', KEYS[1]) ~= 'open' or redis.call('GET', KEYS[3]) ~= ARGV[2] then
    return 0
end
redis.call('SET', KEYS[2], 'open', 'PX', ARGV[1])
redis.call('DEL', KEYS[3])
return 1
