redis.call('SET', KEYS[1], 'open')
redis.call('SET', KEYS[2], 'open', 'PX', ARGV[1])
redis.call('DEL', KEYS[3])
return 1
