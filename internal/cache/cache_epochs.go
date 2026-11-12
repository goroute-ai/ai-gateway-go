package cache

import (
	"github.com/redis/go-redis/v9"
)

var invalidateCacheEpochsScript = redis.NewScript(`
for i = 2, #KEYS do
    redis.call('INCR', KEYS[i])
end
return redis.call('INCR', KEYS[1])
`)
