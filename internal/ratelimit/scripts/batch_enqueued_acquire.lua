-- Atomic Batch Enqueued Token Hold Acquisition (Key, Team, User, Org)
-- KEYS[1..3]:   key_zset,  key_sum,  key_amounts
-- KEYS[4..6]:   team_zset, team_sum, team_amounts
-- KEYS[7..9]:   user_zset, user_sum, user_amounts
-- KEYS[10..12]: org_zset,  org_sum,  org_amounts
-- KEYS[13]:     meta_key
-- ARGV[1]: limit_key, ARGV[2]: limit_team, ARGV[3]: limit_user, ARGV[4]: limit_org
-- ARGV[5]: estimated_tokens, ARGV[6]: batch_id, ARGV[7]: hold_ttl_sec, ARGV[8]: meta_value

local est_tokens = tonumber(ARGV[5]) or 0
local batch_id = ARGV[6] or ""
local hold_ttl = tonumber(ARGV[7]) or 90000
local meta_value = ARGV[8] or ""
local now = tonumber(redis.call("TIME")[1])

local function cleanup_expired(zset_key, sum_key, amounts_key)
    local expired = redis.call("ZRANGEBYSCORE", zset_key, "-inf", now)
    if #expired > 0 then
        local total_expired = 0
        for _, bid in ipairs(expired) do
            local amt = tonumber(redis.call("HGET", amounts_key, bid) or "0")
            if amt > 0 then
                total_expired = total_expired + amt
            end
            redis.call("HDEL", amounts_key, bid)
        end
        redis.call("ZREMRANGEBYSCORE", zset_key, "-inf", now)
        if total_expired > 0 then
            local rem = redis.call("DECRBY", sum_key, total_expired)
            if rem < 0 then
                redis.call("SET", sum_key, 0)
            end
        end
    end
end

local scopes = {
    {tonumber(ARGV[1]) or 0, KEYS[1],  KEYS[2],  KEYS[3],  "KEY_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
    {tonumber(ARGV[2]) or 0, KEYS[4],  KEYS[5],  KEYS[6],  "TEAM_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
    {tonumber(ARGV[3]) or 0, KEYS[7],  KEYS[8],  KEYS[9],  "USER_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
    {tonumber(ARGV[4]) or 0, KEYS[10], KEYS[11], KEYS[12], "ORG_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
}

for _, sc in ipairs(scopes) do
    local limit, zset_key, sum_key, amounts_key, err_code = sc[1], sc[2], sc[3], sc[4], sc[5]
    if limit > 0 and zset_key ~= "" then
        cleanup_expired(zset_key, sum_key, amounts_key)
        if redis.call("HEXISTS", amounts_key, batch_id) == 1 then
            return {0, "BATCH_ENQUEUED_CONFLICT", 0, limit}
        end
        local cur = tonumber(redis.call("GET", sum_key) or "0")
        if cur + est_tokens > limit then
            return {0, err_code, cur, limit}
        end
    end
end

local expires = now + hold_ttl
for _, sc in ipairs(scopes) do
    local limit, zset_key, sum_key, amounts_key = sc[1], sc[2], sc[3], sc[4]
    if limit > 0 and zset_key ~= "" then
        redis.call("ZADD", zset_key, expires, batch_id)
        redis.call("INCRBY", sum_key, est_tokens)
        redis.call("HSET", amounts_key, batch_id, est_tokens)
        redis.call("EXPIRE", zset_key, hold_ttl + 60)
        redis.call("EXPIRE", sum_key, hold_ttl + 60)
        redis.call("EXPIRE", amounts_key, hold_ttl + 60)
    end
end

if KEYS[13] ~= "" and meta_value ~= "" then
    redis.call("SET", KEYS[13], meta_value, "EX", hold_ttl + 60)
end

return {1, "OK"}
