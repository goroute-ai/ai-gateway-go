-- Atomic Rollback of Org-Scoped Acquisition (used when Global Limits fail after Org Acquisition)
-- KEYS[1]: key_rpm, KEYS[2]: key_tpm, KEYS[3]: key_conc
-- KEYS[4]: team_rpm, KEYS[5]: team_tpm
-- KEYS[6]: user_rpm, KEYS[7]: user_tpm, KEYS[8]: user_conc
-- KEYS[9]: org_rpm, KEYS[10]: org_tpm
-- KEYS[11..13]: key_res_zset,  key_res_sum,  key_res_amounts
-- KEYS[14..16]: team_res_zset, team_res_sum, team_res_amounts
-- KEYS[17..19]: user_res_zset, user_res_sum, user_res_amounts
-- KEYS[20..22]: org_res_zset,  org_res_sum,  org_res_amounts
-- ARGV[1]: estimated_tokens, ARGV[2]: request_id
-- ARGV[3]: limit_team_rpm, ARGV[4]: limit_team_tpm
-- ARGV[5]: limit_user_rpm, ARGV[6]: limit_user_tpm, ARGV[7]: limit_user_conc
-- ARGV[8]: limit_org_rpm,  ARGV[9]: limit_org_tpm

local est_tokens = tonumber(ARGV[1]) or 1
local request_id = ARGV[2] or ""

local function decr_floor(key, delta)
    if key ~= "" and delta > 0 then
        local cur = tonumber(redis.call("GET", key) or "0")
        if cur > 0 then
            local v = redis.call("DECRBY", key, delta)
            if v < 0 then
                redis.call("SET", key, 0, "KEEPTTL")
            end
        end
    end
end

decr_floor(KEYS[1], 1)
decr_floor(KEYS[2], est_tokens)
decr_floor(KEYS[3], 1)

if tonumber(ARGV[3]) > 0 then decr_floor(KEYS[4], 1) end
if tonumber(ARGV[4]) > 0 then decr_floor(KEYS[5], est_tokens) end
if tonumber(ARGV[5]) > 0 then decr_floor(KEYS[6], 1) end
if tonumber(ARGV[6]) > 0 then decr_floor(KEYS[7], est_tokens) end
if tonumber(ARGV[7]) > 0 then decr_floor(KEYS[8], 1) end
if tonumber(ARGV[8]) > 0 then decr_floor(KEYS[9], 1) end
if tonumber(ARGV[9]) > 0 then decr_floor(KEYS[10], est_tokens) end

if request_id ~= "" then
    local scopes = {
        {KEYS[11], KEYS[12], KEYS[13]},
        {KEYS[14], KEYS[15], KEYS[16]},
        {KEYS[17], KEYS[18], KEYS[19]},
        {KEYS[20], KEYS[21], KEYS[22]},
    }
    for _, sc in ipairs(scopes) do
        local amt = tonumber(redis.call("HGET", sc[3], request_id) or "0")
        local removed = redis.call("HDEL", sc[3], request_id)
        redis.call("ZREM", sc[1], request_id)
        if removed > 0 and amt > 0 then
            local rem = redis.call("DECRBY", sc[2], amt)
            if rem < 0 then
                redis.call("SET", sc[2], 0)
            end
        end
    end
end

return 1
