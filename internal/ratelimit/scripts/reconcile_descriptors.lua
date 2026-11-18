-- Atomic Post-Request Descriptor Token Reconciliation, Concurrency Release, & Budget Settlement
-- Every key in KEYS MUST carry the same {org:<orgID>} Redis Cluster hash tag.
--
-- Per-descriptor KEYS (10 keys per descriptor idx = 0..count-1, kbase = idx * 10):
--   KEYS[kbase + 1]: tpm_key
--   KEYS[kbase + 2]: itpm_key
--   KEYS[kbase + 3]: otpm_key
--   KEYS[kbase + 4]: tpd_key
--   KEYS[kbase + 5]: conc_key
--   KEYS[kbase + 6]: spend_key
--   KEYS[kbase + 7]: res_zset_key
--   KEYS[kbase + 8]: res_sum_key
--   KEYS[kbase + 9]: res_amounts_key
--   KEYS[kbase + 10]: r24h_zset_key
--
-- Fixed header ARGV[1..9]:
--   ARGV[1]: count (number of descriptors)
--   ARGV[2]: input_delta (actualInput - estInput)
--   ARGV[3]: output_delta (actualOutput - estOutput)
--   ARGV[4]: total_delta ((actualInput + actualOutput) - (estInput + estOutput))
--   ARGV[5]: window_ttl_sec (TTL for 60s minute buckets)
--   ARGV[6]: tpd_ttl_sec (TTL for 86,400s UTC day bucket)
--   ARGV[7]: request_id
--   ARGV[8]: actual_cost_micros (>= 0 settles reservation & charges spend, -1 refunds without charge, -2 leaves reservation for outbox)
--   ARGV[9]: rolling_now_ms (optional unix millisecond timestamp for trailing 24h windows)
--
-- Per-descriptor flags ARGV (7 args per descriptor idx = 0..count-1, abase = 9 + idx * 7):
--   ARGV[abase + 1]: has_tpm (1 or 0)
--   ARGV[abase + 2]: has_itpm (1 or 0)
--   ARGV[abase + 3]: has_otpm (1 or 0)
--   ARGV[abase + 4]: has_tpd (1 or 0)
--   ARGV[abase + 5]: has_conc (1 or 0)
--   ARGV[abase + 6]: has_budget (1 or 0)
--   ARGV[abase + 7]: is_rolling_24h (1 or 0)

local count = tonumber(ARGV[1]) or 0
if count <= 0 then
    return 1
end

local input_delta = tonumber(ARGV[2]) or 0
local output_delta = tonumber(ARGV[3]) or 0
local total_delta = tonumber(ARGV[4]) or 0
local window_ttl = tonumber(ARGV[5]) or 120
local tpd_ttl = tonumber(ARGV[6]) or 172800
local request_id = ARGV[7] or ""
local actual_cost = tonumber(ARGV[8])
if actual_cost == nil then
    actual_cost = -1
end
local rolling_now_ms = tonumber(ARGV[9]) or 0
if rolling_now_ms <= 0 then
    local time_parts = redis.call("TIME")
    rolling_now_ms = tonumber(time_parts[1]) * 1000 + math.floor((tonumber(time_parts[2]) or 0) / 1000)
end

local function adjust_counter(key, delta, ttl)
    if delta == 0 then
        return
    end
    local v = redis.call("INCRBY", key, delta)
    if v < 0 then
        redis.call("SET", key, 0, "EX", ttl)
    elseif redis.call("TTL", key) == -1 then
        redis.call("EXPIRE", key, ttl)
    end
end

for idx = 0, count - 1 do
    local kbase = idx * 10
    local abase = 9 + idx * 7

    local tpm_key = KEYS[kbase + 1]
    local itpm_key = KEYS[kbase + 2]
    local otpm_key = KEYS[kbase + 3]
    local tpd_key = KEYS[kbase + 4]
    local conc_key = KEYS[kbase + 5]
    local spend_key = KEYS[kbase + 6]
    local res_zset = KEYS[kbase + 7]
    local res_sum = KEYS[kbase + 8]
    local res_amounts = KEYS[kbase + 9]
    local r24h_zset = KEYS[kbase + 10]

    local has_tpm = tonumber(ARGV[abase + 1]) or 0
    local has_itpm = tonumber(ARGV[abase + 2]) or 0
    local has_otpm = tonumber(ARGV[abase + 3]) or 0
    local has_tpd = tonumber(ARGV[abase + 4]) or 0
    local has_conc = tonumber(ARGV[abase + 5]) or 0
    local has_budget = tonumber(ARGV[abase + 6]) or 0
    local is_rolling = tonumber(ARGV[abase + 7]) or 0

    if has_conc == 1 then
        local c = tonumber(redis.call("GET", conc_key) or "0")
        if c > 0 then
            redis.call("DECR", conc_key)
        end
    end

    if has_tpm == 1 and total_delta ~= 0 then
        adjust_counter(tpm_key, total_delta, window_ttl)
    end
    if has_itpm == 1 and input_delta ~= 0 then
        adjust_counter(itpm_key, input_delta, window_ttl)
    end
    if has_otpm == 1 and output_delta ~= 0 then
        adjust_counter(otpm_key, output_delta, window_ttl)
    end
    if has_tpd == 1 and total_delta ~= 0 then
        adjust_counter(tpd_key, total_delta, tpd_ttl)
    end

    if has_budget == 1 and request_id ~= "" and actual_cost ~= -2 then
        local amt = tonumber(redis.call("HGET", res_amounts, request_id) or "0")
        local removed = redis.call("HDEL", res_amounts, request_id)
        redis.call("ZREM", res_zset, request_id)
        if removed > 0 and amt > 0 then
            local new_sum = redis.call("DECRBY", res_sum, amt)
            if new_sum < 0 then
                redis.call("SET", res_sum, 0)
            end
        end
        if removed > 0 and actual_cost >= 0 then
            if is_rolling == 1 then
                if actual_cost > 0 then
                    redis.call("ZADD", r24h_zset, rolling_now_ms, "s:" .. request_id .. ":" .. actual_cost)
                    redis.call("EXPIRE", r24h_zset, 90000)
                end
                redis.call("SET", spend_key, "1", "EX", 90000)
            elseif actual_cost > 0 then
                redis.call("INCRBY", spend_key, actual_cost)
            end
        end
    end
end

return 1
