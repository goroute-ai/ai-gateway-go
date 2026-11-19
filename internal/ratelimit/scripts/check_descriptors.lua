-- Atomic 2-Phase All-or-Nothing Multi-Descriptor Rate Limiter & Budget Guard
-- Every key in KEYS MUST carry the same {org:<orgID>} Redis Cluster hash tag.
--
-- Per-descriptor KEYS (12 keys per descriptor idx = 0..count-1, kbase = idx * 12):
--   KEYS[kbase + 1]:  rpm_key         (60s minute bucket)
--   KEYS[kbase + 2]:  tpm_key         (60s minute bucket)
--   KEYS[kbase + 3]:  itpm_key        (60s minute bucket)
--   KEYS[kbase + 4]:  otpm_key        (60s minute bucket)
--   KEYS[kbase + 5]:  tpd_key         (86,400s UTC day bucket)
--   KEYS[kbase + 6]:  zconc_key       (self-healing ZSET concurrency slots)
--   KEYS[kbase + 7]:  iter_key        (session TTL-guarded iteration counter)
--   KEYS[kbase + 8]:  spend_key       (accumulated spend in micro-dollars)
--   KEYS[kbase + 9]:  res_zset_key    (reservation expiration sorted set)
--   KEYS[kbase + 10]: res_sum_key     (O(1) active reserved micro-dollars sum)
--   KEYS[kbase + 11]: res_amounts_key (request_id -> reserved micro-dollars hash)
--   KEYS[kbase + 12]: r24h_zset_key   (trailing 24h timestamped spend sorted set)
--
-- KEYS[count * 12 + 1]: unique admission receipt for Redis command retries.
--
-- Fixed header ARGV[1..10]:
--   ARGV[1]: count (number of descriptors)
--   ARGV[2]: est_input (estimated input tokens, >= 0)
--   ARGV[3]: est_output (estimated output tokens, >= 0)
--   ARGV[4]: reserve_micros (conservative upper-bound cost in micro-dollars, >= 0)
--   ARGV[5]: request_id
--   ARGV[6]: window_ttl_sec (TTL for 60s minute buckets)
--   ARGV[7]: tpd_ttl_sec (TTL for 86,400s UTC day bucket)
--   ARGV[8]: conc_ttl_sec (TTL for concurrency counter)
--   ARGV[9]: reservation_ttl_sec (TTL for budget reservation lease)
--   ARGV[10]: rolling_now_ms (optional unix millisecond timestamp for trailing 24h windows)
--
-- Per-descriptor ARGV (13 args per descriptor idx = 0..count-1, abase = 10 + idx * 13):
--   ARGV[abase + 1]:  scope_upper (e.g. "KEY", "TEAM", "AGENT_SESSION", "MODEL_PER_KEY")
--   ARGV[abase + 2]:  rpm_limit
--   ARGV[abase + 3]:  tpm_limit
--   ARGV[abase + 4]:  itpm_limit
--   ARGV[abase + 5]:  otpm_limit
--   ARGV[abase + 6]:  tpd_limit
--   ARGV[abase + 7]:  max_concurrent
--   ARGV[abase + 8]:  max_iterations
--   ARGV[abase + 9]:  iter_ttl_sec
--   ARGV[abase + 10]: max_budget_micros
--   ARGV[abase + 11]: spent_floor_micros
--   ARGV[abase + 12]: is_rolling_24h (1 or 0)
--   ARGV[abase + 13]: has_rolling_init (1 or 0)
--
-- Trailing cold-init payload after fixed table (starting at 10 + count * 13 + 1):
--   For each descriptor in order with has_rolling_init == 1:
--     entry_count, followed by entry_count triples of (entry_id, ts_ms, amount_micros)

local count = tonumber(ARGV[1]) or 0
if count <= 0 then
    return {1, "OK", 0, 0, 0, 0, 0, 0}
end

local receipt_key = KEYS[count * 12 + 1]
if receipt_key and receipt_key ~= "" and redis.call("EXISTS", receipt_key) == 1 then
    return {1, "OK"}
end

local est_input = tonumber(ARGV[2]) or 0
local est_output = tonumber(ARGV[3]) or 0
if est_input < 0 then est_input = 0 end
if est_output < 0 then est_output = 0 end
local est_total = est_input + est_output

local reserve = tonumber(ARGV[4]) or 0
local request_id = ARGV[5] or ""
local window_ttl = tonumber(ARGV[6]) or 120
local tpd_ttl = tonumber(ARGV[7]) or 172800
local conc_ttl = tonumber(ARGV[8]) or 300
local reservation_ttl = tonumber(ARGV[9]) or 3600

local time_parts = redis.call("TIME")
local now = tonumber(time_parts[1])
local rolling_now_ms = tonumber(ARGV[10]) or 0
if rolling_now_ms <= 0 then
    rolling_now_ms = now * 1000 + math.floor((tonumber(time_parts[2]) or 0) / 1000)
end
local cutoff_ms = rolling_now_ms - 86400000
local retry_min = 60 - (now % 60)
if retry_min <= 0 then retry_min = 60 end
local retry_day = 86400 - (now % 86400)
if retry_day <= 0 then retry_day = 86400 end

local function cleanup_expired(res_zset, res_sum, res_amounts)
    local expired = redis.call("ZRANGEBYSCORE", res_zset, "-inf", now)
    if #expired > 0 then
        local total_expired = 0
        for _, req_id in ipairs(expired) do
            local amt = tonumber(redis.call("HGET", res_amounts, req_id) or "0")
            if amt > 0 then
                total_expired = total_expired + amt
            end
            redis.call("HDEL", res_amounts, req_id)
        end
        redis.call("ZREMRANGEBYSCORE", res_zset, "-inf", now)
        if total_expired > 0 then
            local rem = redis.call("DECRBY", res_sum, total_expired)
            if rem < 0 then
                redis.call("SET", res_sum, 0)
            end
        end
    end
end

local function incr_ttl(key, delta, ttl)
    if delta == 0 then
        return tonumber(redis.call("GET", key) or "0")
    end
    local v = redis.call("INCRBY", key, delta)
    if v == delta or redis.call("TTL", key) == -1 then
        redis.call("EXPIRE", key, ttl)
    end
    return v
end

-- Phase 1: Pure read-only admission checks (cleaning expired ZSET slots/reservations).
local pending_add = {}
local pending_res = {}
local rolling_init_entries = {}
local init_ptr = 10 + count * 13 + 1

for idx = 0, count - 1 do
    local kbase = idx * 12
    local abase = 10 + idx * 13

    local rpm_key = KEYS[kbase + 1]
    local tpm_key = KEYS[kbase + 2]
    local itpm_key = KEYS[kbase + 3]
    local otpm_key = KEYS[kbase + 4]
    local tpd_key = KEYS[kbase + 5]
    local zconc_key = KEYS[kbase + 6]
    local iter_key = KEYS[kbase + 7]
    local spend_key = KEYS[kbase + 8]
    local res_zset = KEYS[kbase + 9]
    local res_sum = KEYS[kbase + 10]
    local res_amounts = KEYS[kbase + 11]
    local r24h_zset = KEYS[kbase + 12]

    local scope = ARGV[abase + 1] or "DESCRIPTOR"
    local rpm_limit = tonumber(ARGV[abase + 2]) or 0
    local tpm_limit = tonumber(ARGV[abase + 3]) or 0
    local itpm_limit = tonumber(ARGV[abase + 4]) or 0
    local otpm_limit = tonumber(ARGV[abase + 5]) or 0
    local tpd_limit = tonumber(ARGV[abase + 6]) or 0
    local max_conc = tonumber(ARGV[abase + 7]) or 0
    local max_iter = tonumber(ARGV[abase + 8]) or 0
    local iter_ttl = tonumber(ARGV[abase + 9]) or 3600
    local max_budget = tonumber(ARGV[abase + 10]) or 0
    local spent_floor = tonumber(ARGV[abase + 11]) or 0
    local is_rolling = tonumber(ARGV[abase + 12]) or 0
    local has_rolling_init = tonumber(ARGV[abase + 13]) or 0

    if has_rolling_init == 1 then
        local n = tonumber(ARGV[init_ptr]) or 0
        init_ptr = init_ptr + 1
        local entries = {}
        for j = 1, n do
            local eid = ARGV[init_ptr] or ""
            local ets = tonumber(ARGV[init_ptr + 1]) or 0
            local eamt = tonumber(ARGV[init_ptr + 2]) or 0
            init_ptr = init_ptr + 3
            if eid ~= "" and eamt > 0 and ets > cutoff_ms then
                local member = eid .. ":" .. eamt
                entries[member] = { ts_ms = ets, amt = eamt }
            end
        end
        rolling_init_entries[idx] = entries
    end

    if rpm_limit > 0 then
        local cur = tonumber(redis.call("GET", rpm_key) or "0") + (pending_add[rpm_key] or 0)
        if (cur + 1) > rpm_limit then
            return {0, scope .. "_RPM_EXCEEDED", cur, rpm_limit, retry_min}
        end
        pending_add[rpm_key] = (pending_add[rpm_key] or 0) + 1
    end

    if tpm_limit > 0 then
        local cur = tonumber(redis.call("GET", tpm_key) or "0") + (pending_add[tpm_key] or 0)
        if (cur + est_total) > tpm_limit or (est_total == 0 and cur >= tpm_limit) then
            return {0, scope .. "_TPM_EXCEEDED", cur, tpm_limit, retry_min}
        end
        pending_add[tpm_key] = (pending_add[tpm_key] or 0) + est_total
    end

    if itpm_limit > 0 then
        local cur = tonumber(redis.call("GET", itpm_key) or "0") + (pending_add[itpm_key] or 0)
        if (cur + est_input) > itpm_limit or (est_input == 0 and cur >= itpm_limit) then
            return {0, scope .. "_ITPM_EXCEEDED", cur, itpm_limit, retry_min}
        end
        pending_add[itpm_key] = (pending_add[itpm_key] or 0) + est_input
    end

    if otpm_limit > 0 then
        local cur = tonumber(redis.call("GET", otpm_key) or "0") + (pending_add[otpm_key] or 0)
        if (cur + est_output) > otpm_limit or (est_output == 0 and cur >= otpm_limit) then
            return {0, scope .. "_OTPM_EXCEEDED", cur, otpm_limit, retry_min}
        end
        pending_add[otpm_key] = (pending_add[otpm_key] or 0) + est_output
    end

    if tpd_limit > 0 then
        local cur = tonumber(redis.call("GET", tpd_key) or "0") + (pending_add[tpd_key] or 0)
        if (cur + est_total) > tpd_limit or (est_total == 0 and cur >= tpd_limit) then
            return {0, scope .. "_TPD_EXCEEDED", cur, tpd_limit, retry_day}
        end
        pending_add[tpd_key] = (pending_add[tpd_key] or 0) + est_total
    end

    if max_conc > 0 then
        redis.call("ZREMRANGEBYSCORE", zconc_key, "-inf", now)
        local cur = tonumber(redis.call("ZCARD", zconc_key) or "0") + (pending_add[zconc_key] or 0)
        if (cur + 1) > max_conc then
            return {0, scope .. "_CONCURRENCY_EXCEEDED", cur, max_conc, 5}
        end
        pending_add[zconc_key] = (pending_add[zconc_key] or 0) + 1
    end

    if max_iter > 0 then
        local cur = tonumber(redis.call("GET", iter_key) or "0") + (pending_add[iter_key] or 0)
        if (cur + 1) > max_iter then
            local r = tonumber(redis.call("TTL", iter_key) or "-1")
            if r <= 0 then
                r = iter_ttl
            end
            return {0, scope .. "_ITERATIONS_EXCEEDED", cur, max_iter, r}
        end
        pending_add[iter_key] = (pending_add[iter_key] or 0) + 1
    end

    if max_budget > 0 then
        local cur_spent = 0
        if is_rolling == 1 then
            local init_score = redis.call("ZSCORE", r24h_zset, "__init__:0")
            local rolling_initialized = (init_score ~= false and init_score ~= nil)
            if rolling_initialized then
                local active_roll = redis.call("ZRANGEBYSCORE", r24h_zset, "(" .. cutoff_ms, "9007199254740990")
                for _, m in ipairs(active_roll) do
                    if m ~= "__init__:0" then
                        local a = tonumber(string.match(m, ":(%d+)$") or "0")
                        if a > 0 then
                            cur_spent = cur_spent + a
                        end
                    end
                end
            else
                if has_rolling_init == 0 then
                    return {0, "ROLLING_WINDOW_COLD", idx, max_budget, 5}
                end
                local init_list = rolling_init_entries[idx] or {}
                for _, entry in pairs(init_list) do
                    cur_spent = cur_spent + entry.amt
                end
                local unsettled_roll = redis.call("ZRANGEBYSCORE", r24h_zset, "(" .. cutoff_ms, "9007199254740990")
                for _, m in ipairs(unsettled_roll) do
                    if not init_list[m] then
                        local a = tonumber(string.match(m, ":(%d+)$") or "0")
                        if a > 0 then
                            cur_spent = cur_spent + a
                        end
                    end
                end
            end
        else
            local redis_spent = tonumber(redis.call("GET", spend_key) or "0")
            cur_spent = math.max(redis_spent, spent_floor)
        end
        if reserve <= 0 or request_id == "" then
            return {0, "BUDGET_ESTIMATE_REQUIRED", cur_spent, max_budget, 5}
        end
        if pending_res[res_zset] then
            return {0, "BUDGET_RESERVATION_CONFLICT", cur_spent, max_budget, 5}
        end

        local expired = redis.call("ZRANGEBYSCORE", res_zset, "-inf", now)
        local expired_sum = 0
        local req_is_expired = false
        for _, eid in ipairs(expired) do
            if eid == request_id then
                req_is_expired = true
            end
            local eamt = tonumber(redis.call("HGET", res_amounts, eid) or "0")
            if eamt > 0 then
                expired_sum = expired_sum + eamt
            end
        end

        if (not req_is_expired) and redis.call("HEXISTS", res_amounts, request_id) == 1 then
            return {0, "BUDGET_RESERVATION_CONFLICT", cur_spent, max_budget, 5}
        end

        local raw_reserved = tonumber(redis.call("GET", res_sum) or "0")
        local active_reserved = raw_reserved - expired_sum
        if active_reserved < 0 then
            active_reserved = 0
        end

        if (cur_spent + active_reserved + reserve) > max_budget then
            return {0, scope .. "_BUDGET_EXCEEDED", cur_spent + active_reserved, max_budget, 60}
        end
        pending_res[res_zset] = true
    end
end

-- Phase 2: All descriptors admitted; atomically apply all counter mutations, ZSET slots, and reservations.
local tight_lim_req, tight_rem_req = 0, 0
local tight_lim_tok, tight_rem_tok = 0, 0
local function track_req(limit, val)
    if limit > 0 then
        local rem = limit - val
        if rem < 0 then rem = 0 end
        if tight_lim_req == 0 or rem < tight_rem_req then
            tight_lim_req = limit
            tight_rem_req = rem
        end
    end
end
local function track_tok(limit, val)
    if limit > 0 then
        local rem = limit - val
        if rem < 0 then rem = 0 end
        if tight_lim_tok == 0 or rem < tight_rem_tok then
            tight_lim_tok = limit
            tight_rem_tok = rem
        end
    end
end

for idx = 0, count - 1 do
    local kbase = idx * 12
    local abase = 10 + idx * 13

    local rpm_key = KEYS[kbase + 1]
    local tpm_key = KEYS[kbase + 2]
    local itpm_key = KEYS[kbase + 3]
    local otpm_key = KEYS[kbase + 4]
    local tpd_key = KEYS[kbase + 5]
    local zconc_key = KEYS[kbase + 6]
    local iter_key = KEYS[kbase + 7]
    local spend_key = KEYS[kbase + 8]
    local res_zset = KEYS[kbase + 9]
    local res_sum = KEYS[kbase + 10]
    local res_amounts = KEYS[kbase + 11]
    local r24h_zset = KEYS[kbase + 12]

    local scope = ARGV[abase + 1]
    local rpm_limit = tonumber(ARGV[abase + 2]) or 0
    local tpm_limit = tonumber(ARGV[abase + 3]) or 0
    local itpm_limit = tonumber(ARGV[abase + 4]) or 0
    local otpm_limit = tonumber(ARGV[abase + 5]) or 0
    local tpd_limit = tonumber(ARGV[abase + 6]) or 0
    local max_conc = tonumber(ARGV[abase + 7]) or 0
    local max_iter = tonumber(ARGV[abase + 8]) or 0
    local iter_ttl = tonumber(ARGV[abase + 9]) or 3600
    local max_budget = tonumber(ARGV[abase + 10]) or 0
    local spent_floor = tonumber(ARGV[abase + 11]) or 0
    local is_rolling = tonumber(ARGV[abase + 12]) or 0
    local res_zset = KEYS[kbase + 9]
    local res_sum = KEYS[kbase + 10]
    local res_amounts = KEYS[kbase + 11]
    local r24h_zset = KEYS[kbase + 12]

    if rpm_limit > 0 then
        track_req(rpm_limit, incr_ttl(rpm_key, 1, window_ttl))
    end
    if tpm_limit > 0 then
        track_tok(tpm_limit, incr_ttl(tpm_key, est_total, window_ttl))
    end
    if itpm_limit > 0 and est_input > 0 then
        incr_ttl(itpm_key, est_input, window_ttl)
    end
    if otpm_limit > 0 and est_output > 0 then
        incr_ttl(otpm_key, est_output, window_ttl)
    end
    if tpd_limit > 0 and est_total > 0 then
        incr_ttl(tpd_key, est_total, tpd_ttl)
    end
    if max_conc > 0 and request_id ~= "" then
        redis.call("ZADD", zconc_key, now + conc_ttl, request_id)
        redis.call("EXPIRE", zconc_key, conc_ttl + 60)
    end
    if max_iter > 0 then
        incr_ttl(iter_key, 1, iter_ttl)
    end
    if max_budget > 0 then
        if is_rolling == 1 then
            redis.call("ZREMRANGEBYSCORE", r24h_zset, "-inf", cutoff_ms)
            local init_score = redis.call("ZSCORE", r24h_zset, "__init__:0")
            if init_score == false or init_score == nil then
                redis.call("ZADD", r24h_zset, 9007199254740991, "__init__:0")
                local init_list = rolling_init_entries[idx] or {}
                for member, entry in pairs(init_list) do
                    redis.call("ZADD", r24h_zset, entry.ts_ms, member)
                end
            end
            redis.call("EXPIRE", r24h_zset, 90000)
        else
            local redis_spent = tonumber(redis.call("GET", spend_key) or "0")
            if spent_floor > redis_spent then
                redis.call("SET", spend_key, spent_floor)
            end
        end
        cleanup_expired(res_zset, res_sum, res_amounts)
        if reserve > 0 and request_id ~= "" then
            local expires = now + reservation_ttl
            redis.call("ZADD", res_zset, expires, request_id)
            redis.call("INCRBY", res_sum, reserve)
            redis.call("HSET", res_amounts, request_id, reserve)
            redis.call("EXPIRE", res_zset, reservation_ttl + 60)
            redis.call("EXPIRE", res_sum, reservation_ttl + 60)
            redis.call("EXPIRE", res_amounts, reservation_ttl + 60)
        end
    end
end

-- Cover Redis client's retry window without extending any quota leases.
if receipt_key and receipt_key ~= "" then
    redis.call("SET", receipt_key, "1", "EX", 5)
end
return {1, "OK", tight_lim_req, tight_rem_req, retry_min, tight_lim_tok, tight_rem_tok, retry_min}
