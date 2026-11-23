package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

func (p *PostgresRepository) EnqueueSpendEvent(ctx context.Context, ev domain.SpendEvent) error {
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.PricingStatus == "" {
		ev.PricingStatus = domain.PricingStatusUnrecorded
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal spend event: %w", err)
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO spend_event_outbox (id, payload_json) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, ev.ID, payload)
	if err != nil {
		return fmt.Errorf("persist spend event outbox: %w", err)
	}
	return nil
}

func (p *PostgresRepository) ClaimSpendEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.SpendEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if lease <= 0 {
		lease = time.Minute
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM spend_event_outbox
			WHERE (status = 'pending' AND next_attempt_at <= NOW())
			   OR (status = 'processing' AND locked_at < NOW() - ($2 * INTERVAL '1 second'))
			ORDER BY created_at
			LIMIT $1 FOR UPDATE SKIP LOCKED
		)
		UPDATE spend_event_outbox o SET status='processing', locked_at=NOW(), attempt_count=o.attempt_count+1, updated_at=NOW()
		FROM candidates c WHERE o.id=c.id RETURNING o.payload_json, o.attempt_count`, limit, lease.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []domain.SpendEvent
	for rows.Next() {
		var raw []byte
		var attempt int
		if err := rows.Scan(&raw, &attempt); err != nil {
			return nil, err
		}
		var ev domain.SpendEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("decode spend outbox payload: %w", err)
		}
		ev.OutboxAttempt = attempt
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return events, nil
}

func (p *PostgresRepository) MarkSpendEventDelivered(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE spend_event_outbox SET status='delivered', locked_at=NULL, last_error=NULL, updated_at=NOW() WHERE id=$1`, id)
	return err
}

func (p *PostgresRepository) MarkSpendEventsDelivered(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.pool.Exec(ctx, `UPDATE spend_event_outbox SET status='delivered', locked_at=NULL, last_error=NULL, updated_at=NOW() WHERE id = ANY($1)`, ids)
	return err
}

func (p *PostgresRepository) CountPendingSpendEvents(ctx context.Context) (int64, error) {
	var count int64
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM spend_event_outbox WHERE status IN ('pending', 'processing')`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (p *PostgresRepository) PruneDeliveredSpendEvents(ctx context.Context, olderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 1000
	}
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM spend_event_outbox
		WHERE id IN (
			SELECT id FROM spend_event_outbox
			WHERE status = 'delivered' AND updated_at < $1
			ORDER BY updated_at ASC
			LIMIT $2
		)`, olderThan.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *PostgresRepository) RetrySpendEvent(ctx context.Context, id string, cause error, retryAt time.Time, maxAttempts int) error {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	_, err := p.pool.Exec(ctx, `UPDATE spend_event_outbox SET status=CASE WHEN attempt_count >= $4 THEN 'dead_letter' ELSE 'pending' END, next_attempt_at=$3, locked_at=NULL, last_error=$2, updated_at=NOW() WHERE id=$1`, id, message, retryAt, maxAttempts)
	return err
}

type spendDelta struct {
	id         string
	costMicros int64
}

func sortedSpendDeltas(m map[string]int64) []spendDelta {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if k != "" && v > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]spendDelta, 0, len(keys))
	for _, k := range keys {
		out = append(out, spendDelta{id: k, costMicros: m[k]})
	}
	return out
}

func (p *PostgresRepository) RecordSpendBatch(ctx context.Context, events []domain.SpendEvent) error {
	if len(events) == 0 {
		return nil
	}
	const insertQ = `
		INSERT INTO spend_logs (
			id, request_id, trace_id, org_id, team_id, user_id, virtual_key_id,
			project_id, end_user_id, tags, session_id, model_access_group_ids, matched_quota_policy_ids,
			endpoint, modality, modality_units, requested_model, resolved_model, provider,
			prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
			cost_micros, pricing_version, pricing_status, pricing_provenance_source,
			latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
		) VALUES (
			$1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),
			COALESCE(NULLIF($8,''), (SELECT project_id FROM virtual_keys WHERE id = NULLIF($7,''))),
			NULLIF($9,''),$10,NULLIF($11,''),$12,$13,
			$14,$15,$16,$17,$18,$19,
			$20,$21,$22,$23,$24,
			$25,$26,$27,$28,
			$29,$30,$31,$32,$33,$34,$35,$36
		)
		ON CONFLICT (id) DO NOTHING
		RETURNING org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''),
			COALESCE(project_id, ''), model_access_group_ids, matched_quota_policy_ids, cost_micros`

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin spend batch tx: %w", err)
	}
	defer tx.Rollback(ctx)

	nowFallback := time.Now().UTC()
	batch := &pgx.Batch{}
	for _, ev := range events {
		id := ev.ID
		if id == "" {
			id = uuid.NewString()
		}
		pv := ev.PricingVersion
		if pv <= 0 {
			pv = 1
		}
		pricingStatus := string(ev.PricingStatus)
		if pricingStatus == "" {
			pricingStatus = string(domain.PricingStatusUnrecorded)
		}
		orgID := ev.OrgID
		if orgID == "" {
			orgID = "00000000-0000-0000-0000-000000000000"
		}
		modality := string(ev.Modality)
		if modality == "" {
			modality = string(domain.ModalityChat)
		}
		modUnitsJSON, _ := json.Marshal(ev.ModalityUnits)
		if len(ev.ModalityUnits) == 0 {
			modUnitsJSON = []byte("{}")
		}
		evTags := ev.Tags
		if evTags == nil {
			evTags = []string{}
		}
		evMAGs := ev.ModelAccessGroupIDs
		if evMAGs == nil {
			evMAGs = []string{}
		}
		evPolicyIDs := ev.MatchedQuotaPolicyIDs
		if evPolicyIDs == nil {
			evPolicyIDs = []string{}
		}
		createdAt := ev.CreatedAt.UTC()
		if createdAt.IsZero() {
			createdAt = nowFallback
		}
		batch.Queue(insertQ,
			id, ev.RequestID, ev.TraceID, orgID, ev.TeamID, ev.UserID, ev.VirtualKeyID,
			ev.ProjectID, ev.EndUserID, evTags, ev.SessionID, evMAGs, evPolicyIDs,
			ev.Endpoint, modality, modUnitsJSON, ev.RequestedModel, ev.ResolvedModel, string(ev.Provider),
			ev.Usage.PromptTokens, ev.Usage.CompletionTokens, ev.Usage.CachedPromptTokens, ev.Usage.ReasoningTokens, ev.Usage.TotalTokens,
			ev.CostMicros, pv, pricingStatus, ev.PricingProvenanceSource,
			ev.LatencyMs, ev.TTFTMs, ev.StatusCode, ev.IsStream, ev.CacheHit, ev.FallbackAttempted, ev.RetryCount, createdAt,
		)
	}
	orgTotals := make(map[string]int64)
	teamTotals := make(map[string]int64)
	userTotals := make(map[string]int64)
	keyTotals := make(map[string]int64)
	projectTotals := make(map[string]int64)
	type teamMemberKey struct {
		teamID string
		userID string
	}
	memberTotals := make(map[teamMemberKey]int64)
	type orgTupleKey struct {
		orgID string
		id    string
	}
	endUserTotals := make(map[orgTupleKey]int64)
	tagTotals := make(map[orgTupleKey]int64)
	magTotals := make(map[string]int64)
	policyTotals := make(map[string]int64)
	type bwSpendKey struct {
		orgID     string
		scopeType domain.QuotaScopeType
		scopeID   string
	}
	bwTotals := make(map[bwSpendKey]int64)

	br := tx.SendBatch(ctx, batch)
	for i := range events {
		var orgID, teamID, userID, keyID, projectID string
		var magIDs, policyIDs []string
		var costMicros int64
		err := br.QueryRow().Scan(&orgID, &teamID, &userID, &keyID, &projectID, &magIDs, &policyIDs, &costMicros)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			_ = br.Close()
			return fmt.Errorf("execute spend batch: %w", err)
		}
		if costMicros > 0 {
			ev := events[i]
			if orgID != "" {
				orgTotals[orgID] += costMicros
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeOrg, scopeID: orgID}] += costMicros
			}
			if teamID != "" {
				teamTotals[teamID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeTeam, scopeID: teamID}] += costMicros
				}
			}
			if userID != "" {
				userTotals[userID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeUser, scopeID: userID}] += costMicros
				}
			}
			if keyID != "" {
				keyTotals[keyID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeKey, scopeID: keyID}] += costMicros
				}
			}
			if projectID != "" {
				projectTotals[projectID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeProject, scopeID: projectID}] += costMicros
				}
			}
			if teamID != "" && userID != "" {
				memberTotals[teamMemberKey{teamID: teamID, userID: userID}] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeTeamMember, scopeID: teamID + ":" + userID}] += costMicros
				}
			}
			if orgID != "" && ev.EndUserID != "" {
				endUserTotals[orgTupleKey{orgID: orgID, id: ev.EndUserID}] += costMicros
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeEndUser, scopeID: ev.EndUserID}] += costMicros
			}
			for _, tagName := range ev.Tags {
				tagName = strings.TrimSpace(tagName)
				if tagName == "" || orgID == "" {
					continue
				}
				tagTotals[orgTupleKey{orgID: orgID, id: tagName}] += costMicros
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeTag, scopeID: tagName}] += costMicros
			}
			seenMAGs := make(map[string]struct{}, len(magIDs))
			for _, magID := range magIDs {
				magID = strings.TrimSpace(magID)
				if magID == "" {
					continue
				}
				if _, dup := seenMAGs[magID]; dup {
					continue
				}
				seenMAGs[magID] = struct{}{}
				magTotals[magID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeModelAccessGroup, scopeID: magID}] += costMicros
				}
			}
			seenPolicies := make(map[string]struct{}, len(policyIDs))
			for _, qpID := range policyIDs {
				qpID = strings.TrimSpace(qpID)
				if qpID == "" {
					continue
				}
				if _, dup := seenPolicies[qpID]; dup {
					continue
				}
				seenPolicies[qpID] = struct{}{}
				policyTotals[qpID] += costMicros
			}
		}
	}
	if err := br.Close(); err != nil {
		return fmt.Errorf("close spend batch: %w", err)
	}

	// Pre-aggregated updates in deterministic ID order prevent row-lock contention and deadlocks.
	updateBatch := &pgx.Batch{}
	updateCount := 0
	for _, d := range sortedSpendDeltas(orgTotals) {
		updateBatch.Queue(`UPDATE organizations SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(teamTotals) {
		updateBatch.Queue(`UPDATE teams SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(userTotals) {
		updateBatch.Queue(`UPDATE users SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(keyTotals) {
		updateBatch.Queue(`UPDATE virtual_keys SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(projectTotals) {
		updateBatch.Queue(`UPDATE projects SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	if len(memberTotals) > 0 {
		mKeys := make([]teamMemberKey, 0, len(memberTotals))
		for k := range memberTotals {
			mKeys = append(mKeys, k)
		}
		sort.Slice(mKeys, func(i, j int) bool {
			if mKeys[i].teamID != mKeys[j].teamID {
				return mKeys[i].teamID < mKeys[j].teamID
			}
			return mKeys[i].userID < mKeys[j].userID
		})
		for _, k := range mKeys {
			updateBatch.Queue(
				`UPDATE team_memberships SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE team_id = $1 AND user_id = $2`,
				k.teamID, k.userID, memberTotals[k],
			)
			updateCount++
		}
	}
	if len(endUserTotals) > 0 {
		euKeys := make([]orgTupleKey, 0, len(endUserTotals))
		for k := range endUserTotals {
			euKeys = append(euKeys, k)
		}
		sort.Slice(euKeys, func(i, j int) bool {
			if euKeys[i].orgID != euKeys[j].orgID {
				return euKeys[i].orgID < euKeys[j].orgID
			}
			return euKeys[i].id < euKeys[j].id
		})
		for _, k := range euKeys {
			updateBatch.Queue(
				`UPDATE end_users SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE org_id = $1 AND end_user_id = $2`,
				k.orgID, k.id, endUserTotals[k],
			)
			updateCount++
		}
	}
	if len(tagTotals) > 0 {
		tKeys := make([]orgTupleKey, 0, len(tagTotals))
		for k := range tagTotals {
			tKeys = append(tKeys, k)
		}
		sort.Slice(tKeys, func(i, j int) bool {
			if tKeys[i].orgID != tKeys[j].orgID {
				return tKeys[i].orgID < tKeys[j].orgID
			}
			return tKeys[i].id < tKeys[j].id
		})
		for _, k := range tKeys {
			updateBatch.Queue(
				`UPDATE tags SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE org_id = $1 AND tag = $2`,
				k.orgID, k.id, tagTotals[k],
			)
			updateCount++
		}
	}
	for _, d := range sortedSpendDeltas(magTotals) {
		updateBatch.Queue(`UPDATE model_access_groups SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(policyTotals) {
		updateBatch.Queue(`UPDATE quota_policies SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	if len(bwTotals) > 0 {
		bwKeys := make([]bwSpendKey, 0, len(bwTotals))
		for k := range bwTotals {
			bwKeys = append(bwKeys, k)
		}
		sort.Slice(bwKeys, func(i, j int) bool {
			if bwKeys[i].orgID != bwKeys[j].orgID {
				return bwKeys[i].orgID < bwKeys[j].orgID
			}
			if bwKeys[i].scopeType != bwKeys[j].scopeType {
				return bwKeys[i].scopeType < bwKeys[j].scopeType
			}
			return bwKeys[i].scopeID < bwKeys[j].scopeID
		})
		for _, k := range bwKeys {
			updateBatch.Queue(
				`UPDATE budget_window_limits SET spent_micros = spent_micros + $4, updated_at = NOW() WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3 AND window_type <> 'rolling_24h'`,
				k.orgID, string(k.scopeType), k.scopeID, bwTotals[k],
			)
			updateCount++
		}
	}
	if updateCount > 0 {
		ubr := tx.SendBatch(ctx, updateBatch)
		for i := 0; i < updateCount; i++ {
			if _, err := ubr.Exec(); err != nil {
				_ = ubr.Close()
				return fmt.Errorf("update aggregated spend: %w", err)
			}
		}
		if err := ubr.Close(); err != nil {
			return fmt.Errorf("close aggregated spend batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit spend batch: %w", err)
	}
	if err := p.mem.RecordSpendBatch(ctx, events); err != nil {
		return err
	}
	return nil
}

func (p *PostgresRepository) GetSpendSummary(ctx context.Context, orgID string) (*SpendSummary, error) {
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	var whereClause string
	var args []any
	if orgID != "" {
		whereClause = "WHERE org_id = $1"
		args = append(args, orgID)
	}

	qTotals := `SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost_micros), 0),
		COUNT(*) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')),
		COALESCE(SUM(total_tokens) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')), 0)
		FROM spend_logs ` + whereClause
	if err := p.pool.QueryRow(ctx, qTotals, args...).Scan(&sum.TotalRequests, &sum.TotalTokens, &sum.TotalCostMicros, &sum.UnpricedRequests, &sum.UnpricedTokens); err != nil {
		return p.mem.GetSpendSummary(ctx, orgID)
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0

	qBreakdown := `
		SELECT
			COALESCE(provider, ''),
			COALESCE(resolved_model, ''),
			COALESCE(team_id, ''),
			COALESCE(virtual_key_id, ''),
			COALESCE(user_id, ''),
			GROUPING(provider, resolved_model, team_id, virtual_key_id, user_id),
			COALESCE(SUM(cost_micros), 0)
		FROM spend_logs ` + whereClause + `
		GROUP BY GROUPING SETS (
			(provider),
			(resolved_model),
			(team_id),
			(virtual_key_id),
			(user_id)
		)`
	if rows, err := p.pool.Query(ctx, qBreakdown, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var prov, model, teamID, vkID, userID string
			var grp int
			var cost int64
			if err := rows.Scan(&prov, &model, &teamID, &vkID, &userID, &grp, &cost); err != nil {
				continue
			}
			switch grp {
			case 15: // 0b01111 -> provider
				sum.SpendByProvider[prov] = cost
			case 23: // 0b10111 -> resolved_model
				sum.SpendByModel[model] = cost
			case 27: // 0b11011 -> team_id
				if teamID != "" {
					sum.SpendByTeam[teamID] = cost
				}
			case 29: // 0b11101 -> virtual_key_id
				if vkID != "" {
					sum.SpendByVirtualKey[vkID] = cost
				}
			case 30: // 0b11110 -> user_id
				if userID != "" {
					sum.SpendByUser[userID] = cost
				}
			}
		}
	}

	return sum, nil
}

func (p *PostgresRepository) ListSpendLogs(ctx context.Context, orgID string, limit int) ([]domain.SpendEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `
			SELECT id, request_id, trace_id, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''),
				COALESCE(project_id, ''), COALESCE(end_user_id, ''), tags, COALESCE(session_id, ''),
				model_access_group_ids, matched_quota_policy_ids,
				endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []any{orgID, limit}
	} else {
		q = `
			SELECT id, request_id, trace_id, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''),
				COALESCE(project_id, ''), COALESCE(end_user_id, ''), tags, COALESCE(session_id, ''),
				model_access_group_ids, matched_quota_policy_ids,
				endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs ORDER BY created_at DESC LIMIT $1`
		args = []any{limit}
	}

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListSpendLogs(ctx, orgID, limit)
	}
	defer rows.Close()

	var out []domain.SpendEvent
	for rows.Next() {
		var ev domain.SpendEvent
		var prov string
		if err := rows.Scan(
			&ev.ID, &ev.RequestID, &ev.TraceID, &ev.OrgID, &ev.TeamID, &ev.UserID, &ev.VirtualKeyID,
			&ev.ProjectID, &ev.EndUserID, &ev.Tags, &ev.SessionID,
			&ev.ModelAccessGroupIDs, &ev.MatchedQuotaPolicyIDs,
			&ev.Endpoint, &ev.RequestedModel, &ev.ResolvedModel, &prov,
			&ev.Usage.PromptTokens, &ev.Usage.CompletionTokens, &ev.Usage.CachedPromptTokens, &ev.Usage.ReasoningTokens, &ev.Usage.TotalTokens,
			&ev.CostMicros, &ev.PricingVersion, &ev.LatencyMs, &ev.TTFTMs, &ev.StatusCode, &ev.IsStream, &ev.CacheHit, &ev.FallbackAttempted, &ev.RetryCount, &ev.CreatedAt,
		); err != nil {
			return nil, err
		}
		ev.Provider = domain.ProviderType(prov)
		out = append(out, ev)
	}
	if len(out) == 0 {
		return p.mem.ListSpendLogs(ctx, orgID, limit)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) GetTeamSpendSummary(ctx context.Context, orgID, teamID string) (*SpendSummary, error) {
	if p.pool == nil {
		return p.mem.GetTeamSpendSummary(ctx, orgID, teamID)
	}
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	var whereClause string
	var args []any
	if orgID != "" {
		whereClause = "WHERE org_id = $1 AND team_id = $2"
		args = []any{orgID, teamID}
	} else {
		whereClause = "WHERE team_id = $1"
		args = []any{teamID}
	}

	qTotals := `SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost_micros), 0),
		COUNT(*) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')),
		COALESCE(SUM(total_tokens) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')), 0)
		FROM spend_logs ` + whereClause
	if err := p.pool.QueryRow(ctx, qTotals, args...).Scan(&sum.TotalRequests, &sum.TotalTokens, &sum.TotalCostMicros, &sum.UnpricedRequests, &sum.UnpricedTokens); err != nil {
		return p.mem.GetTeamSpendSummary(ctx, orgID, teamID)
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0

	qBreakdown := `
		SELECT
			COALESCE(provider, ''),
			COALESCE(resolved_model, ''),
			COALESCE(team_id, ''),
			COALESCE(virtual_key_id, ''),
			COALESCE(user_id, ''),
			GROUPING(provider, resolved_model, team_id, virtual_key_id, user_id),
			COALESCE(SUM(cost_micros), 0)
		FROM spend_logs ` + whereClause + `
		GROUP BY GROUPING SETS (
			(provider),
			(resolved_model),
			(team_id),
			(virtual_key_id),
			(user_id)
		)`
	if rows, err := p.pool.Query(ctx, qBreakdown, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var prov, model, tid, vkID, userID string
			var grp int
			var cost int64
			if err := rows.Scan(&prov, &model, &tid, &vkID, &userID, &grp, &cost); err != nil {
				continue
			}
			switch grp {
			case 15:
				sum.SpendByProvider[prov] = cost
			case 23:
				sum.SpendByModel[model] = cost
			case 27:
				if tid != "" {
					sum.SpendByTeam[tid] = cost
				}
			case 29:
				if vkID != "" {
					sum.SpendByVirtualKey[vkID] = cost
				}
			case 30:
				if userID != "" {
					sum.SpendByUser[userID] = cost
				}
			}
		}
	}
	return sum, nil
}

func (p *PostgresRepository) ListTeamSpendLogs(ctx context.Context, orgID, teamID string, limit int) ([]domain.SpendEvent, error) {
	if p.pool == nil {
		return p.mem.ListTeamSpendLogs(ctx, orgID, teamID, limit)
	}
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `
			SELECT id, request_id, trace_id, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''), endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE org_id = $1 AND team_id = $2 ORDER BY created_at DESC LIMIT $3`
		args = []any{orgID, teamID, limit}
	} else {
		q = `
			SELECT id, request_id, trace_id, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''), endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE team_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []any{teamID, limit}
	}

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListTeamSpendLogs(ctx, orgID, teamID, limit)
	}
	defer rows.Close()

	out := make([]domain.SpendEvent, 0)
	for rows.Next() {
		var ev domain.SpendEvent
		var prov string
		if err := rows.Scan(
			&ev.ID, &ev.RequestID, &ev.TraceID, &ev.OrgID, &ev.TeamID, &ev.UserID, &ev.VirtualKeyID, &ev.Endpoint, &ev.RequestedModel, &ev.ResolvedModel, &prov,
			&ev.Usage.PromptTokens, &ev.Usage.CompletionTokens, &ev.Usage.CachedPromptTokens, &ev.Usage.ReasoningTokens, &ev.Usage.TotalTokens,
			&ev.CostMicros, &ev.PricingVersion, &ev.LatencyMs, &ev.TTFTMs, &ev.StatusCode, &ev.IsStream, &ev.CacheHit, &ev.FallbackAttempted, &ev.RetryCount, &ev.CreatedAt,
		); err != nil {
			return nil, err
		}
		ev.Provider = domain.ProviderType(prov)
		out = append(out, ev)
	}
	if len(out) == 0 {
		return p.mem.ListTeamSpendLogs(ctx, orgID, teamID, limit)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error) {
	res, err := p.ResetExpiredBudgetsWithIDs(ctx, now)
	return res.Total(), err
}

func (p *PostgresRepository) ResetExpiredBudgetsWithIDs(ctx context.Context, now time.Time) (BudgetResetResult, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return BudgetResetResult{}, fmt.Errorf("begin reset budgets tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var res BudgetResetResult
	queries := []struct {
		sql   string
		scope string
		dest  *[]string
	}{
		{
			sql: `UPDATE organizations
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, id`,
			scope: "org",
			dest:  &res.OrgIDs,
		},
		{
			sql: `UPDATE teams
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, org_id`,
			scope: "team",
			dest:  &res.TeamIDs,
		},
		{
			sql: `UPDATE users
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, org_id`,
			scope: "user",
			dest:  &res.UserIDs,
		},
		{
			sql: `UPDATE virtual_keys
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, org_id`,
			scope: "key",
			dest:  &res.VirtualKeyIDs,
		},
	}

	outboxBatch := &pgx.Batch{}
	outboxCount := 0
	for _, q := range queries {
		rows, err := tx.Query(ctx, q.sql, now)
		if err != nil {
			return BudgetResetResult{}, fmt.Errorf("reset expired budgets: %w", err)
		}
		for rows.Next() {
			var id, orgID string
			if err := rows.Scan(&id, &orgID); err != nil {
				rows.Close()
				return BudgetResetResult{}, fmt.Errorf("scan reset budget id: %w", err)
			}
			*q.dest = append(*q.dest, id)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: q.scope, EntityID: id, OrgID: orgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			outboxBatch.Queue(`INSERT INTO budget_reset_outbox (id, scope, entity_id, org_id, reset_at) VALUES ($1,$2,$3,$4,$5)`, event.ID, event.Scope, event.EntityID, event.OrgID, event.ResetAt)
			outboxCount++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return BudgetResetResult{}, fmt.Errorf("iterate reset budget ids: %w", err)
		}
		rows.Close()
	}

	if outboxCount > 0 {
		br := tx.SendBatch(ctx, outboxBatch)
		for i := 0; i < outboxCount; i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return BudgetResetResult{}, fmt.Errorf("enqueue Redis budget reset: %w", err)
			}
		}
		if err := br.Close(); err != nil {
			return BudgetResetResult{}, fmt.Errorf("close budget reset outbox batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return BudgetResetResult{}, fmt.Errorf("commit reset budgets tx: %w", err)
	}

	memRes, _ := p.mem.ResetExpiredBudgetsWithIDs(ctx, now)
	if res.Total() == 0 {
		return memRes, nil
	}
	return res, nil
}

func (p *PostgresRepository) ListPendingBudgetResets(ctx context.Context, limit int) ([]BudgetResetEvent, error) {
	if limit <= 0 {
		limit = 250
	}
	rows, err := p.pool.Query(ctx, `SELECT id::text, scope, entity_id, org_id, reset_at FROM budget_reset_outbox WHERE delivered_at IS NULL ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending budget resets: %w", err)
	}
	defer rows.Close()
	var out []BudgetResetEvent
	for rows.Next() {
		var ev BudgetResetEvent
		if err := rows.Scan(&ev.ID, &ev.Scope, &ev.EntityID, &ev.OrgID, &ev.ResetAt); err != nil {
			return nil, fmt.Errorf("scan pending budget reset: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) MarkBudgetResetsDelivered(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.pool.Exec(ctx, `UPDATE budget_reset_outbox SET delivered_at = NOW() WHERE id::text = ANY($1) AND delivered_at IS NULL`, ids)
	if err != nil {
		return fmt.Errorf("mark budget resets delivered: %w", err)
	}
	return nil
}

// SetAuditLogObserver forwards audit log events recorded through PostgresRepository to fn.
func (p *PostgresRepository) SetAuditLogObserver(fn func(*domain.AuditLog)) {
	if p != nil && p.mem != nil {
		p.mem.SetAuditLogObserver(fn)
	}
}

func (p *PostgresRepository) RecordAuditLog(ctx context.Context, log *domain.AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.RecordAuditLog(ctx, log)
	}
	detailsJSON, _ := json.Marshal(log.Details)
	if len(detailsJSON) == 0 || string(detailsJSON) == "null" {
		detailsJSON = []byte("{}")
	}
	var beforeJSON, afterJSON []byte
	if log.BeforeValue != nil {
		beforeJSON, _ = json.Marshal(log.BeforeValue)
	}
	if log.AfterValue != nil {
		afterJSON, _ = json.Marshal(log.AfterValue)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO audit_logs (id, org_id, actor_id, action, resource, resource_id, details, before_value, after_value) VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8, $9)`,
		log.ID, log.OrgID, log.ActorID, log.Action, log.Resource, log.ResourceID, detailsJSON, beforeJSON, afterJSON,
	); err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return p.mem.RecordAuditLog(ctx, log)
}

func (p *PostgresRepository) ListAuditLogs(ctx context.Context, orgID string, limit int) ([]*domain.AuditLog, error) {
	logs, _, err := p.ListAuditLogsFiltered(ctx, domain.AuditLogFilter{
		OrgID: orgID,
		Limit: limit,
	})
	return logs, err
}

func (p *PostgresRepository) ListAuditLogsFiltered(ctx context.Context, filter domain.AuditLogFilter) ([]*domain.AuditLog, string, error) {
	if p.pool == nil {
		return p.mem.ListAuditLogsFiltered(ctx, filter)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	var conds []string
	var args []any
	addCond := func(clause string, vals ...any) {
		args = append(args, vals...)
		conds = append(conds, clause)
	}

	if v := strings.TrimSpace(filter.OrgID); v != "" {
		addCond(fmt.Sprintf("org_id = $%d", len(args)+1), v)
	}
	if v := strings.TrimSpace(filter.ActorID); v != "" {
		addCond(fmt.Sprintf("actor_id = $%d", len(args)+1), v)
	}
	if v := strings.TrimSpace(filter.Action); v != "" {
		addCond(fmt.Sprintf("action = $%d", len(args)+1), v)
	}
	if v := strings.TrimSpace(filter.Resource); v != "" {
		addCond(fmt.Sprintf("resource = $%d", len(args)+1), v)
	}
	if v := strings.TrimSpace(filter.ResourceID); v != "" {
		addCond(fmt.Sprintf("resource_id = $%d", len(args)+1), v)
	}
	if filter.Since != nil {
		addCond(fmt.Sprintf("created_at >= $%d", len(args)+1), filter.Since.UTC())
	}
	if filter.Until != nil {
		addCond(fmt.Sprintf("created_at <= $%d", len(args)+1), filter.Until.UTC())
	}
	if strings.TrimSpace(filter.Cursor) != "" {
		ct, cid, err := decodeAuditLogCursor(filter.Cursor)
		if err != nil {
			return nil, "", fmt.Errorf("invalid audit log cursor: %w", err)
		}
		pTime := len(args) + 1
		pID := len(args) + 2
		addCond(fmt.Sprintf("(created_at, id) < ($%d, $%d)", pTime, pID), ct.UTC(), cid)
	}

	q := `SELECT id, COALESCE(org_id, ''), actor_id, action, resource, resource_id, details, before_value, after_value, created_at FROM audit_logs`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	args = append(args, limit+1)
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListAuditLogsFiltered(ctx, filter)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		var a domain.AuditLog
		var detailsJSON, beforeJSON, afterJSON []byte
		if err := rows.Scan(&a.ID, &a.OrgID, &a.ActorID, &a.Action, &a.Resource, &a.ResourceID, &detailsJSON, &beforeJSON, &afterJSON, &a.CreatedAt); err != nil {
			return nil, "", err
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &a.Details)
		}
		if len(beforeJSON) > 0 {
			_ = json.Unmarshal(beforeJSON, &a.BeforeValue)
		}
		if len(afterJSON) > 0 {
			_ = json.Unmarshal(afterJSON, &a.AfterValue)
		}
		logs = append(logs, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var nextCursor string
	if len(logs) > limit {
		logs = logs[:limit]
		last := logs[len(logs)-1]
		nextCursor = encodeAuditLogCursor(last.CreatedAt, last.ID)
	}
	if len(logs) == 0 && filter.Cursor == "" && filter.ActorID == "" && filter.Action == "" && filter.Resource == "" && filter.ResourceID == "" && filter.Since == nil && filter.Until == nil {
		return p.mem.ListAuditLogsFiltered(ctx, filter)
	}
	return logs, nextCursor, nil
}
