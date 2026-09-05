package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// GuardrailEvaluationRecord captures one guardrail evaluation event for daily
// evaluation counters and micro-dollar usage-unit rollups.
type GuardrailEvaluationRecord struct {
	OrgID         string
	GuardrailID   string
	GuardrailName string
	Date          time.Time
	TeamID        string
	VirtualKeyID  string
	Hook          string
	Decision      domain.GuardrailDecision
	UsageUnit     string
	Units         int64
	CostMicros    int64
	LatencyMs     int64
	IsError       bool
}

// GuardrailUsageFilter scopes guardrail usage summary queries.
type GuardrailUsageFilter struct {
	OrgID        string
	GuardrailID  string
	TeamID       string
	VirtualKeyID string
	StartDate    time.Time
	EndDate      time.Time
	TopLimit     int
}

// GuardrailUsageTotals holds integer aggregate metrics for an organization.
type GuardrailUsageTotals struct {
	Evaluations     int64 `json:"evaluations"`
	Blocks          int64 `json:"blocks"`
	Redactions      int64 `json:"redactions"`
	Flags           int64 `json:"flags"`
	Errors          int64 `json:"errors"`
	LatencySumMs    int64 `json:"latency_sum_ms"`
	TotalUnits      int64 `json:"total_units"`
	TotalCostMicros int64 `json:"total_cost_micros"`
}

// GuardrailDailyUsagePoint represents one daily guardrail rollup row.
type GuardrailDailyUsagePoint struct {
	Date          string `json:"date"`
	GuardrailID   string `json:"guardrail_id"`
	GuardrailName string `json:"guardrail_name"`
	Evaluations   int64  `json:"evaluations"`
	Blocks        int64  `json:"blocks"`
	Redactions    int64  `json:"redactions"`
	Flags         int64  `json:"flags"`
	Errors        int64  `json:"errors"`
	LatencySumMs  int64  `json:"latency_sum_ms"`
	Units         int64  `json:"units"`
	CostMicros    int64  `json:"cost_micros"`
}

// GuardrailUsageUnitBreakdown tracks micro-dollar usage units by tenant scope.
type GuardrailUsageUnitBreakdown struct {
	Date         string `json:"date"`
	GuardrailID  string `json:"guardrail_id"`
	TeamID       string `json:"team_id,omitempty"`
	VirtualKeyID string `json:"virtual_key_id,omitempty"`
	UsageUnit    string `json:"usage_unit"`
	Units        int64  `json:"units"`
	CostMicros   int64  `json:"cost_micros"`
}

// GuardrailTopTriggered summarizes the most frequently triggered guardrails.
type GuardrailTopTriggered struct {
	GuardrailID    string `json:"guardrail_id"`
	GuardrailName  string `json:"guardrail_name"`
	Evaluations    int64  `json:"evaluations"`
	Blocks         int64  `json:"blocks"`
	Redactions     int64  `json:"redactions"`
	Flags          int64  `json:"flags"`
	TriggeredCount int64  `json:"triggered_count"`
	Errors         int64  `json:"errors"`
	Units          int64  `json:"units"`
	CostMicros     int64  `json:"cost_micros"`
}

// GuardrailUsageSummary aggregates guardrail activity and integer micro-dollar costs.
type GuardrailUsageSummary struct {
	OrgID           string                        `json:"org_id"`
	StartDate       string                        `json:"start_date"`
	EndDate         string                        `json:"end_date"`
	Totals          GuardrailUsageTotals          `json:"totals"`
	TotalCostMicros int64                         `json:"total_cost_micros"`
	DailySeries     []GuardrailDailyUsagePoint    `json:"daily_series"`
	UsageUnits      []GuardrailUsageUnitBreakdown `json:"usage_units"`
	TopTriggered    []GuardrailTopTriggered       `json:"top_triggered"`
}

// SpendLogGuardrail links a spend log entry to an evaluated guardrail and its micro-dollar cost.
type SpendLogGuardrail struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	SpendLogID    string    `json:"spend_log_id"`
	GuardrailID   string    `json:"guardrail_id"`
	GuardrailName string    `json:"guardrail_name"`
	Hook          string    `json:"hook"`
	Decision      string    `json:"decision"`
	Units         int64     `json:"units"`
	CostMicros    int64     `json:"cost_micros"`
	CreatedAt     time.Time `json:"created_at"`
}

// GuardrailUsageRepository persists and aggregates guardrail evaluation telemetry and micro-dollar usage.
type GuardrailUsageRepository interface {
	RecordGuardrailEvaluation(ctx context.Context, record GuardrailEvaluationRecord) error
	GetGuardrailUsageSummary(ctx context.Context, filter GuardrailUsageFilter) (*GuardrailUsageSummary, error)
	RecordSpendLogGuardrail(ctx context.Context, entry *SpendLogGuardrail) error
	ListSpendLogGuardrails(ctx context.Context, orgID, spendLogID string) ([]*SpendLogGuardrail, error)
}

var (
	_ GuardrailUsageRepository = (*MemoryRepository)(nil)
	_ GuardrailUsageRepository = (*PostgresRepository)(nil)
)

type dailyMetricKey struct {
	OrgID       string
	GuardrailID string
	Date        string
}

type dailyMetricRow struct {
	OrgID         string
	GuardrailID   string
	GuardrailName string
	Date          string
	Evaluations   int64
	Blocks        int64
	Redactions    int64
	Flags         int64
	Errors        int64
	LatencySumMs  int64
}

type dailyUsageUnitKey struct {
	OrgID        string
	GuardrailID  string
	Date         string
	TeamID       string
	VirtualKeyID string
	UsageUnit    string
}

type dailyUsageUnitRow struct {
	OrgID        string
	GuardrailID  string
	Date         string
	TeamID       string
	VirtualKeyID string
	UsageUnit    string
	Units        int64
	CostMicros   int64
}

type memoryGuardrailMetricsState struct {
	mu          sync.RWMutex
	daily       map[dailyMetricKey]*dailyMetricRow
	usageUnits  map[dailyUsageUnitKey]*dailyUsageUnitRow
	spendLogMap map[string][]*SpendLogGuardrail // keyed by org_id
}

var (
	memGuardrailMetricsMu     sync.Mutex
	memGuardrailMetricsByRepo = map[weak.Pointer[MemoryRepository]]*memoryGuardrailMetricsState{}
)

func getMemoryGuardrailMetricsState(r *MemoryRepository) *memoryGuardrailMetricsState {
	wp := weak.Make(r)
	memGuardrailMetricsMu.Lock()
	defer memGuardrailMetricsMu.Unlock()
	if st, ok := memGuardrailMetricsByRepo[wp]; ok {
		return st
	}
	st := &memoryGuardrailMetricsState{
		daily:       make(map[dailyMetricKey]*dailyMetricRow),
		usageUnits:  make(map[dailyUsageUnitKey]*dailyUsageUnitRow),
		spendLogMap: make(map[string][]*SpendLogGuardrail),
	}
	memGuardrailMetricsByRepo[wp] = st
	runtime.AddCleanup(r, func(ptr weak.Pointer[MemoryRepository]) {
		memGuardrailMetricsMu.Lock()
		delete(memGuardrailMetricsByRepo, ptr)
		memGuardrailMetricsMu.Unlock()
	}, wp)
	return st
}

func normalizeGuardrailEvalRecord(record GuardrailEvaluationRecord) (GuardrailEvaluationRecord, string, error) {
	record.OrgID = strings.TrimSpace(record.OrgID)
	record.GuardrailID = strings.TrimSpace(record.GuardrailID)
	record.GuardrailName = strings.TrimSpace(record.GuardrailName)
	record.TeamID = strings.TrimSpace(record.TeamID)
	record.VirtualKeyID = strings.TrimSpace(record.VirtualKeyID)
	record.UsageUnit = strings.TrimSpace(record.UsageUnit)
	if record.OrgID == "" {
		return record, "", errors.New("org_id is required")
	}
	if record.GuardrailID == "" {
		if record.GuardrailName != "" {
			record.GuardrailID = record.GuardrailName
		} else {
			return record, "", errors.New("guardrail_id is required")
		}
	}
	if record.GuardrailName == "" {
		record.GuardrailName = record.GuardrailID
	}
	if record.Date.IsZero() {
		record.Date = time.Now().UTC()
	} else {
		record.Date = record.Date.UTC()
	}
	if record.LatencyMs < 0 {
		record.LatencyMs = 0
	}
	if record.Units < 0 {
		record.Units = 0
	}
	if record.CostMicros < 0 {
		record.CostMicros = 0
	}
	if record.UsageUnit == "" {
		record.UsageUnit = "call"
	}
	dateStr := record.Date.Format("2006-01-02")
	return record, dateStr, nil
}

func decisionIncrements(decision domain.GuardrailDecision, isError bool) (blocks, redactions, flags, errs int64) {
	if isError || strings.EqualFold(string(decision), "error") {
		errs = 1
	}
	switch strings.ToLower(strings.TrimSpace(string(decision))) {
	case string(domain.GuardrailDecisionBlock):
		blocks = 1
	case string(domain.GuardrailDecisionModify):
		redactions = 1
	case string(domain.GuardrailDecisionFlag):
		flags = 1
	}
	return blocks, redactions, flags, errs
}

func normalizeUsageRange(start, end time.Time) (time.Time, time.Time) {
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if end.IsZero() {
		end = today
	} else {
		u := end.UTC()
		end = time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	}
	if start.IsZero() {
		start = end.AddDate(0, 0, -29)
	} else {
		u := start.UTC()
		start = time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	}
	if start.After(end) {
		start = end
	}
	return start, end
}

// RecordGuardrailEvaluation persists daily metric counters and usage-unit rollups in memory.
func (r *MemoryRepository) RecordGuardrailEvaluation(ctx context.Context, record GuardrailEvaluationRecord) error {
	if r == nil {
		return errors.New("memory repository is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, dateStr, err := normalizeGuardrailEvalRecord(record)
	if err != nil {
		return err
	}
	blocks, redactions, flags, errs := decisionIncrements(rec.Decision, rec.IsError)

	st := getMemoryGuardrailMetricsState(r)
	st.mu.Lock()
	defer st.mu.Unlock()

	mk := dailyMetricKey{
		OrgID:       rec.OrgID,
		GuardrailID: rec.GuardrailID,
		Date:        dateStr,
	}
	row, ok := st.daily[mk]
	if !ok {
		row = &dailyMetricRow{
			OrgID:         rec.OrgID,
			GuardrailID:   rec.GuardrailID,
			GuardrailName: rec.GuardrailName,
			Date:          dateStr,
		}
		st.daily[mk] = row
	} else if rec.GuardrailName != "" {
		row.GuardrailName = rec.GuardrailName
	}
	row.Evaluations++
	row.Blocks += blocks
	row.Redactions += redactions
	row.Flags += flags
	row.Errors += errs
	row.LatencySumMs += rec.LatencyMs

	if rec.Units > 0 || rec.CostMicros > 0 {
		uk := dailyUsageUnitKey{
			OrgID:        rec.OrgID,
			GuardrailID:  rec.GuardrailID,
			Date:         dateStr,
			TeamID:       rec.TeamID,
			VirtualKeyID: rec.VirtualKeyID,
			UsageUnit:    rec.UsageUnit,
		}
		urow, uok := st.usageUnits[uk]
		if !uok {
			urow = &dailyUsageUnitRow{
				OrgID:        rec.OrgID,
				GuardrailID:  rec.GuardrailID,
				Date:         dateStr,
				TeamID:       rec.TeamID,
				VirtualKeyID: rec.VirtualKeyID,
				UsageUnit:    rec.UsageUnit,
			}
			st.usageUnits[uk] = urow
		}
		urow.Units += rec.Units
		urow.CostMicros += rec.CostMicros
	}

	return nil
}

// GetGuardrailUsageSummary returns tenant-isolated guardrail metrics and micro-dollar usage rollups from memory.
func (r *MemoryRepository) GetGuardrailUsageSummary(ctx context.Context, filter GuardrailUsageFilter) (*GuardrailUsageSummary, error) {
	if r == nil {
		return nil, errors.New("memory repository is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	orgID := strings.TrimSpace(filter.OrgID)
	if orgID == "" {
		return nil, errors.New("org_id is required")
	}
	start, end := normalizeUsageRange(filter.StartDate, filter.EndDate)
	startStr := start.Format("2006-01-02")
	endStr := end.Format("2006-01-02")
	topLimit := filter.TopLimit
	if topLimit <= 0 {
		topLimit = 10
	}

	st := getMemoryGuardrailMetricsState(r)
	st.mu.RLock()
	defer st.mu.RUnlock()

	type dateGuardrail struct {
		Date        string
		GuardrailID string
	}

	unitsByDateGuardrail := make(map[dateGuardrail]struct {
		Units      int64
		CostMicros int64
	})
	unitRows := make([]GuardrailUsageUnitBreakdown, 0)
	for _, u := range st.usageUnits {
		if u.OrgID != orgID {
			continue
		}
		if filter.GuardrailID != "" && u.GuardrailID != filter.GuardrailID {
			continue
		}
		if filter.TeamID != "" && u.TeamID != filter.TeamID {
			continue
		}
		if filter.VirtualKeyID != "" && u.VirtualKeyID != filter.VirtualKeyID {
			continue
		}
		if u.Date < startStr || u.Date > endStr {
			continue
		}
		unitRows = append(unitRows, GuardrailUsageUnitBreakdown{
			Date:         u.Date,
			GuardrailID:  u.GuardrailID,
			TeamID:       u.TeamID,
			VirtualKeyID: u.VirtualKeyID,
			UsageUnit:    u.UsageUnit,
			Units:        u.Units,
			CostMicros:   u.CostMicros,
		})
		dg := dateGuardrail{Date: u.Date, GuardrailID: u.GuardrailID}
		cur := unitsByDateGuardrail[dg]
		cur.Units += u.Units
		cur.CostMicros += u.CostMicros
		unitsByDateGuardrail[dg] = cur
	}

	dailyMap := make(map[dateGuardrail]*GuardrailDailyUsagePoint)
	for _, m := range st.daily {
		if m.OrgID != orgID {
			continue
		}
		if filter.GuardrailID != "" && m.GuardrailID != filter.GuardrailID {
			continue
		}
		if m.Date < startStr || m.Date > endStr {
			continue
		}
		dg := dateGuardrail{Date: m.Date, GuardrailID: m.GuardrailID}
		uAgg, hasUnits := unitsByDateGuardrail[dg]
		if (filter.TeamID != "" || filter.VirtualKeyID != "") && !hasUnits {
			continue
		}
		dailyMap[dg] = &GuardrailDailyUsagePoint{
			Date:          m.Date,
			GuardrailID:   m.GuardrailID,
			GuardrailName: m.GuardrailName,
			Evaluations:   m.Evaluations,
			Blocks:        m.Blocks,
			Redactions:    m.Redactions,
			Flags:         m.Flags,
			Errors:        m.Errors,
			LatencySumMs:  m.LatencySumMs,
			Units:         uAgg.Units,
			CostMicros:    uAgg.CostMicros,
		}
	}

	for dg, uAgg := range unitsByDateGuardrail {
		if _, ok := dailyMap[dg]; !ok {
			dailyMap[dg] = &GuardrailDailyUsagePoint{
				Date:          dg.Date,
				GuardrailID:   dg.GuardrailID,
				GuardrailName: dg.GuardrailID,
				Units:         uAgg.Units,
				CostMicros:    uAgg.CostMicros,
			}
		}
	}

	dailySeries := make([]GuardrailDailyUsagePoint, 0, len(dailyMap))
	for _, pt := range dailyMap {
		dailySeries = append(dailySeries, *pt)
	}

	return buildGuardrailUsageSummary(orgID, startStr, endStr, dailySeries, unitRows, topLimit), nil
}

// RecordSpendLogGuardrail stores a spend-log guardrail attribution record in memory.
func (r *MemoryRepository) RecordSpendLogGuardrail(ctx context.Context, entry *SpendLogGuardrail) error {
	if r == nil {
		return errors.New("memory repository is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if entry == nil {
		return errors.New("spend_log_guardrail entry is required")
	}
	if strings.TrimSpace(entry.OrgID) == "" || strings.TrimSpace(entry.SpendLogID) == "" || strings.TrimSpace(entry.GuardrailID) == "" {
		return errors.New("org_id, spend_log_id, and guardrail_id are required")
	}
	cp := *entry
	if cp.ID == "" {
		cp.ID = generateGuardrailMetricID()
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}

	st := getMemoryGuardrailMetricsState(r)
	st.mu.Lock()
	st.spendLogMap[cp.OrgID] = append(st.spendLogMap[cp.OrgID], &cp)
	st.mu.Unlock()
	*entry = cp
	return nil
}

// ListSpendLogGuardrails lists spend-log guardrail attributions scoped by org_id and optional spend_log_id.
func (r *MemoryRepository) ListSpendLogGuardrails(ctx context.Context, orgID, spendLogID string) ([]*SpendLogGuardrail, error) {
	if r == nil {
		return nil, errors.New("memory repository is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	orgID = strings.TrimSpace(orgID)
	spendLogID = strings.TrimSpace(spendLogID)
	if orgID == "" {
		return nil, errors.New("org_id is required")
	}
	st := getMemoryGuardrailMetricsState(r)
	st.mu.RLock()
	entries := st.spendLogMap[orgID]
	out := make([]*SpendLogGuardrail, 0, len(entries))
	for _, item := range entries {
		if spendLogID != "" && item.SpendLogID != spendLogID {
			continue
		}
		cp := *item
		out = append(out, &cp)
	}
	st.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// RecordGuardrailEvaluation persists daily metric counters and usage-unit rollups in PostgreSQL.
func (r *PostgresRepository) RecordGuardrailEvaluation(ctx context.Context, record GuardrailEvaluationRecord) error {
	if r == nil || r.pool == nil {
		return errors.New("postgres pool is not configured")
	}
	rec, dateStr, err := normalizeGuardrailEvalRecord(record)
	if err != nil {
		return err
	}
	blocks, redactions, flags, errs := decisionIncrements(rec.Decision, rec.IsError)

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin guardrail evaluation tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO daily_guardrail_metrics (
			org_id, guardrail_id, guardrail_name, date,
			evaluations, blocks, redactions, flags, errors, latency_sum_ms, updated_at
		) VALUES (
			$1, $2, $3, $4::date,
			1, $5, $6, $7, $8, $9, NOW()
		)
		ON CONFLICT (org_id, guardrail_id, date) DO UPDATE SET
			guardrail_name = CASE WHEN EXCLUDED.guardrail_name <> '' THEN EXCLUDED.guardrail_name ELSE daily_guardrail_metrics.guardrail_name END,
			evaluations = daily_guardrail_metrics.evaluations + 1,
			blocks = daily_guardrail_metrics.blocks + EXCLUDED.blocks,
			redactions = daily_guardrail_metrics.redactions + EXCLUDED.redactions,
			flags = daily_guardrail_metrics.flags + EXCLUDED.flags,
			errors = daily_guardrail_metrics.errors + EXCLUDED.errors,
			latency_sum_ms = daily_guardrail_metrics.latency_sum_ms + EXCLUDED.latency_sum_ms,
			updated_at = NOW()`,
		rec.OrgID, rec.GuardrailID, rec.GuardrailName, dateStr,
		blocks, redactions, flags, errs, rec.LatencyMs,
	)
	if err != nil {
		return fmt.Errorf("upsert daily_guardrail_metrics: %w", err)
	}

	if rec.Units > 0 || rec.CostMicros > 0 {
		_, err = tx.Exec(ctx, `
			INSERT INTO daily_guardrail_usage_units (
				org_id, guardrail_id, date, team_id, virtual_key_id, usage_unit,
				units, cost_micros, updated_at
			) VALUES (
				$1, $2, $3::date, $4, $5, $6,
				$7, $8, NOW()
			)
			ON CONFLICT (org_id, guardrail_id, date, team_id, virtual_key_id, usage_unit) DO UPDATE SET
				units = daily_guardrail_usage_units.units + EXCLUDED.units,
				cost_micros = daily_guardrail_usage_units.cost_micros + EXCLUDED.cost_micros,
				updated_at = NOW()`,
			rec.OrgID, rec.GuardrailID, dateStr, rec.TeamID, rec.VirtualKeyID, rec.UsageUnit,
			rec.Units, rec.CostMicros,
		)
		if err != nil {
			return fmt.Errorf("upsert daily_guardrail_usage_units: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit guardrail evaluation tx: %w", err)
	}
	return nil
}

// GetGuardrailUsageSummary queries tenant-isolated guardrail metrics and micro-dollar usage rollups from PostgreSQL.
func (r *PostgresRepository) GetGuardrailUsageSummary(ctx context.Context, filter GuardrailUsageFilter) (*GuardrailUsageSummary, error) {
	if r == nil || r.pool == nil {
		return nil, errors.New("postgres pool is not configured")
	}
	orgID := strings.TrimSpace(filter.OrgID)
	if orgID == "" {
		return nil, errors.New("org_id is required")
	}
	start, end := normalizeUsageRange(filter.StartDate, filter.EndDate)
	startStr := start.Format("2006-01-02")
	endStr := end.Format("2006-01-02")
	topLimit := filter.TopLimit
	if topLimit <= 0 {
		topLimit = 10
	}

	// Query usage units scoped strictly by org_id (and optional guardrail/team/key filters).
	unitArgs := []any{orgID, startStr, endStr}
	unitConds := []string{"org_id = $1", "date >= $2::date", "date <= $3::date"}
	if filter.GuardrailID != "" {
		unitArgs = append(unitArgs, filter.GuardrailID)
		unitConds = append(unitConds, fmt.Sprintf("guardrail_id = $%d", len(unitArgs)))
	}
	if filter.TeamID != "" {
		unitArgs = append(unitArgs, filter.TeamID)
		unitConds = append(unitConds, fmt.Sprintf("team_id = $%d", len(unitArgs)))
	}
	if filter.VirtualKeyID != "" {
		unitArgs = append(unitArgs, filter.VirtualKeyID)
		unitConds = append(unitConds, fmt.Sprintf("virtual_key_id = $%d", len(unitArgs)))
	}

	unitRowsQuery := `
		SELECT to_char(date, 'YYYY-MM-DD'), guardrail_id, team_id, virtual_key_id, usage_unit, units, cost_micros
		FROM daily_guardrail_usage_units
		WHERE ` + strings.Join(unitConds, " AND ") + `
		ORDER BY date ASC, guardrail_id ASC, usage_unit ASC`

	uRows, err := r.pool.Query(ctx, unitRowsQuery, unitArgs...)
	if err != nil {
		return nil, fmt.Errorf("query daily_guardrail_usage_units: %w", err)
	}
	defer uRows.Close()

	type dateGuardrail struct {
		Date        string
		GuardrailID string
	}
	unitsByDateGuardrail := make(map[dateGuardrail]struct {
		Units      int64
		CostMicros int64
	})
	unitRows := make([]GuardrailUsageUnitBreakdown, 0)
	for uRows.Next() {
		var row GuardrailUsageUnitBreakdown
		if err := uRows.Scan(&row.Date, &row.GuardrailID, &row.TeamID, &row.VirtualKeyID, &row.UsageUnit, &row.Units, &row.CostMicros); err != nil {
			return nil, fmt.Errorf("scan daily_guardrail_usage_units: %w", err)
		}
		unitRows = append(unitRows, row)
		dg := dateGuardrail{Date: row.Date, GuardrailID: row.GuardrailID}
		cur := unitsByDateGuardrail[dg]
		cur.Units += row.Units
		cur.CostMicros += row.CostMicros
		unitsByDateGuardrail[dg] = cur
	}
	if err := uRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate daily_guardrail_usage_units: %w", err)
	}

	metricArgs := []any{orgID, startStr, endStr}
	metricConds := []string{"org_id = $1", "date >= $2::date", "date <= $3::date"}
	if filter.GuardrailID != "" {
		metricArgs = append(metricArgs, filter.GuardrailID)
		metricConds = append(metricConds, fmt.Sprintf("guardrail_id = $%d", len(metricArgs)))
	}
	metricQuery := `
		SELECT to_char(date, 'YYYY-MM-DD'), guardrail_id, guardrail_name,
		       evaluations, blocks, redactions, flags, errors, latency_sum_ms
		FROM daily_guardrail_metrics
		WHERE ` + strings.Join(metricConds, " AND ") + `
		ORDER BY date ASC, guardrail_id ASC`

	mRows, err := r.pool.Query(ctx, metricQuery, metricArgs...)
	if err != nil {
		return nil, fmt.Errorf("query daily_guardrail_metrics: %w", err)
	}
	defer mRows.Close()

	dailyMap := make(map[dateGuardrail]*GuardrailDailyUsagePoint)
	for mRows.Next() {
		var pt GuardrailDailyUsagePoint
		if err := mRows.Scan(
			&pt.Date, &pt.GuardrailID, &pt.GuardrailName,
			&pt.Evaluations, &pt.Blocks, &pt.Redactions, &pt.Flags, &pt.Errors, &pt.LatencySumMs,
		); err != nil {
			return nil, fmt.Errorf("scan daily_guardrail_metrics: %w", err)
		}
		dg := dateGuardrail{Date: pt.Date, GuardrailID: pt.GuardrailID}
		uAgg, hasUnits := unitsByDateGuardrail[dg]
		if (filter.TeamID != "" || filter.VirtualKeyID != "") && !hasUnits {
			continue
		}
		pt.Units = uAgg.Units
		pt.CostMicros = uAgg.CostMicros
		dailyMap[dg] = &pt
	}
	if err := mRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate daily_guardrail_metrics: %w", err)
	}

	for dg, uAgg := range unitsByDateGuardrail {
		if _, ok := dailyMap[dg]; !ok {
			dailyMap[dg] = &GuardrailDailyUsagePoint{
				Date:          dg.Date,
				GuardrailID:   dg.GuardrailID,
				GuardrailName: dg.GuardrailID,
				Units:         uAgg.Units,
				CostMicros:    uAgg.CostMicros,
			}
		}
	}

	dailySeries := make([]GuardrailDailyUsagePoint, 0, len(dailyMap))
	for _, pt := range dailyMap {
		dailySeries = append(dailySeries, *pt)
	}

	return buildGuardrailUsageSummary(orgID, startStr, endStr, dailySeries, unitRows, topLimit), nil
}

// RecordSpendLogGuardrail inserts a spend-log guardrail attribution record into PostgreSQL.
func (r *PostgresRepository) RecordSpendLogGuardrail(ctx context.Context, entry *SpendLogGuardrail) error {
	if r == nil || r.pool == nil {
		return errors.New("postgres pool is not configured")
	}
	if entry == nil {
		return errors.New("spend_log_guardrail entry is required")
	}
	if strings.TrimSpace(entry.OrgID) == "" || strings.TrimSpace(entry.SpendLogID) == "" || strings.TrimSpace(entry.GuardrailID) == "" {
		return errors.New("org_id, spend_log_id, and guardrail_id are required")
	}
	if entry.ID == "" {
		entry.ID = generateGuardrailMetricID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO spend_log_guardrails (
			id, org_id, spend_log_id, guardrail_id, guardrail_name,
			hook, decision, units, cost_micros, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		entry.ID, entry.OrgID, entry.SpendLogID, entry.GuardrailID, entry.GuardrailName,
		entry.Hook, entry.Decision, entry.Units, entry.CostMicros, entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert spend_log_guardrails: %w", err)
	}
	return nil
}

// ListSpendLogGuardrails returns spend-log guardrail attributions scoped to an organization.
func (r *PostgresRepository) ListSpendLogGuardrails(ctx context.Context, orgID, spendLogID string) ([]*SpendLogGuardrail, error) {
	if r == nil || r.pool == nil {
		return nil, errors.New("postgres pool is not configured")
	}
	orgID = strings.TrimSpace(orgID)
	spendLogID = strings.TrimSpace(spendLogID)
	if orgID == "" {
		return nil, errors.New("org_id is required")
	}

	args := []any{orgID}
	query := `
		SELECT id, org_id, spend_log_id, guardrail_id, guardrail_name,
		       hook, decision, units, cost_micros, created_at
		FROM spend_log_guardrails
		WHERE org_id = $1`
	if spendLogID != "" {
		args = append(args, spendLogID)
		query += ` AND spend_log_id = $2`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query spend_log_guardrails: %w", err)
	}
	defer rows.Close()

	out := make([]*SpendLogGuardrail, 0)
	for rows.Next() {
		var item SpendLogGuardrail
		if err := rows.Scan(
			&item.ID, &item.OrgID, &item.SpendLogID, &item.GuardrailID, &item.GuardrailName,
			&item.Hook, &item.Decision, &item.Units, &item.CostMicros, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan spend_log_guardrails: %w", err)
		}
		out = append(out, &item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate spend_log_guardrails: %w", err)
	}
	return out, nil
}

func buildGuardrailUsageSummary(
	orgID, startStr, endStr string,
	dailySeries []GuardrailDailyUsagePoint,
	unitRows []GuardrailUsageUnitBreakdown,
	topLimit int,
) *GuardrailUsageSummary {
	sort.Slice(dailySeries, func(i, j int) bool {
		if dailySeries[i].Date != dailySeries[j].Date {
			return dailySeries[i].Date < dailySeries[j].Date
		}
		return dailySeries[i].GuardrailID < dailySeries[j].GuardrailID
	})
	sort.Slice(unitRows, func(i, j int) bool {
		if unitRows[i].Date != unitRows[j].Date {
			return unitRows[i].Date < unitRows[j].Date
		}
		if unitRows[i].GuardrailID != unitRows[j].GuardrailID {
			return unitRows[i].GuardrailID < unitRows[j].GuardrailID
		}
		return unitRows[i].UsageUnit < unitRows[j].UsageUnit
	})

	var totals GuardrailUsageTotals
	topMap := make(map[string]*GuardrailTopTriggered)
	for _, pt := range dailySeries {
		totals.Evaluations += pt.Evaluations
		totals.Blocks += pt.Blocks
		totals.Redactions += pt.Redactions
		totals.Flags += pt.Flags
		totals.Errors += pt.Errors
		totals.LatencySumMs += pt.LatencySumMs
		totals.TotalUnits += pt.Units
		totals.TotalCostMicros += pt.CostMicros

		top, ok := topMap[pt.GuardrailID]
		if !ok {
			top = &GuardrailTopTriggered{
				GuardrailID:   pt.GuardrailID,
				GuardrailName: pt.GuardrailName,
			}
			topMap[pt.GuardrailID] = top
		} else if pt.GuardrailName != "" && top.GuardrailName == top.GuardrailID {
			top.GuardrailName = pt.GuardrailName
		}
		top.Evaluations += pt.Evaluations
		top.Blocks += pt.Blocks
		top.Redactions += pt.Redactions
		top.Flags += pt.Flags
		top.TriggeredCount += pt.Blocks + pt.Redactions + pt.Flags
		top.Errors += pt.Errors
		top.Units += pt.Units
		top.CostMicros += pt.CostMicros
	}

	topList := make([]GuardrailTopTriggered, 0, len(topMap))
	for _, t := range topMap {
		topList = append(topList, *t)
	}
	sort.Slice(topList, func(i, j int) bool {
		if topList[i].TriggeredCount != topList[j].TriggeredCount {
			return topList[i].TriggeredCount > topList[j].TriggeredCount
		}
		if topList[i].Evaluations != topList[j].Evaluations {
			return topList[i].Evaluations > topList[j].Evaluations
		}
		return topList[i].GuardrailID < topList[j].GuardrailID
	})
	if topLimit > 0 && len(topList) > topLimit {
		topList = topList[:topLimit]
	}

	return &GuardrailUsageSummary{
		OrgID:           orgID,
		StartDate:       startStr,
		EndDate:         endStr,
		Totals:          totals,
		TotalCostMicros: totals.TotalCostMicros,
		DailySeries:     dailySeries,
		UsageUnits:      unitRows,
		TopTriggered:    topList,
	}
}

func generateGuardrailMetricID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("grlog_%d", time.Now().UTC().UnixNano())
	}
	return "grlog_" + hex.EncodeToString(raw[:])
}
