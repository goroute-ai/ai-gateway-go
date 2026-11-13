package server

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (s *GatewayServer) evaluateGuardrailText(ctx context.Context, orgID string, texts ...string) error {
	_, err := s.guardrailTextValues(ctx, orgID, texts...)
	return err
}

func (s *GatewayServer) guardrailTextValues(ctx context.Context, orgID string, texts ...string) ([]string, error) {
	if s.guardrails == nil {
		return append([]string(nil), texts...), nil
	}
	req := &domain.CanonicalChatRequest{}
	for _, text := range texts {
		if text != "" {
			req.Messages = append(req.Messages, domain.CanonicalMessage{Role: "user", Content: text})
		}
	}
	if len(req.Messages) == 0 {
		return append([]string(nil), texts...), nil
	}
	_, err := s.guardrails.EvaluateInput(ctx, orgID, req)
	if err != nil {
		return nil, err
	}
	updated := make([]string, len(req.Messages))
	for i := range req.Messages {
		updated[i] = req.Messages[i].Content
	}
	return updated, nil
}

func (s *GatewayServer) guardrailInputValue(ctx context.Context, orgID string, value any) (any, error) {
	switch v := value.(type) {
	case string:
		updated, err := s.guardrailTextValues(ctx, orgID, v)
		if err != nil {
			return nil, err
		}
		return updated[0], nil
	case map[string]any:
		for key, item := range v {
			updated, err := s.guardrailInputValue(ctx, orgID, item)
			if err != nil {
				return nil, err
			}
			v[key] = updated
		}
		return v, nil
	case []any:
		for i, item := range v {
			updated, err := s.guardrailInputValue(ctx, orgID, item)
			if err != nil {
				return nil, err
			}
			v[i] = updated
		}
		return v, nil
	default:
		return value, nil
	}
}

func (s *GatewayServer) sanitizeGuardrailValue(ctx context.Context, orgID string, value any) (any, bool, error) {
	switch v := value.(type) {
	case string:
		updated, err := s.sanitizeGuardrailText(ctx, orgID, v)
		return updated, updated != v, err
	case map[string]any:
		changed := false
		for key, item := range v {
			updated, itemChanged, err := s.sanitizeGuardrailValue(ctx, orgID, item)
			if err != nil {
				return nil, false, err
			}
			v[key] = updated
			changed = changed || itemChanged
		}
		return v, changed, nil
	case []any:
		changed := false
		for i, item := range v {
			updated, itemChanged, err := s.sanitizeGuardrailValue(ctx, orgID, item)
			if err != nil {
				return nil, false, err
			}
			v[i] = updated
			changed = changed || itemChanged
		}
		return v, changed, nil
	default:
		return value, false, nil
	}
}

func (s *GatewayServer) sanitizeGuardrailText(ctx context.Context, orgID, text string) (string, error) {
	if s.guardrails == nil {
		return text, nil
	}
	updated, _, err := s.guardrails.SanitizeTextOutput(ctx, orgID, text)
	return updated, err
}
