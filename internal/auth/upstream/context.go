package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// UpstreamAuthContext encapsulates the caller identity, server destination,
// and delegation attributes required to resolve upstream authentication.
type UpstreamAuthContext struct {
	ServerID          string            `json:"server_id"`
	ServerSlug        string            `json:"server_slug"`
	TargetURL         string            `json:"target_url"`
	CallingOrgID      string            `json:"calling_org_id"`
	CallingTeamID     string            `json:"calling_team_id,omitempty"`
	CallingUserID     string            `json:"calling_user_id,omitempty"`
	CallingVirtualKey string            `json:"calling_virtual_key,omitempty"`
	CallingAgentID    string            `json:"calling_agent_id,omitempty"`
	DelegatedToken    string            `json:"-"` // Never serialized in logs
	ExtraHeaders      map[string]string `json:"-"` // Never serialized in logs
}

// PrincipalDigest computes a deterministic SHA-256 hex digest of the caller context
// to isolate cache keys and session states per upstream principal.
func (c *UpstreamAuthContext) PrincipalDigest() string {
	h := sha256.New()
	fmt.Fprintf(h, "server:%s|org:%s|team:%s|user:%s|vk:%s|agent:%s|token:%s",
		c.ServerID,
		c.CallingOrgID,
		c.CallingTeamID,
		c.CallingUserID,
		c.CallingVirtualKey,
		c.CallingAgentID,
		c.DelegatedToken,
	)
	return hex.EncodeToString(h.Sum(nil))
}
