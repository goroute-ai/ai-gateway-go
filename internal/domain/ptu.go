package domain

import "time"

// DeploymentPTUShare allocates a dedicated Provisioned Throughput Unit (PTU)
// RPM/TPM capacity slice on a physical deployment for a specific team.
type DeploymentPTUShare struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	DeploymentID string    `json:"deployment_id"`
	TeamID       string    `json:"team_id"`
	ReservedRPM  int       `json:"reserved_rpm"`
	ReservedTPM  int       `json:"reserved_tpm"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Clone returns a copy of the DeploymentPTUShare.
func (s *DeploymentPTUShare) Clone() *DeploymentPTUShare {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}

// PriorityClass defines a weighted capacity-sharing class for an organization.
type PriorityClass struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"org_id"`
	Name              string    `json:"name"`
	Weight            float64   `json:"weight"`
	PriorityRank      int       `json:"priority_rank"`
	MaxBorrowMultiple float64   `json:"max_borrow_multiple"`
	CreatedAt         time.Time `json:"created_at"`
}

// Clone returns a copy of the PriorityClass.
func (p *PriorityClass) Clone() *PriorityClass {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}
