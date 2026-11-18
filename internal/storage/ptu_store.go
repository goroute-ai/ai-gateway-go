package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// ErrTeamHasActivePTUShares is returned when deleting a team that still owns
// one or more deployment_ptu_shares allocations.
var ErrTeamHasActivePTUShares = errors.New("team has active PTU shares")

// PTUShareRepository is an optional Repository extension for managing
// Provisioned Throughput Unit (PTU) deployment team shares and organization
// priority classes.
type PTUShareRepository interface {
	UpsertDeploymentPTUShare(ctx context.Context, share *domain.DeploymentPTUShare) error
	ListDeploymentPTUShares(ctx context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error)
	DeleteDeploymentPTUShare(ctx context.Context, deploymentID, teamID string) error
	HasTeamPTUShares(ctx context.Context, teamID string) (bool, error)
	UpsertPriorityClass(ctx context.Context, pc *domain.PriorityClass) error
	ListPriorityClasses(ctx context.Context, orgID string) ([]*domain.PriorityClass, error)
}

var (
	_ PTUShareRepository = (*MemoryRepository)(nil)
	_ PTUShareRepository = (*PostgresRepository)(nil)
)

func ptuShareTupleKey(deploymentID, teamID string) string {
	return deploymentID + "\x00" + teamID
}

func priorityClassTupleKey(orgID, name string) string {
	return orgID + "\x00" + name
}

func normalizePTUShare(share *domain.DeploymentPTUShare, now time.Time) error {
	if share == nil {
		return fmt.Errorf("deployment PTU share is required")
	}
	share.OrgID = strings.TrimSpace(share.OrgID)
	share.DeploymentID = strings.TrimSpace(share.DeploymentID)
	share.TeamID = strings.TrimSpace(share.TeamID)
	if share.OrgID == "" {
		return fmt.Errorf("org_id is required for deployment PTU share")
	}
	if share.DeploymentID == "" {
		return fmt.Errorf("deployment_id is required for deployment PTU share")
	}
	if share.TeamID == "" {
		return fmt.Errorf("team_id is required for deployment PTU share")
	}
	if share.ReservedRPM < 0 || share.ReservedTPM < 0 {
		return fmt.Errorf("reserved_rpm and reserved_tpm must be non-negative")
	}
	if share.CreatedAt.IsZero() {
		share.CreatedAt = now
	}
	share.UpdatedAt = now
	return nil
}

func normalizePriorityClass(pc *domain.PriorityClass, now time.Time) error {
	if pc == nil {
		return fmt.Errorf("priority class is required")
	}
	pc.OrgID = strings.TrimSpace(pc.OrgID)
	pc.Name = strings.TrimSpace(pc.Name)
	if pc.OrgID == "" {
		return fmt.Errorf("org_id is required for priority class")
	}
	if pc.Name == "" {
		return fmt.Errorf("name is required for priority class")
	}
	if pc.Weight < 0 {
		return fmt.Errorf("weight must be non-negative")
	}
	if pc.Weight == 0 {
		pc.Weight = 1.0
	}
	if pc.MaxBorrowMultiple < 0 {
		return fmt.Errorf("max_borrow_multiple must be non-negative")
	}
	if pc.MaxBorrowMultiple == 0 {
		pc.MaxBorrowMultiple = 2.0
	}
	if pc.CreatedAt.IsZero() {
		pc.CreatedAt = now
	}
	return nil
}

func sortPTUShares(list []*domain.DeploymentPTUShare) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].DeploymentID != list[j].DeploymentID {
			return list[i].DeploymentID < list[j].DeploymentID
		}
		if list[i].TeamID != list[j].TeamID {
			return list[i].TeamID < list[j].TeamID
		}
		return list[i].ID < list[j].ID
	})
}

func sortPriorityClasses(list []*domain.PriorityClass) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].PriorityRank != list[j].PriorityRank {
			return list[i].PriorityRank < list[j].PriorityRank
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}
