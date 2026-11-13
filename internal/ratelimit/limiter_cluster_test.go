package ratelimit

import (
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// redisClusterSlot computes the Redis Cluster CRC16-CCITT hash slot (0..16383)
// according to the Redis Cluster specification, extracting the first non-empty {...} hash tag.
func redisClusterSlot(key string) uint16 {
	hashKey := key
	if s := strings.IndexByte(key, '{'); s >= 0 {
		if e := strings.IndexByte(key[s+1:], '}'); e > 0 {
			hashKey = key[s+1 : s+1+e]
		}
	}
	var crc uint16
	for i := 0; i < len(hashKey); i++ {
		crc ^= uint16(hashKey[i]) << 8
		for b := 0; b < 8; b++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc % 16384
}

func assertSameClusterSlot(t *testing.T, label string, keys []string) {
	t.Helper()
	if len(keys) == 0 {
		t.Fatalf("%s: expected non-empty keys", label)
	}
	wantSlot := redisClusterSlot(keys[0])
	for i, k := range keys {
		if got := redisClusterSlot(k); got != wantSlot {
			t.Fatalf("%s: key[%d] (%q) mapped to slot %d, want slot %d (key[0]=%q)", label, i, k, got, wantSlot, keys[0])
		}
	}
}

func TestRateLimitKeysAlignToSameClusterSlot(t *testing.T) {
	cases := []struct {
		name  string
		idCtx *domain.IdentityContext
		tag   string
	}{
		{
			name: "explicit org ID",
			idCtx: &domain.IdentityContext{
				VirtualKeyID: "key_123",
				TeamID:       "team_456",
				OrgID:        "org_acme",
			},
			tag: "{org:org_acme}",
		},
		{
			name: "empty org ID falls back to default",
			idCtx: &domain.IdentityContext{
				VirtualKeyID: "key_123",
				TeamID:       "",
				OrgID:        "",
			},
			tag: "{org:default}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acq := acquireKeys(tc.idCtx, 12345)
			if len(acq) != 13 {
				t.Fatalf("acquireKeys len = %d, want 13", len(acq))
			}
			for i, k := range acq {
				if !strings.Contains(k, tc.tag) {
					t.Fatalf("acquireKeys[%d] = %q, missing hash tag %q", i, k, tc.tag)
				}
			}
			assertSameClusterSlot(t, "acquireKeys", acq)

			rec := reconcileKeys(acq)
			if len(rec) != 10 {
				t.Fatalf("reconcileKeys len = %d, want 10", len(rec))
			}
			assertSameClusterSlot(t, "reconcileKeys", rec)
			if redisClusterSlot(rec[0]) != redisClusterSlot(acq[0]) {
				t.Fatalf("reconcileKeys slot %d != acquireKeys slot %d", redisClusterSlot(rec[0]), redisClusterSlot(acq[0]))
			}

			sp := spendKeys(tc.idCtx.VirtualKeyID, tc.idCtx.TeamID, tc.idCtx.OrgID)
			if len(sp) != 6 {
				t.Fatalf("spendKeys len = %d, want 6", len(sp))
			}
			for i, k := range sp {
				if !strings.Contains(k, tc.tag) {
					t.Fatalf("spendKeys[%d] = %q, missing hash tag %q", i, k, tc.tag)
				}
			}
			assertSameClusterSlot(t, "spendKeys", sp)
			if redisClusterSlot(sp[0]) != redisClusterSlot(acq[0]) {
				t.Fatalf("spendKeys slot %d != acquireKeys slot %d", redisClusterSlot(sp[0]), redisClusterSlot(acq[0]))
			}
			idempotencyKey := "gw:spend:applied:" + orgHashTag(tc.idCtx.OrgID) + ":event_123"
			assertSameClusterSlot(t, "spend keys plus idempotency marker", append(sp, idempotencyKey))
		})
	}
}
