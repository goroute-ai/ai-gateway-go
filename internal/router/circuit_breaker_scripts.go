package router

import (
	_ "embed"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed scripts/allow_circuit_probe.lua
var allowCircuitProbeLua string

//go:embed scripts/trip_circuit.lua
var tripCircuitLua string

//go:embed scripts/close_circuit.lua
var closeCircuitLua string

//go:embed scripts/reopen_half_open.lua
var reopenHalfOpenLua string

//go:embed scripts/record_circuit_failure.lua
var recordCircuitFailureLua string

var (
	allowCircuitProbeScript    = redis.NewScript(allowCircuitProbeLua)
	tripCircuitScript          = redis.NewScript(tripCircuitLua)
	closeCircuitScript         = redis.NewScript(closeCircuitLua)
	reopenHalfOpenScript       = redis.NewScript(reopenHalfOpenLua)
	recordCircuitFailureScript = redis.NewScript(recordCircuitFailureLua)
)

const circuitProbeLeaseTTL = 5 * time.Minute
