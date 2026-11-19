// Package ratelimit enforces multi-dimensional RPM, TPM, RPD, TPD, concurrent
// slot leases, and rolling 24-hour/windowed micro-dollar budgets using atomic
// Redis Lua scripts with fail-closed PostgreSQL cold-recovery fallbacks.
package ratelimit
