// Package finops implements high-precision micro-dollar financial accounting and asynchronous
// spend tracking for the GoRoute AI Gateway.
//
// Key Principles:
//   - Zero Floating-Point Drift: Financial balances and token costs are stored as 64-bit integer
//     micro-dollars (1 USD = 1,000,000 micro-USD = 1,000,000,000,000 pico-USD). All calculations
//     perform integer arithmetic with half-up pico-dollar rounding, completely eliminating IEEE-754 drift.
//   - Asynchronous Batch Flushing: High-frequency inference spend records are buffered in memory
//     channels and flushed in batches to PostgreSQL via multi-row INSERTs by dedicated worker routines.
//   - Real-Time Budget Enforcement: Checks organization and virtual key spend against configured
//     hard budget caps prior to request dispatch, rejecting over-budget requests with HTTP 429.
package finops
