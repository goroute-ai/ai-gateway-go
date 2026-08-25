package network

import (
	"context"
	"errors"
	"fmt"
	"net"
)

var (
	ErrNoValidIPFound = errors.New("network: no permitted IP addresses found for host")
)

// SafeResolver wraps net.Resolver with outbound SSRF security policy enforcement.
type SafeResolver struct {
	Policy   *Policy
	Resolver *net.Resolver
}

// NewSafeResolver creates a new SafeResolver backed by the given security policy.
func NewSafeResolver(policy *Policy) *SafeResolver {
	return &SafeResolver{
		Policy:   policy,
		Resolver: net.DefaultResolver,
	}
}

// LookupAndValidate resolves a hostname and returns only permitted IP addresses.
func (r *SafeResolver) LookupAndValidate(ctx context.Context, host string) ([]net.IP, error) {
	// If host is already an IP literal
	if ip := net.ParseIP(host); ip != nil {
		if err := r.Policy.ValidateIP(ip); err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}

	addrs, err := r.Resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("network: resolve host %q: %w", host, err)
	}

	var validIPs []net.IP
	var lastErr error
	for _, ip := range addrs {
		if err := r.Policy.ValidateIP(ip); err != nil {
			lastErr = err
			continue
		}
		validIPs = append(validIPs, ip)
	}

	if len(validIPs) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("%w for %s: %v", ErrNoValidIPFound, host, lastErr)
		}
		return nil, fmt.Errorf("%w for %s", ErrNoValidIPFound, host)
	}

	return validIPs, nil
}
