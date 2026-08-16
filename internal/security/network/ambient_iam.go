package network

import (
	"net"
	"net/http"
	"time"
)

// NewAmbientIAMPolicy constructs a dedicated outbound network policy that permits
// cloud metadata endpoints (IMDSv2, ECS task metadata, Azure MSI/IMDS, GCP metadata)
// ONLY when allowAmbientCloudIAM is explicitly true.
//
// When allowAmbientCloudIAM is false, it returns ErrCloudMetadataBlocked so callers
// cannot accidentally bypass SSRF metadata protections.
func NewAmbientIAMPolicy(basePolicy *Policy, allowAmbientCloudIAM bool) (*Policy, error) {
	if !allowAmbientCloudIAM {
		return nil, ErrCloudMetadataBlocked
	}

	p := &Policy{
		AllowInsecureHTTP: true, // IMDS / Azure MSI / GCP metadata use local HTTP
		AllowedSchemes: map[string]bool{
			"https": true,
			"http":  true,
		},
		DialTimeout:        2 * time.Second,
		MaxRedirects:       0, // Metadata endpoints must never redirect
		allowCloudMetadata: true,
	}

	if basePolicy != nil {
		p.AllowPrivateNetworks = basePolicy.AllowPrivateNetworks
		if len(basePolicy.AllowedPrivateCIDRs) > 0 {
			p.AllowedPrivateCIDRs = append([]*net.IPNet(nil), basePolicy.AllowedPrivateCIDRs...)
		}
		if basePolicy.DialTimeout > 0 && basePolicy.DialTimeout < p.DialTimeout {
			p.DialTimeout = basePolicy.DialTimeout
		}
	}

	return p, nil
}

// NewAmbientIAMHTTPClient returns an SSRF-bounded HTTP client for ambient cloud IAM
// metadata/identity endpoints when allowAmbientCloudIAM is explicitly true.
// When allowAmbientCloudIAM is false, it returns ErrCloudMetadataBlocked.
func NewAmbientIAMHTTPClient(basePolicy *Policy, allowAmbientCloudIAM bool) (*http.Client, error) {
	p, err := NewAmbientIAMPolicy(basePolicy, allowAmbientCloudIAM)
	if err != nil {
		return nil, err
	}
	return NewHTTPClientWithOptions(p, HTTPClientOptions{
		RequestTimeout:        5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		StreamIdleTimeout:     5 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
	}, nil), nil
}
