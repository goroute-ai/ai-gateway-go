package upstream

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrIssuerMissing   = errors.New("rfc9207: missing 'iss' parameter in authorization/token response")
	ErrIssuerMismatch  = errors.New("rfc9207: issuer mismatch between authorization server and response")
	ErrInvalidResource = errors.New("rfc8707: invalid resource URI")
)

// ValidateRFC9207Issuer strictly validates the received issuer parameter against the expected
// issuer identifier using byte-for-byte exact equality (RFC 9207 Section 2.3).
//
// No case folding, percent-decoding, trailing slash manipulation, or path normalization is permitted.
func ValidateRFC9207Issuer(expectedIssuer, actualIssuer string) error {
	if actualIssuer == "" {
		return ErrIssuerMissing
	}
	if expectedIssuer != actualIssuer {
		return fmt.Errorf("%w: expected %q, got %q", ErrIssuerMismatch, expectedIssuer, actualIssuer)
	}
	return nil
}

// ValidateRFC8707ResourceURI verifies that a resource indicator conforms to RFC 8707 Section 2:
// - Must be an absolute URI (contains scheme)
// - Must not include a URI fragment component ('#')
func ValidateRFC8707ResourceURI(uriStr string) error {
	uriStr = strings.TrimSpace(uriStr)
	if uriStr == "" {
		return fmt.Errorf("%w: resource URI cannot be empty", ErrInvalidResource)
	}

	u, err := url.Parse(uriStr)
	if err != nil {
		return fmt.Errorf("%w: failed to parse URI: %v", ErrInvalidResource, err)
	}

	if !u.IsAbs() {
		return fmt.Errorf("%w: resource URI %q must be an absolute URI with scheme", ErrInvalidResource, uriStr)
	}

	if u.Fragment != "" || strings.Contains(uriStr, "#") {
		return fmt.Errorf("%w: resource URI %q must not contain a fragment identifier", ErrInvalidResource, uriStr)
	}

	return nil
}

// ApplyRFC8707Resources validates and injects RFC 8707 'resource' parameters into query/form values.
func ApplyRFC8707Resources(values url.Values, resourceURIs []string) error {
	for _, res := range resourceURIs {
		res = strings.TrimSpace(res)
		if res == "" {
			continue
		}
		if err := ValidateRFC8707ResourceURI(res); err != nil {
			return err
		}
		values.Add("resource", res)
	}
	return nil
}
