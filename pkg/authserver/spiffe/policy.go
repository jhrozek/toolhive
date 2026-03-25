// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"strings"
	"sync/atomic"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ClientPolicy controls which SPIFFE IDs are allowed to register as OAuth clients.
type ClientPolicy struct {
	// AllowedIdentities is the list of namespace/service-account patterns allowed.
	// An empty list denies all registrations.
	AllowedIdentities []AllowedIdentity

	// MaxRegistrations caps the total number of auto-registered clients (0 = unlimited).
	MaxRegistrations int

	// registrationCount tracks the number of auto-registered clients.
	// This is used to enforce MaxRegistrations.
	registrationCount atomic.Int64
}

// AllowedIdentity matches SPIFFE IDs by namespace and service account.
// The SPIFFE ID path is expected to follow the Kubernetes convention:
// /ns/<namespace>/sa/<service-account>
type AllowedIdentity struct {
	Namespace      string // exact match or "*" for any namespace
	ServiceAccount string // exact match or "*" for any service account
}

// IsAllowed checks whether a SPIFFE ID is permitted to register.
// It parses the SPIFFE ID path (/ns/<ns>/sa/<sa>) and matches against
// the allowed identities list. Returns false if the path doesn't follow
// the Kubernetes SPIFFE ID convention or no pattern matches.
func (p *ClientPolicy) IsAllowed(id spiffeid.ID) bool {
	ns, sa, ok := parseKubernetesPath(id.Path())
	if !ok {
		return false
	}

	for _, allowed := range p.AllowedIdentities {
		if matchIdentity(allowed, ns, sa) {
			return true
		}
	}
	return false
}

// IncrementRegistrations atomically increments the registration count and
// returns true if the registration is within the MaxRegistrations limit.
// When MaxRegistrations is 0, no limit is enforced and this always returns true.
func (p *ClientPolicy) IncrementRegistrations() bool {
	if p.MaxRegistrations <= 0 {
		p.registrationCount.Add(1)
		return true
	}
	// Optimistic increment: add first, then check.
	// If over the limit, decrement and reject.
	newCount := p.registrationCount.Add(1)
	if newCount > int64(p.MaxRegistrations) {
		p.registrationCount.Add(-1)
		return false
	}
	return true
}

// DecrementRegistrations rolls back a previously incremented registration count.
// Call this when a registration slot was consumed but the registration did not
// actually succeed (e.g., TOCTOU race where another request registered first).
func (p *ClientPolicy) DecrementRegistrations() {
	p.registrationCount.Add(-1)
}

// RegistrationCount returns the current number of auto-registered clients.
func (p *ClientPolicy) RegistrationCount() int64 {
	return p.registrationCount.Load()
}

// parseKubernetesPath extracts namespace and service account from a SPIFFE ID path
// following the Kubernetes convention: /ns/<namespace>/sa/<service-account>.
// Returns the namespace, service account, and true if parsing succeeded.
func parseKubernetesPath(path string) (namespace, serviceAccount string, ok bool) {
	// Path starts with "/" so Split produces ["", "ns", "<ns>", "sa", "<sa>"]
	parts := strings.Split(path, "/")
	if len(parts) != 5 {
		return "", "", false
	}
	if parts[0] != "" || parts[1] != "ns" || parts[3] != "sa" {
		return "", "", false
	}
	ns := parts[2]
	sa := parts[4]
	if ns == "" || sa == "" {
		return "", "", false
	}
	return ns, sa, true
}

// matchIdentity checks whether a namespace/service-account pair matches
// an AllowedIdentity pattern. The wildcard "*" matches any value.
func matchIdentity(allowed AllowedIdentity, namespace, serviceAccount string) bool {
	nsMatch := allowed.Namespace == "*" || allowed.Namespace == namespace
	saMatch := allowed.ServiceAccount == "*" || allowed.ServiceAccount == serviceAccount
	return nsMatch && saMatch
}
