// Package identity verifies user identity assertions.
//
// NETRA never stores passwords and never authenticates users itself (spec §6).
// It consumes tokens issued by an organisational identity provider and its job
// is to decide whether a token is genuine, current, and intended for NETRA.
package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role is a NETRA authorization role (spec §39).
type Role string

const (
	RoleUser    Role = "USER"
	RoleAnalyst Role = "SECURITY_ANALYST"
	RoleAdmin   Role = "ADMIN"
	RoleAuditor Role = "AUDITOR"
)

// knownRoles is the allowlist. A role claim NETRA does not recognise is
// discarded rather than carried forward: an identity provider compromise
// should not be able to invent new authority inside NETRA.
var knownRoles = map[string]Role{
	string(RoleUser):    RoleUser,
	string(RoleAnalyst): RoleAnalyst,
	string(RoleAdmin):   RoleAdmin,
	string(RoleAuditor): RoleAuditor,
}

// ParseRole maps a claim value onto a known role.
func ParseRole(raw string) (Role, bool) {
	r, ok := knownRoles[strings.ToUpper(strings.TrimSpace(raw))]
	return r, ok
}

// ParseRoles maps claim values onto known roles, discarding the rest.
// Every authenticated principal holds RoleUser at minimum.
func ParseRoles(raw []string) []Role {
	seen := map[Role]bool{RoleUser: true}
	out := []Role{RoleUser}

	for _, value := range raw {
		role, ok := ParseRole(value)
		if !ok || seen[role] {
			continue
		}
		seen[role] = true
		out = append(out, role)
	}
	return out
}

// Claims is the subset of an identity token that NETRA acts on.
type Claims struct {
	Subject     string
	Email       string
	DisplayName string
	Department  string
	Roles       []Role
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// ErrInvalidToken is returned for any token that cannot be trusted. The reason
// is deliberately not exposed to the caller: distinguishing "expired" from
// "bad signature" from "wrong audience" gives an attacker a probing oracle.
var ErrInvalidToken = errors.New("invalid identity token")

// Validate checks the claims NETRA depends on beyond signature verification.
func (c *Claims) Validate() error {
	if strings.TrimSpace(c.Subject) == "" {
		return fmt.Errorf("%w: token has no subject", ErrInvalidToken)
	}
	if len(c.Roles) == 0 {
		return fmt.Errorf("%w: token carries no usable role", ErrInvalidToken)
	}
	return nil
}

// HighestRole returns the most privileged role held, used for the persisted
// display role. Authorization decisions always consult the full role set.
func (c *Claims) HighestRole() Role {
	// Ordered most to least privileged.
	for _, candidate := range []Role{RoleAdmin, RoleAnalyst, RoleAuditor, RoleUser} {
		for _, held := range c.Roles {
			if held == candidate {
				return candidate
			}
		}
	}
	return RoleUser
}

// HasRole reports whether the principal holds the given role.
func (c *Claims) HasRole(role Role) bool {
	for _, held := range c.Roles {
		if held == role {
			return true
		}
	}
	return false
}
