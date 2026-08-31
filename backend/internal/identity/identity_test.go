package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseRolesKeepsOnlyKnownRoles(t *testing.T) {
	// An identity provider compromise must not be able to invent authority
	// inside NETRA by asserting a role name NETRA does not define.
	got := ParseRoles([]string{"ADMIN", "SUPER_ADMIN", "root", "AUDITOR"})

	want := map[Role]bool{RoleUser: true, RoleAdmin: true, RoleAuditor: true}
	if len(got) != len(want) {
		t.Fatalf("roles = %v, want exactly %v", got, want)
	}
	for _, role := range got {
		if !want[role] {
			t.Errorf("unexpected role %q accepted", role)
		}
	}
}

func TestParseRolesAlwaysIncludesUser(t *testing.T) {
	if roles := ParseRoles(nil); len(roles) != 1 || roles[0] != RoleUser {
		t.Errorf("roles = %v, want [USER] for a token with no role claim", roles)
	}
}

func TestParseRolesDeduplicates(t *testing.T) {
	got := ParseRoles([]string{"ADMIN", "admin", " ADMIN "})

	if len(got) != 2 {
		t.Errorf("roles = %v, want [USER ADMIN] with duplicates collapsed", got)
	}
}

func TestHighestRole(t *testing.T) {
	tests := []struct {
		name  string
		roles []Role
		want  Role
	}{
		{"admin wins", []Role{RoleUser, RoleAuditor, RoleAdmin}, RoleAdmin},
		{"analyst over auditor", []Role{RoleUser, RoleAuditor, RoleAnalyst}, RoleAnalyst},
		{"user only", []Role{RoleUser}, RoleUser},
		{"empty", nil, RoleUser},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{Roles: tt.roles}
			if got := claims.HighestRole(); got != tt.want {
				t.Errorf("HighestRole() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClaimsValidateRejectsMissingSubject(t *testing.T) {
	claims := &Claims{Roles: []Role{RoleUser}}

	if err := claims.Validate(); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Validate() error = %v, want ErrInvalidToken", err)
	}
}

// ── Development verifier ────────────────────────────────────────────────────

func TestDevVerifierRefusedOutsideDevelopment(t *testing.T) {
	// This is the control that keeps a test affordance out of production.
	for _, env := range []string{"production", "staging", "", "Development"} {
		t.Run(env, func(t *testing.T) {
			if _, err := NewDevVerifier(env, time.Hour); !errors.Is(err, ErrDevAuthNotPermitted) {
				t.Errorf("NewDevVerifier(%q) error = %v, want ErrDevAuthNotPermitted", env, err)
			}
		})
	}
}

func TestDevVerifierRoundTrip(t *testing.T) {
	v, err := NewDevVerifier("development", time.Hour)
	if err != nil {
		t.Fatalf("NewDevVerifier: %v", err)
	}

	token, err := v.Mint("alice", "alice@example.gov", "Alice Sharma", "Operations",
		[]Role{RoleAnalyst})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" || claims.Email != "alice@example.gov" {
		t.Errorf("claims = %+v, want subject alice", claims)
	}
	if !claims.HasRole(RoleAnalyst) || !claims.HasRole(RoleUser) {
		t.Errorf("roles = %v, want SECURITY_ANALYST and USER", claims.Roles)
	}
	if claims.HasRole(RoleAdmin) {
		t.Error("ADMIN was granted but never requested")
	}
}

func TestDevVerifierRejectsForeignKey(t *testing.T) {
	// Each verifier holds a random per-process key, so a token minted by one
	// process is worthless to another.
	minter, _ := NewDevVerifier("development", time.Hour)
	other, _ := NewDevVerifier("development", time.Hour)

	token, err := minter.Mint("alice", "a@example.gov", "Alice", "", []Role{RoleUser})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if _, err := other.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify accepted a token signed with a different key: %v", err)
	}
}

func TestDevVerifierRejectsAlgNone(t *testing.T) {
	v, _ := NewDevVerifier("development", time.Hour)

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": DevIssuer,
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build unsigned token: %v", err)
	}

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrInvalidToken) {
		t.Error("an alg:none token was accepted")
	}
}

func TestDevVerifierRejectsExpiredToken(t *testing.T) {
	v, err := NewDevVerifier("development", -time.Minute)
	if err != nil {
		t.Fatalf("NewDevVerifier: %v", err)
	}
	// A negative TTL is clamped to one hour, so mint an expired token directly.
	expired := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":   DevIssuer,
		"sub":   "alice",
		"roles": []string{"USER"},
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"exp":   time.Now().Add(-time.Hour).Unix(),
	})
	raw, err := expired.SignedString(v.secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrInvalidToken) {
		t.Error("an expired token was accepted")
	}
}

func TestDevVerifierRejectsForeignIssuer(t *testing.T) {
	// The development verifier must never validate something claiming to come
	// from the real identity provider.
	v, _ := NewDevVerifier("development", time.Hour)

	foreign := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":   "https://keycloak.internal/realms/netra",
		"sub":   "alice",
		"roles": []string{"ADMIN"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	raw, err := foreign.SignedString(v.secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrInvalidToken) {
		t.Error("a token claiming a foreign issuer was accepted")
	}
}

// ── OIDC verifier construction ──────────────────────────────────────────────

func TestNewOIDCVerifierRequiresAudience(t *testing.T) {
	// Without audience validation, a token minted for any other client of the
	// same realm would be accepted by NETRA.
	if _, err := NewOIDCVerifier("https://idp.test/realms/netra", ""); err == nil {
		t.Error("verifier constructed without an audience")
	}
	if _, err := NewOIDCVerifier("", "netra-backend"); err == nil {
		t.Error("verifier constructed without an issuer")
	}
}

func TestOIDCVerifierReportsUnreachableProvider(t *testing.T) {
	v, err := NewOIDCVerifier("http://127.0.0.1:1/realms/netra", "netra-backend")
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = v.Verify(ctx, "irrelevant")
	if err == nil {
		t.Fatal("Verify succeeded against an unreachable provider")
	}
	// Discovery failure is an availability problem and must be distinguishable
	// from a bad token, so operators can tell the two apart.
	if errors.Is(err, ErrInvalidToken) {
		t.Error("provider unreachable was reported as an invalid token")
	}
	if !strings.Contains(err.Error(), "discover") {
		t.Errorf("error = %v, want it to mention discovery", err)
	}
}

func TestOIDCPayloadMergesRoleClaims(t *testing.T) {
	payload := &oidcPayload{Subject: "alice", Roles: []string{"AUDITOR"}}
	payload.RealmAccess.Roles = []string{"SECURITY_ANALYST"}

	claims := payload.toClaims()

	if !claims.HasRole(RoleAuditor) || !claims.HasRole(RoleAnalyst) {
		t.Errorf("roles = %v, want both the plain and realm_access claims honoured", claims.Roles)
	}
}

func TestOIDCPayloadFallsBackForDisplayName(t *testing.T) {
	payload := &oidcPayload{Subject: "abc-123", PreferredUsername: "alice"}

	if got := payload.toClaims().DisplayName; got != "alice" {
		t.Errorf("DisplayName = %q, want the preferred_username fallback", got)
	}
}
