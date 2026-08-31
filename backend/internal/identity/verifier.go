package identity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verifier validates a raw bearer token and returns the claims NETRA trusts.
type Verifier interface {
	// Verify returns ErrInvalidToken (wrapped) for anything untrustworthy.
	Verify(ctx context.Context, rawToken string) (*Claims, error)
	// Issuer identifies the authority this verifier trusts, for logging.
	Issuer() string
}

// oidcPayload is the claim set NETRA reads from an OIDC token.
type oidcPayload struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Department        string   `json:"department"`
	Roles             []string `json:"roles"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// OIDCVerifier validates tokens against an OpenID Connect provider.
//
// Provider metadata and signing keys are fetched lazily rather than at
// construction: the identity provider and the backend start together, and a
// control plane that refuses to boot because the IdP is thirty seconds behind
// is operationally worse than one that reports the dependency as unavailable.
type OIDCVerifier struct {
	issuer   string
	audience string

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewOIDCVerifier builds a verifier for the given issuer and audience.
func NewOIDCVerifier(issuer, audience string) (*OIDCVerifier, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("oidc issuer is required")
	}
	if strings.TrimSpace(audience) == "" {
		// Without audience validation a token minted for any other client of
		// the same realm would be accepted here.
		return nil, fmt.Errorf("oidc audience is required")
	}
	return &OIDCVerifier{issuer: issuer, audience: audience}, nil
}

// Issuer returns the trusted issuer URL.
func (v *OIDCVerifier) Issuer() string { return v.issuer }

// resolve fetches provider metadata once, retrying on later calls if the
// provider was not reachable the first time.
func (v *OIDCVerifier) resolve(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.verifier != nil {
		return v.verifier, nil
	}

	provider, err := oidc.NewProvider(ctx, v.issuer)
	if err != nil {
		return nil, fmt.Errorf("discover identity provider: %w", err)
	}
	v.verifier = provider.Verifier(&oidc.Config{ClientID: v.audience})
	return v.verifier, nil
}

// Verify validates the token's signature, issuer, audience and expiry.
func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	verifier, err := v.resolve(ctx)
	if err != nil {
		return nil, err
	}

	token, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		// The specific failure is not surfaced: telling a caller whether a
		// token was expired, wrongly signed or wrongly addressed turns this
		// endpoint into an oracle.
		return nil, ErrInvalidToken
	}

	var payload oidcPayload
	if err := token.Claims(&payload); err != nil {
		return nil, ErrInvalidToken
	}
	return payload.toClaims(), nil
}

func (p *oidcPayload) toClaims() *Claims {
	// Keycloak carries realm roles under realm_access; a plain `roles` claim is
	// also accepted so the backend is not tied to one identity provider.
	roles := append(append([]string{}, p.Roles...), p.RealmAccess.Roles...)

	displayName := p.Name
	if strings.TrimSpace(displayName) == "" {
		displayName = p.PreferredUsername
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = p.Subject
	}

	return &Claims{
		Subject:     p.Subject,
		Email:       p.Email,
		DisplayName: displayName,
		Department:  p.Department,
		Roles:       ParseRoles(roles),
		IssuedAt:    unixOrZero(p.IssuedAt),
		ExpiresAt:   unixOrZero(p.ExpiresAt),
	}
}

func unixOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
