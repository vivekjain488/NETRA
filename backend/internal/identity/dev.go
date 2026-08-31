package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DevIssuer is the issuer value stamped on locally minted development tokens.
// It is not a URL, so it can never collide with a real OIDC issuer.
const DevIssuer = "netra-dev-local"

// ErrDevAuthNotPermitted is returned when development authentication is
// requested outside a development environment.
var ErrDevAuthNotPermitted = errors.New(
	"development authentication is only permitted when NETRA_ENV=development")

// DevVerifier mints and validates tokens signed by an ephemeral local key.
//
// Its purpose is twofold: it keeps integration tests free of a live identity
// provider, and it keeps a demonstration alive if Keycloak fails to start.
//
// It is NOT a password system and NOT a fallback authenticator for real
// deployments. Three properties keep it contained:
//
//   - construction fails unless the environment is development;
//   - the signing key is random per process and never written to disk, so
//     tokens do not survive a restart and cannot be minted out of band;
//   - it accepts only its own issuer, so it can never validate a token that
//     claims to come from the real identity provider.
type DevVerifier struct {
	secret []byte
	ttl    time.Duration
}

// NewDevVerifier builds a development verifier, refusing any other environment.
func NewDevVerifier(environment string, ttl time.Duration) (*DevVerifier, error) {
	if environment != "development" {
		return nil, fmt.Errorf("%w (environment is %q)", ErrDevAuthNotPermitted, environment)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate development signing key: %w", err)
	}
	return &DevVerifier{secret: secret, ttl: ttl}, nil
}

// Issuer returns the local development issuer.
func (d *DevVerifier) Issuer() string { return DevIssuer }

// Mint issues a short-lived development token for the given identity.
func (d *DevVerifier) Mint(subject, email, displayName, department string, roles []Role) (string, error) {
	if subject == "" {
		return "", fmt.Errorf("subject is required")
	}

	roleNames := make([]string, 0, len(roles))
	for _, r := range ParseRoles(toStrings(roles)) {
		roleNames = append(roleNames, string(r))
	}

	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":        DevIssuer,
		"sub":        subject,
		"email":      email,
		"name":       displayName,
		"department": department,
		"roles":      roleNames,
		"iat":        now.Unix(),
		"exp":        now.Add(d.ttl).Unix(),
	})
	return token.SignedString(d.secret)
}

// Verify validates a development token against the ephemeral key.
func (d *DevVerifier) Verify(_ context.Context, rawToken string) (*Claims, error) {
	parsed, err := jwt.Parse(rawToken, func(t *jwt.Token) (any, error) {
		// Pinning the algorithm rejects the "alg: none" and HMAC-for-RSA
		// confusion attacks outright.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return d.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(DevIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	claims := &Claims{
		Subject:     stringClaim(mapClaims, "sub"),
		Email:       stringClaim(mapClaims, "email"),
		DisplayName: stringClaim(mapClaims, "name"),
		Department:  stringClaim(mapClaims, "department"),
		Roles:       ParseRoles(stringSliceClaim(mapClaims, "roles")),
		IssuedAt:    unixOrZero(int64Claim(mapClaims, "iat")),
		ExpiresAt:   unixOrZero(int64Claim(mapClaims, "exp")),
	}
	if claims.DisplayName == "" {
		claims.DisplayName = claims.Subject
	}
	if err := claims.Validate(); err != nil {
		return nil, err
	}
	return claims, nil
}

func toStrings(roles []Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, string(r))
	}
	return out
}

func stringClaim(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return v
}

func int64Claim(claims jwt.MapClaims, key string) int64 {
	switch v := claims[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	default:
		return 0
	}
}

func stringSliceClaim(claims jwt.MapClaims, key string) []string {
	raw, ok := claims[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
