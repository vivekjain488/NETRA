// Package config loads NETRA backend configuration from the environment.
//
// Every value is externalised (spec §39): there are no hard-coded addresses,
// credentials, or risk thresholds anywhere in the codebase. Loading fails
// loudly on invalid input rather than silently falling back to a default that
// would weaken a security control.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netra/backend/internal/posture"
	"github.com/netra/backend/internal/risk"
)

// Environment names the deployment environment. Some development-only
// affordances are refused unless this is EnvDevelopment.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// Config is the fully resolved backend configuration.
type Config struct {
	Env      Environment
	Log      LogConfig
	HTTP     HTTPConfig
	Database DatabaseConfig
	OIDC     OIDCConfig
	Risk     RiskConfig
	Posture  PostureConfig
}

// PostureConfig controls device trust scoring.
type PostureConfig struct {
	// Weights are the maximum points each control contributes. They must sum
	// to 100 so the score stays interpretable as a percentage (spec §11).
	Weights posture.Weights
	// ExpectedAgentVersion is the agent build the fleet should be running.
	// A device reporting an older build scores partial agent health.
	ExpectedAgentVersion string
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string // debug | info | warn | error
	Format string // json | text
}

// HTTPConfig controls the API server.
type HTTPConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	AllowedOrigins  []string
}

// DatabaseConfig controls the PostgreSQL connection pool.
type DatabaseConfig struct {
	URL         string
	MaxConns    int32
	MinConns    int32
	AutoMigrate bool
}

// OIDCConfig describes the identity provider.
type OIDCConfig struct {
	Issuer   string
	ClientID string
	Audience string

	// DevAuthEnabled turns on locally minted development tokens. It is
	// refused outside a development environment at load time, so it cannot be
	// switched on in production by configuration alone.
	DevAuthEnabled bool
	DevAuthTTL     time.Duration
}

// RiskConfig controls the risk engine.
type RiskConfig struct {
	RiskThresholds
	// Weights scale each dimension. Configuration, so a deployment can weigh
	// device trust differently from behaviour without a code change.
	Weights risk.Weights
}

// Thresholds returns the bands in the form the risk engine expects.
func (r RiskConfig) Thresholds() risk.Thresholds {
	return risk.Thresholds{Low: r.Low, Medium: r.Medium, Elevated: r.Elevated, High: r.High}
}

// RiskThresholds are the upper bounds (inclusive) of each risk band.
// Spec §19 requires these to be configurable rather than scattered constants.
type RiskThresholds struct {
	Low      int // 0..Low            => LOW
	Medium   int // Low+1..Medium     => MEDIUM
	Elevated int // Medium+1..Elevated=> ELEVATED
	High     int // Elevated+1..High  => HIGH, above => CRITICAL
}

// Validate reports whether the bands are strictly increasing and in range.
func (r RiskThresholds) Validate() error {
	if r.Low <= 0 || r.Low >= r.Medium || r.Medium >= r.Elevated ||
		r.Elevated >= r.High || r.High >= 100 {
		return fmt.Errorf(
			"risk thresholds must be strictly increasing within 0<low<medium<elevated<high<100, got %d/%d/%d/%d",
			r.Low, r.Medium, r.Elevated, r.High)
	}
	return nil
}

// Load reads configuration from the process environment.
func Load() (*Config, error) {
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	env := Environment(strings.ToLower(stringVar("NETRA_ENV", string(EnvDevelopment))))
	switch env {
	case EnvDevelopment, EnvStaging, EnvProduction:
	default:
		collect(fmt.Errorf("NETRA_ENV must be development, staging or production, got %q", env))
	}

	httpRead, err := durationVar("NETRA_HTTP_READ_TIMEOUT", 15*time.Second)
	collect(err)
	httpWrite, err := durationVar("NETRA_HTTP_WRITE_TIMEOUT", 30*time.Second)
	collect(err)
	httpShutdown, err := durationVar("NETRA_HTTP_SHUTDOWN_TIMEOUT", 15*time.Second)
	collect(err)

	maxConns, err := intVar("NETRA_DB_MAX_CONNS", 10)
	collect(err)
	minConns, err := intVar("NETRA_DB_MIN_CONNS", 1)
	collect(err)
	autoMigrate, err := boolVar("NETRA_DB_AUTO_MIGRATE", true)
	collect(err)

	dbURL := stringVar("NETRA_DATABASE_URL", "")
	if dbURL == "" {
		collect(errors.New("NETRA_DATABASE_URL is required"))
	}

	low, err := intVar("NETRA_RISK_THRESHOLD_LOW", 30)
	collect(err)
	medium, err := intVar("NETRA_RISK_THRESHOLD_MEDIUM", 50)
	collect(err)
	elevated, err := intVar("NETRA_RISK_THRESHOLD_ELEVATED", 70)
	collect(err)
	high, err := intVar("NETRA_RISK_THRESHOLD_HIGH", 85)
	collect(err)

	devAuth, err := boolVar("NETRA_DEV_AUTH_ENABLED", false)
	collect(err)
	devAuthTTL, err := durationVar("NETRA_DEV_AUTH_TTL", time.Hour)
	collect(err)

	issuer := stringVar("NETRA_OIDC_ISSUER", "")
	audience := stringVar("NETRA_OIDC_AUDIENCE", "")

	if devAuth && env != EnvDevelopment {
		collect(fmt.Errorf(
			"NETRA_DEV_AUTH_ENABLED is only permitted when NETRA_ENV=development, not %q", env))
	}
	if !devAuth && (issuer == "" || audience == "") {
		// Without a verifier there is no authentication at all, so refusing to
		// start is safer than serving an unauthenticated control plane.
		collect(errors.New(
			"NETRA_OIDC_ISSUER and NETRA_OIDC_AUDIENCE are required unless NETRA_DEV_AUTH_ENABLED is set"))
	}

	riskWeights := risk.DefaultWeights()
	for _, binding := range []struct {
		key    string
		target *float64
	}{
		{"NETRA_RISK_WEIGHT_IDENTITY", &riskWeights.Identity},
		{"NETRA_RISK_WEIGHT_DEVICE", &riskWeights.Device},
		{"NETRA_RISK_WEIGHT_BEHAVIOUR", &riskWeights.Behaviour},
		{"NETRA_RISK_WEIGHT_NETWORK", &riskWeights.Network},
		{"NETRA_RISK_WEIGHT_RESOURCE", &riskWeights.Resource},
		{"NETRA_RISK_WEIGHT_HISTORY", &riskWeights.History},
	} {
		value, err := floatVar(binding.key, *binding.target)
		collect(err)
		*binding.target = value
	}
	collect(riskWeights.Validate())

	weights := posture.DefaultWeights()
	for _, binding := range []struct {
		key    string
		target *int
	}{
		{"NETRA_POSTURE_WEIGHT_DEVICE_IDENTITY", &weights.DeviceIdentity},
		{"NETRA_POSTURE_WEIGHT_AGENT_HEALTH", &weights.AgentHealth},
		{"NETRA_POSTURE_WEIGHT_DISK_ENCRYPTION", &weights.DiskEncryption},
		{"NETRA_POSTURE_WEIGHT_SECURE_BOOT", &weights.SecureBoot},
		{"NETRA_POSTURE_WEIGHT_OS_SUPPORTED", &weights.OSSupported},
		{"NETRA_POSTURE_WEIGHT_FIREWALL", &weights.Firewall},
		{"NETRA_POSTURE_WEIGHT_SCREEN_LOCK", &weights.ScreenLock},
		{"NETRA_POSTURE_WEIGHT_ANTI_MALWARE", &weights.AntiMalware},
	} {
		value, err := intVar(binding.key, *binding.target)
		collect(err)
		*binding.target = value
	}
	collect(weights.Validate())

	logLevel := strings.ToLower(stringVar("NETRA_LOG_LEVEL", "info"))
	switch logLevel {
	case "debug", "info", "warn", "error":
	default:
		collect(fmt.Errorf("NETRA_LOG_LEVEL must be debug, info, warn or error, got %q", logLevel))
	}

	logFormat := strings.ToLower(stringVar("NETRA_LOG_FORMAT", "json"))
	if logFormat != "json" && logFormat != "text" {
		collect(fmt.Errorf("NETRA_LOG_FORMAT must be json or text, got %q", logFormat))
	}

	if minConns > maxConns {
		collect(fmt.Errorf("NETRA_DB_MIN_CONNS (%d) must not exceed NETRA_DB_MAX_CONNS (%d)", minConns, maxConns))
	}

	cfg := &Config{
		Env: env,
		Log: LogConfig{Level: logLevel, Format: logFormat},
		HTTP: HTTPConfig{
			Addr:            stringVar("NETRA_HTTP_ADDR", ":8080"),
			ReadTimeout:     httpRead,
			WriteTimeout:    httpWrite,
			ShutdownTimeout: httpShutdown,
			AllowedOrigins:  listVar("NETRA_CORS_ALLOWED_ORIGINS"),
		},
		Database: DatabaseConfig{
			URL:         dbURL,
			MaxConns:    int32(maxConns),
			MinConns:    int32(minConns),
			AutoMigrate: autoMigrate,
		},
		OIDC: OIDCConfig{
			Issuer:         issuer,
			ClientID:       stringVar("NETRA_OIDC_CLIENT_ID", ""),
			Audience:       audience,
			DevAuthEnabled: devAuth,
			DevAuthTTL:     devAuthTTL,
		},
		Risk: RiskConfig{
			RiskThresholds: RiskThresholds{Low: low, Medium: medium, Elevated: elevated, High: high},
			Weights:        riskWeights,
		},
		Posture: PostureConfig{
			Weights:              weights,
			ExpectedAgentVersion: stringVar("NETRA_EXPECTED_AGENT_VERSION", ""),
		},
	}
	collect(cfg.Risk.Validate())

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return cfg, nil
}

// IsDevelopment reports whether development-only affordances are permitted.
func (c *Config) IsDevelopment() bool { return c.Env == EnvDevelopment }

func stringVar(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func listVar(key string) []string {
	raw := stringVar(key, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func intVar(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return v, nil
}

func boolVar(key string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return v, nil
}

func floatVar(key string, fallback float64) (float64, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number: %w", key, err)
	}
	return v, nil
}

func durationVar(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration such as 30s: %w", key, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", key, v)
	}
	return v, nil
}
