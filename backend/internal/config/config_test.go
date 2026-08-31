package config

import (
	"strings"
	"testing"
	"time"
)

func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NETRA_DATABASE_URL", "postgres://u:p@localhost:5432/netra?sslmode=disable")
}

func TestLoadDefaults(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Env != EnvDevelopment {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvDevelopment)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("HTTP.Addr = %q, want :8080", cfg.HTTP.Addr)
	}
	if cfg.HTTP.ReadTimeout != 15*time.Second {
		t.Errorf("HTTP.ReadTimeout = %s, want 15s", cfg.HTTP.ReadTimeout)
	}
	want := RiskThresholds{Low: 30, Medium: 50, Elevated: 70, High: 85}
	if cfg.Risk != want {
		t.Errorf("Risk = %+v, want %+v", cfg.Risk, want)
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("NETRA_DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() succeeded without NETRA_DATABASE_URL, want error")
	} else if !strings.Contains(err.Error(), "NETRA_DATABASE_URL") {
		t.Errorf("error = %v, want it to name NETRA_DATABASE_URL", err)
	}
}

func TestLoadReportsAllErrorsAtOnce(t *testing.T) {
	t.Setenv("NETRA_DATABASE_URL", "")
	t.Setenv("NETRA_LOG_LEVEL", "verbose")
	t.Setenv("NETRA_HTTP_READ_TIMEOUT", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() succeeded with invalid configuration, want error")
	}
	for _, want := range []string{"NETRA_DATABASE_URL", "NETRA_LOG_LEVEL", "NETRA_HTTP_READ_TIMEOUT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not mention %s; all problems should be reported together", err, want)
		}
	}
}

func TestLoadRejectsMinConnsAboveMaxConns(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("NETRA_DB_MIN_CONNS", "20")
	t.Setenv("NETRA_DB_MAX_CONNS", "5")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted min_conns > max_conns, want error")
	}
}

func TestLoadParsesCORSOrigins(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("NETRA_CORS_ALLOWED_ORIGINS", "http://a.test , http://b.test,")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	got := cfg.HTTP.AllowedOrigins
	if len(got) != 2 || got[0] != "http://a.test" || got[1] != "http://b.test" {
		t.Errorf("AllowedOrigins = %#v, want [http://a.test http://b.test]", got)
	}
}

func TestRiskThresholdsValidate(t *testing.T) {
	tests := []struct {
		name    string
		in      RiskThresholds
		wantErr bool
	}{
		{"spec defaults", RiskThresholds{30, 50, 70, 85}, false},
		{"tuned but ordered", RiskThresholds{25, 45, 65, 90}, false},
		{"not increasing", RiskThresholds{50, 30, 70, 85}, true},
		{"equal bands", RiskThresholds{30, 30, 70, 85}, true},
		{"high at ceiling", RiskThresholds{30, 50, 70, 100}, true},
		{"zero low", RiskThresholds{0, 50, 70, 85}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsDevelopment(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("NETRA_ENV", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.IsDevelopment() {
		t.Error("IsDevelopment() = true for production; development-only affordances would be enabled")
	}
}
