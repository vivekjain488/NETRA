// Package posture turns endpoint security signals into an explainable device
// trust score.
//
// The division of labour matters: the agent reports what it observed, and the
// backend decides what that is worth. An endpoint that scored itself would be
// asserting its own trustworthiness, and a compromised endpoint would simply
// report 100 (spec §43).
//
// The score is a risk indicator, not a statement that a device is secure. It
// is built from signals that are cheap to collect and easy to explain, and
// anything the agent could not determine counts as unknown rather than as
// satisfied — unverifiable is not the same as safe.
package posture

import (
	"fmt"
	"strings"
	"time"
)

// Signals are the security facts an agent reports about its endpoint.
//
// Every field is a pointer so that "not reported" is distinguishable from
// "reported false". Collapsing those would let a collector that failed to run
// look identical to one that found a control disabled — or worse, the reverse.
type Signals struct {
	// DiskEncryption is FileVault on macOS, BitLocker on Windows.
	DiskEncryption *bool `json:"disk_encryption,omitempty"`
	// SecureBoot is Secure Boot on Windows, System Integrity Protection on macOS.
	SecureBoot *bool `json:"secure_boot,omitempty"`
	// Firewall is the host firewall.
	Firewall *bool `json:"firewall,omitempty"`
	// ScreenLock is whether a password is required after sleep or screensaver.
	ScreenLock *bool `json:"screen_lock,omitempty"`
	// AntiMalware is whether real-time protection is active.
	AntiMalware *bool `json:"anti_malware,omitempty"`

	// OSName and OSVersion as observed at collection time.
	OSName    string `json:"os_name,omitempty"`
	OSVersion string `json:"os_version,omitempty"`

	// CollectionErrors names signals the agent could not determine and why.
	// Reporting the failure is more useful than silently omitting the field.
	CollectionErrors map[string]string `json:"collection_errors,omitempty"`
}

// Validate rejects a posture report that is malformed or implausibly large.
func (s Signals) Validate() error {
	if len(s.OSName) > 64 || len(s.OSVersion) > 64 {
		return fmt.Errorf("os_name and os_version must be at most 64 characters")
	}
	if len(s.CollectionErrors) > 32 {
		return fmt.Errorf("collection_errors must contain at most 32 entries")
	}
	for key, value := range s.CollectionErrors {
		if len(key) > 64 || len(value) > 256 {
			return fmt.Errorf("collection_errors entries must be short")
		}
	}
	return nil
}

// DeviceContext is what the backend already knows about the device, without
// having to take the endpoint's word for it.
type DeviceContext struct {
	Active          bool
	KeyProtection   string
	AgentVersion    string
	ExpectedAgent   string
	LastHeartbeatAt *time.Time
	Now             time.Time
}

// Source records whether a factor rests on something the backend verified or
// on something the endpoint claimed.
type Source string

const (
	// SourceVerified is a fact the backend established itself.
	SourceVerified Source = "verified"
	// SourceReported is an endpoint claim. It is scored, but it is a claim.
	SourceReported Source = "reported"
)

// Factor is one contribution to the trust score.
type Factor struct {
	Code         string `json:"code"`
	Label        string `json:"label"`
	Contribution int    `json:"contribution"`
	Maximum      int    `json:"maximum"`
	Source       Source `json:"source"`
	Detail       string `json:"detail,omitempty"`
}

// Satisfied reports whether this control was fully awarded.
func (f Factor) Satisfied() bool { return f.Contribution == f.Maximum && f.Maximum > 0 }

// Assessment is a scored posture report.
type Assessment struct {
	Score        int      `json:"score"`
	Factors      []Factor `json:"factors"`
	ModelVersion string   `json:"model_version"`
	// Verified is true only when every scored factor was independently
	// established by the backend. In practice endpoint signals dominate, so
	// this is normally false — which is the honest answer.
	Verified bool `json:"verified"`
}

// Weakest returns the factors that lost the most points, worst first. This is
// what an operator needs: not the score, but what to fix.
func (a Assessment) Weakest(limit int) []Factor {
	shortfall := func(f Factor) int { return f.Maximum - f.Contribution }

	ranked := make([]Factor, 0, len(a.Factors))
	for _, f := range a.Factors {
		if shortfall(f) > 0 {
			ranked = append(ranked, f)
		}
	}
	for i := 1; i < len(ranked); i++ {
		for j := i; j > 0 && shortfall(ranked[j]) > shortfall(ranked[j-1]); j-- {
			ranked[j], ranked[j-1] = ranked[j-1], ranked[j]
		}
	}
	if limit > 0 && len(ranked) > limit {
		ranked = ranked[:limit]
	}
	return ranked
}

// tristate renders a reported boolean for a factor detail.
func tristate(value *bool, whenTrue, whenFalse string) (bool, string) {
	if value == nil {
		return false, "not reported by the agent"
	}
	if *value {
		return true, whenTrue
	}
	return false, whenFalse
}

// normalize lowercases and trims a reported string.
func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
