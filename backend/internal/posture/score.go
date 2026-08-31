package posture

import (
	"fmt"
	"time"
)

// ModelVersion identifies the scoring model. It is stored with every
// assessment, because a historical score is only interpretable alongside the
// weights that produced it.
const ModelVersion = "posture-v1"

// AgentStaleAfter is how long since the last heartbeat before the agent is
// treated as not reporting.
const AgentStaleAfter = 15 * time.Minute

// Weights are the maximum points each control can contribute.
//
// They are configuration, not constants (spec §11, §39): a defence deployment
// may weigh disk encryption differently from a general one. They must sum to
// 100 so the score stays interpretable as a percentage.
type Weights struct {
	DeviceIdentity int
	AgentHealth    int
	DiskEncryption int
	SecureBoot     int
	OSSupported    int
	Firewall       int
	ScreenLock     int
	AntiMalware    int
}

// DefaultWeights is the shipped model.
func DefaultWeights() Weights {
	return Weights{
		DeviceIdentity: 20,
		AgentHealth:    15,
		DiskEncryption: 20,
		SecureBoot:     15,
		OSSupported:    10,
		Firewall:       10,
		ScreenLock:     5,
		AntiMalware:    5,
	}
}

// Total returns the sum of all weights.
func (w Weights) Total() int {
	return w.DeviceIdentity + w.AgentHealth + w.DiskEncryption + w.SecureBoot +
		w.OSSupported + w.Firewall + w.ScreenLock + w.AntiMalware
}

// Validate checks that the weights produce an interpretable score.
func (w Weights) Validate() error {
	each := map[string]int{
		"device identity": w.DeviceIdentity, "agent health": w.AgentHealth,
		"disk encryption": w.DiskEncryption, "secure boot": w.SecureBoot,
		"os supported": w.OSSupported, "firewall": w.Firewall,
		"screen lock": w.ScreenLock, "anti-malware": w.AntiMalware,
	}
	for name, value := range each {
		if value < 0 {
			return fmt.Errorf("posture weight for %s must not be negative", name)
		}
	}
	if total := w.Total(); total != 100 {
		return fmt.Errorf("posture weights must sum to 100, got %d", total)
	}
	return nil
}

// MinimumOSVersions are the lowest builds considered current, by OS name.
// Below these, a device scores nothing for OS currency.
var MinimumOSVersions = map[string]string{
	"windows": "10",
	"macos":   "14",
}

// Evaluate scores a posture report.
//
// Contributions always sum exactly to the score, so the explanation shown to an
// analyst reconciles with the number rather than approximating it.
func Evaluate(signals Signals, context DeviceContext, weights Weights) Assessment {
	factors := make([]Factor, 0, 8)

	factors = append(factors, deviceIdentityFactor(context, weights.DeviceIdentity))
	factors = append(factors, agentHealthFactor(context, weights.AgentHealth))
	factors = append(factors, reportedFactor("DISK_ENCRYPTION", "Disk encryption",
		signals.DiskEncryption, weights.DiskEncryption,
		"volume encryption is enabled", "volume encryption is disabled"))
	factors = append(factors, reportedFactor("SECURE_BOOT", "Boot and system integrity",
		signals.SecureBoot, weights.SecureBoot,
		"platform integrity protection is enabled", "platform integrity protection is disabled"))
	factors = append(factors, osSupportedFactor(signals, weights.OSSupported))
	factors = append(factors, reportedFactor("FIREWALL", "Host firewall",
		signals.Firewall, weights.Firewall,
		"host firewall is enabled", "host firewall is disabled"))
	factors = append(factors, reportedFactor("SCREEN_LOCK", "Screen lock",
		signals.ScreenLock, weights.ScreenLock,
		"a password is required after sleep", "no password is required after sleep"))
	factors = append(factors, reportedFactor("ANTI_MALWARE", "Malware protection",
		signals.AntiMalware, weights.AntiMalware,
		"real-time protection is active", "real-time protection is not active"))

	score := 0
	allVerified := true
	for _, factor := range factors {
		score += factor.Contribution
		if factor.Source != SourceVerified {
			allVerified = false
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return Assessment{
		Score:        score,
		Factors:      factors,
		ModelVersion: ModelVersion,
		Verified:     allVerified,
	}
}

// deviceIdentityFactor scores the strength of the device's cryptographic
// identity. This is one of the few factors the backend knows first-hand.
//
// A software-protected key earns partial credit: it is a real identity, but it
// is not equivalent to one the hardware will not surrender (spec §11).
func deviceIdentityFactor(context DeviceContext, maximum int) Factor {
	factor := Factor{
		Code: "DEVICE_IDENTITY", Label: "Device identity",
		Maximum: maximum, Source: SourceVerified,
	}

	if !context.Active {
		factor.Detail = "the device is not active"
		return factor
	}

	switch normalize(context.KeyProtection) {
	case "tpm", "windows-cert-store":
		factor.Contribution = maximum
		factor.Detail = "hardware-backed key"
	case "software":
		// Three fifths: a genuine identity, but the key can be copied by
		// anything running with the agent's privileges.
		factor.Contribution = maximum * 3 / 5
		factor.Detail = "software-protected key; hardware-backed protection is stronger"
	default:
		factor.Detail = "unrecognised key protection"
	}
	return factor
}

// agentHealthFactor scores whether NETRA can currently observe this endpoint.
// Silence is itself a signal: a device whose agent stopped reporting is no
// longer under observation.
func agentHealthFactor(context DeviceContext, maximum int) Factor {
	factor := Factor{
		Code: "AGENT_HEALTH", Label: "Agent health",
		Maximum: maximum, Source: SourceVerified,
	}

	if context.LastHeartbeatAt == nil {
		factor.Detail = "the agent has never reported"
		return factor
	}
	since := context.Now.Sub(*context.LastHeartbeatAt)
	if since > AgentStaleAfter {
		factor.Detail = fmt.Sprintf("the agent last reported %s ago", since.Round(time.Minute))
		return factor
	}

	if context.ExpectedAgent != "" && context.AgentVersion != context.ExpectedAgent {
		// Half credit: the agent is reporting, so the endpoint is observed, but
		// an out-of-date agent may be missing collectors or fixes.
		factor.Contribution = maximum / 2
		factor.Detail = fmt.Sprintf("agent %s is behind the expected %s",
			context.AgentVersion, context.ExpectedAgent)
		return factor
	}

	factor.Contribution = maximum
	factor.Detail = "the agent is reporting and current"
	return factor
}

// osSupportedFactor scores whether the operating system is still current.
func osSupportedFactor(signals Signals, maximum int) Factor {
	factor := Factor{
		Code: "OS_SUPPORTED", Label: "Operating system currency",
		Maximum: maximum, Source: SourceReported,
	}

	minimum, known := MinimumOSVersions[normalize(signals.OSName)]
	if signals.OSVersion == "" || !known {
		factor.Detail = "operating system version could not be assessed"
		return factor
	}

	if compareVersions(signals.OSVersion, minimum) < 0 {
		factor.Detail = fmt.Sprintf("%s %s is below the supported minimum of %s",
			signals.OSName, signals.OSVersion, minimum)
		return factor
	}

	factor.Contribution = maximum
	factor.Detail = fmt.Sprintf("%s %s is supported", signals.OSName, signals.OSVersion)
	return factor
}

// reportedFactor scores a boolean the agent claimed.
func reportedFactor(code, label string, value *bool, maximum int, whenTrue, whenFalse string) Factor {
	satisfied, detail := tristate(value, whenTrue, whenFalse)

	factor := Factor{
		Code: code, Label: label, Maximum: maximum,
		Source: SourceReported, Detail: detail,
	}
	if satisfied {
		factor.Contribution = maximum
	}
	return factor
}

// compareVersions compares dotted numeric versions. Returns -1, 0 or 1.
// Non-numeric components sort as zero, which is the conservative reading for a
// version string that cannot be parsed.
func compareVersions(a, b string) int {
	left, right := splitVersion(a), splitVersion(b)
	for i := 0; i < len(left) || i < len(right); i++ {
		var x, y int
		if i < len(left) {
			x = left[i]
		}
		if i < len(right) {
			y = right[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	var (
		parts   []int
		current int
		digits  bool
	)
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			current = current*10 + int(r-'0')
			digits = true
		case r == '.':
			parts = append(parts, current)
			current, digits = 0, false
		default:
			// Anything else ends the numeric run: "11-preview" reads as 11.
		}
	}
	if digits || len(parts) == 0 {
		parts = append(parts, current)
	}
	return parts
}
