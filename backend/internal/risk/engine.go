package risk

import (
	"time"

	"github.com/google/uuid"
)

// ModelVersion identifies the scoring model. Stored with every assessment,
// because a historical score only means something alongside the model that
// produced it.
const ModelVersion = "risk-v1"

// Sensitivity of the resource being accessed (spec §16).
type Sensitivity string

const (
	SensitivityPublic    Sensitivity = "PUBLIC"
	SensitivityInternal  Sensitivity = "INTERNAL"
	SensitivitySensitive Sensitivity = "SENSITIVE"
	SensitivityCritical  Sensitivity = "CRITICAL"
)

// Inputs is everything the engine needs about a session at one moment.
//
// It is a plain value assembled by the caller from the stores, so the scoring
// itself is a pure function: same inputs, same score, testable without a
// database.
type Inputs struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	Now       time.Time

	// ── Identity ──
	FirstEverSession bool
	SessionAttested  bool

	// ── Device ──
	DeviceTrustScore       *int
	DeviceKeyProtection    string
	DeviceFirstSeenForUser bool
	DeviceEnrolledAt       *time.Time
	AgentLastHeartbeat     *time.Time

	// ── Behaviour ──
	// LoginHourTypical is false when the session started outside the hours this
	// user normally works, judged against their own history.
	LoginHourTypical      bool
	BaselineEstablished   bool
	AccessVolumeZScore    float64
	UnfamiliarApplication bool
	// AnomalyScore is the asynchronous model's output, 0..1. It contributes a
	// bounded number of points and can never dominate the deterministic
	// signals (spec §15, §22).
	AnomalyScore float64

	// ── Network ──
	NetworkFamiliar bool
	NetworkKnown    bool

	// ── Resource ──
	ResourceSensitivity Sensitivity

	// ── History ──
	RecentIncidents int
	RecentDenials   int
}

// Engine scores sessions.
type Engine struct {
	weights    Weights
	thresholds Thresholds
}

// NewEngine builds an engine. Invalid configuration is a startup error
// elsewhere; here the values are taken as given.
func NewEngine(weights Weights, thresholds Thresholds) *Engine {
	return &Engine{weights: weights, thresholds: thresholds}
}

// Evaluate scores one session.
//
// Contributions are summed and clamped to 0..100. Because the factors are the
// summands, the explanation always reconciles with the score.
func (e *Engine) Evaluate(in Inputs) Assessment {
	factors := make([]Factor, 0, 12)
	add := func(dim Dimension, code, label, detail string, points float64) {
		weighted := int(points*e.weights.forDimension(dim) + 0.5)
		if weighted <= 0 {
			return
		}
		factors = append(factors, Factor{
			Code: code, Label: label, Dimension: dim,
			Contribution: weighted, Detail: detail,
		})
	}

	e.identitySignals(in, add)
	e.deviceSignals(in, add)
	e.behaviourSignals(in, add)
	e.networkSignals(in, add)
	e.resourceSignals(in, add)
	e.historySignals(in, add)

	score := 0
	dimensions := map[Dimension]int{}
	for _, factor := range factors {
		score += factor.Contribution
		dimensions[factor.Dimension] += factor.Contribution
	}

	// Clamping can break the sum, so when it bites the largest factor absorbs
	// the difference. An analyst must never see factors that do not add up.
	if score > 100 {
		sortFactors(factors)
		factors[0].Contribution -= score - 100
		dimensions[factors[0].Dimension] -= score - 100
		score = 100
	}
	if score < 0 {
		score = 0
	}

	sortFactors(factors)
	level := e.thresholds.Level(score)

	return Assessment{
		SessionID:    in.SessionID,
		Score:        score,
		Level:        level,
		Action:       level.RecommendedAction(),
		Factors:      factors,
		Dimensions:   dimensions,
		ComputedAt:   in.Now.UTC(),
		ModelVersion: ModelVersion,
	}
}

type addFunc func(dim Dimension, code, label, detail string, points float64)

func (e *Engine) identitySignals(in Inputs, add addFunc) {
	if in.FirstEverSession {
		add(DimIdentity, "FIRST_SESSION", "First session for this account",
			"no prior sessions to compare against", 8)
	}
	if !in.SessionAttested {
		// A session without device proof should not exist; if one does, it is
		// the single most important thing about it.
		add(DimIdentity, "UNATTESTED_SESSION", "Session lacks device attestation",
			"established without cryptographic device proof", 30)
	}
}

func (e *Engine) deviceSignals(in Inputs, add addFunc) {
	if in.DeviceFirstSeenForUser {
		add(DimDevice, "NEW_DEVICE", "New device for this user",
			"this user has not worked from this device before", 20)
	}

	if in.DeviceEnrolledAt != nil && in.Now.Sub(*in.DeviceEnrolledAt) < 24*time.Hour {
		add(DimDevice, "RECENTLY_ENROLLED", "Recently enrolled device",
			"enrolled within the last 24 hours", 6)
	}

	if in.DeviceTrustScore == nil {
		add(DimDevice, "NO_POSTURE", "Device posture unknown",
			"the device has not reported its security posture", 12)
	} else if trust := *in.DeviceTrustScore; trust < 70 {
		// Scaled by how far below the bar it sits, so a device at 68 is not
		// treated the same as one at 20.
		points := float64(70-trust) * 0.4
		if points > 20 {
			points = 20
		}
		add(DimDevice, "LOW_DEVICE_TRUST", "Low device trust",
			formatTrust(trust), points)
	}

	if in.DeviceKeyProtection == "software" {
		add(DimDevice, "SOFTWARE_KEY", "Software-protected device key",
			"the device key is not hardware-backed", 3)
	}

	if in.AgentLastHeartbeat == nil || in.Now.Sub(*in.AgentLastHeartbeat) > 15*time.Minute {
		// Silence is a signal: NETRA cannot see what this endpoint is doing.
		add(DimDevice, "AGENT_SILENT", "Agent not reporting",
			"no heartbeat within the last 15 minutes", 15)
	}
}

func (e *Engine) behaviourSignals(in Inputs, add addFunc) {
	if !in.BaselineEstablished {
		// Absence of a baseline is not evidence of good behaviour, but it is
		// also not evidence of bad. A small, honest contribution.
		add(DimBehaviour, "NO_BASELINE", "No behavioural baseline",
			"not enough history to judge this session against", 5)
		return
	}

	if !in.LoginHourTypical {
		add(DimBehaviour, "UNUSUAL_LOGIN_TIME", "Unusual sign-in time",
			"outside the hours this user normally works", 15)
	}

	if in.AccessVolumeZScore >= 3 {
		points := 12 + (in.AccessVolumeZScore-3)*4
		if points > 22 {
			points = 22
		}
		add(DimBehaviour, "ABNORMAL_ACCESS_VOLUME", "Abnormal access volume",
			formatZScore(in.AccessVolumeZScore), points)
	}

	if in.UnfamiliarApplication {
		add(DimBehaviour, "UNFAMILIAR_APPLICATION", "Unfamiliar application",
			"this user has not used this application before", 6)
	}

	if in.AnomalyScore > 0.5 {
		// Bounded at 10 points: the model informs the score, it does not
		// decide it.
		add(DimBehaviour, "BEHAVIOUR_ANOMALY", "Behavioural anomaly",
			"the anomaly model flagged this session", (in.AnomalyScore-0.5)*20)
	}
}

func (e *Engine) networkSignals(in Inputs, add addFunc) {
	if !in.NetworkKnown {
		add(DimNetwork, "UNKNOWN_NETWORK", "Network context unknown",
			"the session's network could not be determined", 4)
		return
	}
	if !in.NetworkFamiliar {
		add(DimNetwork, "UNUSUAL_NETWORK", "Unusual network",
			"this user has not connected from this network before", 12)
	}
}

func (e *Engine) resourceSignals(in Inputs, add addFunc) {
	// The same behaviour is worth different amounts depending on what is being
	// reached. This is the contextual part of the trust model (spec §16).
	switch in.ResourceSensitivity {
	case SensitivityCritical:
		add(DimResource, "CRITICAL_RESOURCE", "Critical resource accessed",
			"the session reached a resource classified CRITICAL", 25)
	case SensitivitySensitive:
		add(DimResource, "SENSITIVE_RESOURCE", "Sensitive resource accessed",
			"the session reached a resource classified SENSITIVE", 12)
	}
}

func (e *Engine) historySignals(in Inputs, add addFunc) {
	if in.RecentIncidents > 0 {
		points := float64(in.RecentIncidents) * 6
		if points > 15 {
			points = 15
		}
		add(DimHistory, "RECENT_INCIDENT", "Recent incident for this user",
			"an incident was raised for this user in the last 7 days", points)
	}
	if in.RecentDenials >= 3 {
		add(DimHistory, "REPEATED_DENIALS", "Repeated access denials",
			"several access attempts were refused recently", 8)
	}
}

func formatTrust(trust int) string {
	return "device trust is " + itoa(trust) + "/100"
}

func formatZScore(z float64) string {
	return "access volume is " + ftoa(z) + " standard deviations above this user's norm"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func ftoa(v float64) string {
	whole := int(v)
	frac := int((v - float64(whole)) * 10)
	if frac < 0 {
		frac = -frac
	}
	return itoa(whole) + "." + itoa(frac)
}
