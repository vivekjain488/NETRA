package simulator

import (
	"time"

	"github.com/netra/backend/internal/telemetry"
)

// normalSession is the baseline the demonstration opens on: a known user, a
// known device, ordinary work.
func normalSession() Scenario {
	return Scenario{
		Name:        "normal-session",
		Title:       "Normal session",
		Description: "A known user signs in from their usual device during working hours and opens internal applications.",
		Expectation: "Risk stays in the LOW band and access is allowed.",
		steps: []step{
			{"Sign in from the usual device", func(r *run) error {
				return r.startSession(sessionOptions{Familiar: true})
			}},
			{"Open mail", func(r *run) error {
				return r.accessResource("mail", "inbox")
			}},
			{"Open the internal portal", func(r *run) error {
				return r.accessResource("portal", "policies")
			}},
		},
	}
}

// newDevice is the first escalation: the same person, a machine they have
// never worked from.
func newDevice() Scenario {
	return Scenario{
		Name:        "new-device",
		Title:       "New device",
		Description: "The same user signs in from a device they have never used before.",
		Expectation: "The NEW_DEVICE factor appears and risk rises.",
		steps: []step{
			{"Enrol an unfamiliar device", func(r *run) error {
				return r.enrolDevice("SIM-LAPTOP-NEW")
			}},
			{"Sign in from the unfamiliar device", func(r *run) error {
				return r.startSession(sessionOptions{})
			}},
			{"Open mail", func(r *run) error {
				return r.accessResource("mail", "inbox")
			}},
		},
	}
}

// unusualLoginTime tests the behavioural baseline directly.
func unusualLoginTime() Scenario {
	return Scenario{
		Name:        "unusual-login-time",
		Title:       "Unusual sign-in time",
		Description: "The user signs in at 01:47, far outside the hours their own history shows.",
		Expectation: "UNUSUAL_LOGIN_TIME appears, judged against this user's baseline rather than an office norm.",
		steps: []step{
			{"Sign in at 01:47", func(r *run) error {
				return r.startSession(sessionOptions{Familiar: true, AtHour: 1, AtMinute: 47})
			}},
			{"Open the operations portal", func(r *run) error {
				return r.accessResource("operations", "field-reports")
			}},
		},
	}
}

// sensitiveAccess shows that context changes the answer.
func sensitiveAccess() Scenario {
	return Scenario{
		Name:        "sensitive-resource",
		Title:       "Sensitive resource access",
		Description: "The same session reaches a CRITICAL resource instead of an internal one.",
		Expectation: "CRITICAL_RESOURCE contributes and the policy answer becomes stricter for identical behaviour.",
		steps: []step{
			{"Sign in normally", func(r *run) error {
				return r.startSession(sessionOptions{Familiar: true})
			}},
			{"Open an internal resource", func(r *run) error {
				return r.accessResource("portal", "policies")
			}},
			{"Open the classified operations database", func(r *run) error {
				return r.accessResource("critical", "operations-db")
			}},
		},
	}
}

// abnormalVolume exercises the z-score against the user's own history.
func abnormalVolume() Scenario {
	return Scenario{
		Name:        "abnormal-volume",
		Title:       "Abnormal access volume",
		Description: "The session reads far more than this user's history shows they ever do.",
		Expectation: "ABNORMAL_ACCESS_VOLUME appears once the z-score exceeds three.",
		steps: []step{
			{"Sign in normally", func(r *run) error {
				return r.startSession(sessionOptions{Familiar: true})
			}},
			{"Read 120 records in quick succession", func(r *run) error {
				return r.bulkAccess("operations", "field-reports", 120)
			}},
		},
	}
}

// networkAnomaly adds the network dimension.
func networkAnomaly() Scenario {
	return Scenario{
		Name:        "network-anomaly",
		Title:       "Unusual network",
		Description: "The session connects from a network this user has never used, and reaches an unfamiliar destination.",
		Expectation: "UNUSUAL_NETWORK contributes to the score.",
		steps: []step{
			{"Sign in from an unfamiliar network", func(r *run) error {
				return r.startSession(sessionOptions{SourceIP: "203.0.113.77"})
			}},
			{"Connect to an unfamiliar destination", func(r *run) error {
				return r.networkEvent("198.51.100.42:8443")
			}},
		},
	}
}

// compromisedSession is the hero demonstration (spec §51).
//
// Each step is a separate, real evaluation. The scores are whatever the engine
// computes from the accumulated context — the scenario controls the situation,
// never the number.
func compromisedSession() Scenario {
	return Scenario{
		Name:  "compromised-session",
		Title: "Compromised employee session",
		Description: "A credential is used from an unfamiliar device at 01:47, reaches classified " +
			"material, reads at a volume the user has never reached, and connects to an unfamiliar destination.",
		Expectation: "Risk escalates step by step until policy isolates the session and opens one incident.",
		steps: []step{
			{"Normal sign-in, usual device", func(r *run) error {
				if err := r.startSession(sessionOptions{Familiar: true}); err != nil {
					return err
				}
				return r.accessResource("mail", "inbox")
			}},
			{"Credential used from a new device", func(r *run) error {
				if err := r.enrolDevice("SIM-LAPTOP-UNKNOWN"); err != nil {
					return err
				}
				return r.startSession(sessionOptions{})
			}},
			{"Sign-in at 01:47 from an unfamiliar network", func(r *run) error {
				if err := r.startSession(sessionOptions{
					AtHour: 1, AtMinute: 47, SourceIP: "203.0.113.77",
				}); err != nil {
					return err
				}
				return r.networkEvent("198.51.100.42:8443")
			}},
			{"Classified resource reached", func(r *run) error {
				return r.accessResource("critical", "deployment-plans")
			}},
			{"Abnormal read volume", func(r *run) error {
				return r.bulkAccess("critical", "operations-db", 140)
			}},
		},
	}
}

// habitualHour and habitualMinute match the seeded history, so a step
// described as a normal sign-in is judged as one by the user's own baseline.
const (
	habitualHour   = 9
	habitualMinute = 12
)

// sessionOptions describes the session a step should establish.
type sessionOptions struct {
	// Familiar uses the user's usual device rather than the most recently
	// created one.
	Familiar bool
	AtHour   int
	AtMinute int
	SourceIP string
}

// startedAt resolves the session start time.
//
// Unset means the user's habitual hour rather than the wall clock: a scenario
// run at three in the morning would otherwise flag its own baseline step as an
// unusual sign-in.
func (o sessionOptions) startedAt(now time.Time) time.Time {
	hour, minute := o.AtHour, o.AtMinute
	if hour == 0 && minute == 0 {
		hour, minute = habitualHour, habitualMinute
	}
	return time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, time.UTC)
}

// eventFor builds a simulated event. Source is always SIMULATOR, so simulated
// activity can never be mistaken for a real endpoint's.
func eventFor(eventType telemetry.Type, severity telemetry.Severity, metadata map[string]string) telemetry.Event {
	return telemetry.Event{
		Type:     eventType,
		Severity: severity,
		Source:   telemetry.SourceSimulator,
		Metadata: metadata,
	}
}
