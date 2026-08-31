// Package behaviour builds per-user behavioural baselines.
//
// Baselines are personal: a night-shift operator's normal hours are not an
// office worker's, so "unusual" is judged against the individual's own history
// rather than an organisational average (spec §12).
//
// The statistics are deliberately simple — histograms, membership sets, mean
// and standard deviation. They are cheap to compute, cheap to explain to an
// analyst, and produce a defensible answer to "why was this flagged?". A model
// can refine this later; it cannot replace the explanation.
package behaviour

import (
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

// MinimumObservations is how many sessions a user needs before their baseline
// is treated as meaningful. Below it, deviation is not evidence of anything.
const MinimumObservations = 5

// DefaultWindowDays is how far back a baseline looks.
const DefaultWindowDays = 30

// Profile is one user's learned normal.
type Profile struct {
	UserID            uuid.UUID `json:"user_id"`
	UpdatedAt         time.Time `json:"updated_at"`
	WindowDays        int       `json:"window_days"`
	ObservationCount  int       `json:"observation_count"`
	LoginHours        [24]int   `json:"login_hours"`
	KnownDevices      []string  `json:"known_devices"`
	KnownApplications []string  `json:"known_applications"`
	KnownNetworks     []string  `json:"known_networks"`
	AccessRateMean    float64   `json:"access_rate_mean"`
	AccessRateStdDev  float64   `json:"access_rate_stddev"`
	Established       bool      `json:"established"`
}

// Observation is one session's worth of behaviour, used to build a profile.
type Observation struct {
	StartedAt    time.Time
	DeviceID     uuid.UUID
	Applications []string
	Network      string
	EventCount   int
}

// Build computes a profile from a user's recent sessions.
func Build(userID uuid.UUID, windowDays int, observations []Observation, now time.Time) Profile {
	if windowDays <= 0 {
		windowDays = DefaultWindowDays
	}

	profile := Profile{
		UserID:     userID,
		UpdatedAt:  now.UTC(),
		WindowDays: windowDays,
	}

	devices := map[string]bool{}
	applications := map[string]bool{}
	networks := map[string]bool{}
	counts := make([]float64, 0, len(observations))

	for _, observation := range observations {
		profile.ObservationCount++
		profile.LoginHours[observation.StartedAt.UTC().Hour()]++
		devices[observation.DeviceID.String()] = true

		for _, application := range observation.Applications {
			if application != "" {
				applications[application] = true
			}
		}
		if observation.Network != "" {
			networks[observation.Network] = true
		}
		counts = append(counts, float64(observation.EventCount))
	}

	profile.KnownDevices = sortedKeys(devices)
	profile.KnownApplications = sortedKeys(applications)
	profile.KnownNetworks = sortedKeys(networks)
	profile.AccessRateMean, profile.AccessRateStdDev = meanAndStdDev(counts)
	profile.Established = profile.ObservationCount >= MinimumObservations

	return profile
}

// IsTypicalHour reports whether an hour is one the user normally works.
//
// An hour counts as typical if the user has ever signed in during it, or in
// either adjacent hour. The neighbours matter: someone who usually starts at
// 09:00 should not be flagged for starting at 08:55 one morning.
func (p Profile) IsTypicalHour(t time.Time) bool {
	if !p.Established {
		// Without a baseline, everything is typical. Treating an unknown hour
		// as suspicious would flag every new joiner on their first morning.
		return true
	}
	hour := t.UTC().Hour()
	for _, offset := range []int{-1, 0, 1} {
		if p.LoginHours[((hour+offset)%24+24)%24] > 0 {
			return true
		}
	}
	return false
}

// IsKnownDevice reports whether this user has worked from a device before.
func (p Profile) IsKnownDevice(deviceID uuid.UUID) bool {
	return contains(p.KnownDevices, deviceID.String())
}

// IsKnownApplication reports whether this user has used an application before.
func (p Profile) IsKnownApplication(application string) bool {
	return contains(p.KnownApplications, application)
}

// IsKnownNetwork reports whether this user has connected from a network before.
func (p Profile) IsKnownNetwork(network string) bool {
	return contains(p.KnownNetworks, network)
}

// AccessVolumeZScore expresses how unusual an event count is for this user.
//
// Returns 0 when there is no usable baseline: a z-score computed from too few
// observations, or from a standard deviation of zero, is a number without
// meaning, and feeding one into the risk engine would manufacture alarm.
func (p Profile) AccessVolumeZScore(eventCount int) float64 {
	if !p.Established || p.AccessRateStdDev <= 0 {
		return 0
	}
	z := (float64(eventCount) - p.AccessRateMean) / p.AccessRateStdDev
	if z < 0 {
		// Doing less than usual is not a security signal.
		return 0
	}
	return z
}

// meanAndStdDev computes the population mean and standard deviation.
func meanAndStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}
	mean := sum / float64(len(values))

	if len(values) < 2 {
		return mean, 0
	}

	variance := 0.0
	for _, value := range values {
		delta := value - mean
		variance += delta * delta
	}
	return mean, math.Sqrt(variance / float64(len(values)))
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}
