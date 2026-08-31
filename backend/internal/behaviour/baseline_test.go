package behaviour

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func at(hour int) time.Time {
	return time.Date(2026, 8, 24, hour, 0, 0, 0, time.UTC)
}

// officeWorker has a week of 09:00-ish sessions from one device.
func officeWorker(device uuid.UUID) []Observation {
	var out []Observation
	for day := 0; day < 7; day++ {
		out = append(out, Observation{
			StartedAt:    at(9).AddDate(0, 0, day),
			DeviceID:     device,
			Applications: []string{"mail", "portal"},
			Network:      "10.1.2.3",
			EventCount:   20,
		})
	}
	return out
}

func TestProfileIsNotEstablishedWithoutEnoughHistory(t *testing.T) {
	// Deviation from three data points is not evidence of anything.
	profile := Build(uuid.New(), 30, officeWorker(uuid.New())[:3], time.Now())

	if profile.Established {
		t.Errorf("a profile from %d observations claims to be established", profile.ObservationCount)
	}
}

func TestUnestablishedProfileTreatsEverythingAsTypical(t *testing.T) {
	// A new joiner must not be flagged on their first morning.
	profile := Build(uuid.New(), 30, nil, time.Now())

	if !profile.IsTypicalHour(at(3)) {
		t.Error("an unestablished profile flagged an hour as unusual")
	}
	if z := profile.AccessVolumeZScore(10_000); z != 0 {
		t.Errorf("z-score = %f without a baseline, want 0", z)
	}
}

func TestTypicalHoursIncludeNeighbours(t *testing.T) {
	// Someone who normally starts at 09:00 should not be flagged at 08:55.
	profile := Build(uuid.New(), 30, officeWorker(uuid.New()), time.Now())

	for _, hour := range []int{8, 9, 10} {
		if !profile.IsTypicalHour(at(hour)) {
			t.Errorf("hour %d was flagged as unusual for a 09:00 worker", hour)
		}
	}
	for _, hour := range []int{1, 2, 3, 22} {
		if profile.IsTypicalHour(at(hour)) {
			t.Errorf("hour %d was treated as typical for a 09:00 worker", hour)
		}
	}
}

func TestBaselinesArePersonal(t *testing.T) {
	// A night-shift operator's normal is not an office worker's.
	device := uuid.New()
	var nightShift []Observation
	for day := 0; day < 7; day++ {
		nightShift = append(nightShift, Observation{
			StartedAt: at(2).AddDate(0, 0, day), DeviceID: device, EventCount: 20,
		})
	}

	office := Build(uuid.New(), 30, officeWorker(device), time.Now())
	night := Build(uuid.New(), 30, nightShift, time.Now())

	if office.IsTypicalHour(at(2)) {
		t.Error("02:00 is typical for the office worker")
	}
	if !night.IsTypicalHour(at(2)) {
		t.Error("02:00 is not typical for the night-shift operator")
	}
}

func TestKnownDevicesApplicationsAndNetworks(t *testing.T) {
	device := uuid.New()
	profile := Build(uuid.New(), 30, officeWorker(device), time.Now())

	if !profile.IsKnownDevice(device) {
		t.Error("the user's own device is not recognised")
	}
	if profile.IsKnownDevice(uuid.New()) {
		t.Error("an unseen device was recognised")
	}
	if !profile.IsKnownApplication("mail") || profile.IsKnownApplication("exfil-tool") {
		t.Errorf("application recognition is wrong: %v", profile.KnownApplications)
	}
	if !profile.IsKnownNetwork("10.1.2.3") || profile.IsKnownNetwork("203.0.113.9") {
		t.Errorf("network recognition is wrong: %v", profile.KnownNetworks)
	}
}

func TestAccessVolumeZScore(t *testing.T) {
	device := uuid.New()
	observations := officeWorker(device)
	// Introduce variance so the standard deviation is usable.
	for i := range observations {
		observations[i].EventCount = 18 + i
	}
	profile := Build(uuid.New(), 30, observations, time.Now())

	if z := profile.AccessVolumeZScore(21); z > 2 {
		t.Errorf("a normal volume scored %f", z)
	}
	if z := profile.AccessVolumeZScore(500); z < 3 {
		t.Errorf("a large spike scored only %f", z)
	}
}

func TestDoingLessThanUsualIsNotASignal(t *testing.T) {
	device := uuid.New()
	observations := officeWorker(device)
	for i := range observations {
		observations[i].EventCount = 50 + i
	}
	profile := Build(uuid.New(), 30, observations, time.Now())

	if z := profile.AccessVolumeZScore(1); z != 0 {
		t.Errorf("a quiet session scored %f; low volume is not a security signal", z)
	}
}

func TestZeroVarianceDoesNotManufactureAlarm(t *testing.T) {
	// Every session identical means the standard deviation is zero; dividing by
	// it would produce infinity and flag everything.
	profile := Build(uuid.New(), 30, officeWorker(uuid.New()), time.Now())

	if z := profile.AccessVolumeZScore(1000); z != 0 {
		t.Errorf("z-score = %f with zero variance, want 0", z)
	}
}

func TestMeanAndStdDev(t *testing.T) {
	mean, stddev := meanAndStdDev([]float64{2, 4, 4, 4, 5, 5, 7, 9})

	if mean != 5 {
		t.Errorf("mean = %f, want 5", mean)
	}
	if stddev != 2 {
		t.Errorf("stddev = %f, want 2", stddev)
	}
	if m, s := meanAndStdDev(nil); m != 0 || s != 0 {
		t.Errorf("empty input gave mean %f stddev %f, want 0 and 0", m, s)
	}
}
