package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/posture"
)

// fakePosture stores assessments in memory, preserving the ordering the real
// store guarantees.
type fakePosture struct {
	records map[uuid.UUID][]posture.Record
}

func newFakePosture() *fakePosture {
	return &fakePosture{records: map[uuid.UUID][]posture.Record{}}
}

func (f *fakePosture) Record(_ context.Context, deviceID uuid.UUID, signals posture.Signals, assessment posture.Assessment) (*posture.Record, error) {
	record := posture.Record{
		ID: uuid.New(), DeviceID: deviceID, CollectedAt: time.Now().UTC(),
		TrustScore: assessment.Score, Signals: signals, Factors: assessment.Factors,
		Verified: assessment.Verified, ModelVersion: assessment.ModelVersion,
	}
	// Newest first, matching the real store's ordering.
	f.records[deviceID] = append([]posture.Record{record}, f.records[deviceID]...)
	return &record, nil
}

func (f *fakePosture) Latest(_ context.Context, deviceID uuid.UUID) (*posture.Record, error) {
	records := f.records[deviceID]
	if len(records) == 0 {
		return nil, posture.ErrNoPosture
	}
	return &records[0], nil
}

func (f *fakePosture) History(_ context.Context, deviceID uuid.UUID, limit int) ([]posture.Record, error) {
	records := f.records[deviceID]
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (f *fakePosture) LatestScores(_ context.Context) (map[uuid.UUID]int, error) {
	scores := map[uuid.UUID]int{}
	for id, records := range f.records {
		if len(records) > 0 {
			scores[id] = records[0].TrustScore
		}
	}
	return scores, nil
}

// postureHarness extends the device harness with posture scoring.
type postureHarness struct {
	*deviceHarness
	posture *fakePosture
}

func newPostureHarness(t *testing.T) *postureHarness {
	t.Helper()

	base := newDeviceHarness(t)
	fake := newFakePosture()

	// Rebuild the router with posture wired in, reusing the same doubles so
	// devices enrolled through the harness remain valid.
	base.harness.router = NewRouter(Options{
		Config:               testConfig(),
		Logger:               discardLogger(),
		DB:                   stubPinger{},
		Verifier:             base.dev,
		Users:                base.users,
		Audit:                base.audit,
		AuditReader:          base.audit,
		DevVerifier:          base.dev,
		Devices:              base.devices,
		Posture:              fake,
		PostureWeights:       posture.DefaultWeights(),
		ExpectedAgentVersion: "0.1.0",
	})
	return &postureHarness{deviceHarness: base, posture: fake}
}

const fullPosture = `{"signals":{"disk_encryption":true,"secure_boot":true,"firewall":true,` +
	`"screen_lock":true,"anti_malware":true,"os_name":"windows","os_version":"11"}}`

func TestPostureRequiresADeviceSignature(t *testing.T) {
	h := newPostureHarness(t)
	h.enroll(t, "device-uid-p00001")

	rec := h.post(t, "/api/v1/agent/posture", "", fullPosture)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for an unsigned posture report", rec.Code)
	}
}

func TestPostureIsScoredByTheBackend(t *testing.T) {
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00002")
	// A heartbeat first, so agent health can be satisfied.
	h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/heartbeat", `{"agent_version":"0.1.0"}`))

	rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var body PostureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TrustScore <= 0 || body.TrustScore > 100 {
		t.Errorf("trust_score = %d, want 1..100", body.TrustScore)
	}
	if body.ModelVersion == "" {
		t.Error("model_version is empty; a historical score would not be interpretable")
	}

	total := 0
	for _, factor := range body.Factors {
		total += factor.Contribution
	}
	if total != body.TrustScore {
		t.Errorf("factors sum to %d but the score is %d", total, body.TrustScore)
	}
}

func TestEndpointCannotSupplyItsOwnScore(t *testing.T) {
	// The whole point of scoring server-side: a compromised endpoint must not
	// be able to assert its own trustworthiness.
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00003")

	body := `{"signals":{"os_name":"windows","os_version":"11"},"trust_score":100}`
	rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", body))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a report carrying its own score", rec.Code)
	}
}

func TestPostureIsAttributedToTheSigningDevice(t *testing.T) {
	// The device comes from the verified signature, never the body, so one
	// agent cannot report posture on another device's behalf.
	h := newPostureHarness(t)
	first := h.enroll(t, "device-uid-p00004")
	second := h.enroll(t, "device-uid-p00005")

	h.send(first.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))

	firstID := uuid.MustParse(first.response.ID)
	secondID := uuid.MustParse(second.response.ID)

	if _, err := h.posture.Latest(context.Background(), firstID); err != nil {
		t.Errorf("the signing device has no posture: %v", err)
	}
	if _, err := h.posture.Latest(context.Background(), secondID); err == nil {
		t.Error("posture was attributed to a device that did not report it")
	}
}

func TestPostureRejectsOversizedSignals(t *testing.T) {
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00006")

	body := `{"signals":{"os_name":"` + strings.Repeat("x", 200) + `","os_version":"11"}}`
	rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", body))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUnknownSignalsDoNotEarnCredit(t *testing.T) {
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00007")

	reported := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))
	silent := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture",
		`{"signals":{"os_name":"windows","os_version":"11"}}`))

	var full, sparse PostureResponse
	_ = json.Unmarshal(reported.Body.Bytes(), &full)
	_ = json.Unmarshal(silent.Body.Bytes(), &sparse)

	if sparse.TrustScore >= full.TrustScore {
		t.Errorf("a device reporting nothing scored %d against %d for one reporting everything",
			sparse.TrustScore, full.TrustScore)
	}
}

func TestWeakestFactorsAreReturnedToTheAgent(t *testing.T) {
	// The user should be told what to fix, not just given a number.
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00008")

	rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture",
		`{"signals":{"disk_encryption":false,"os_name":"windows","os_version":"11"}}`))

	var body PostureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Weakest) == 0 {
		t.Fatal("no weaknesses were returned for a device with encryption disabled")
	}
	if body.Weakest[0].Code != "DISK_ENCRYPTION" {
		t.Errorf("worst factor = %s, want DISK_ENCRYPTION", body.Weakest[0].Code)
	}
}

func TestPostureViewsRequireAPrivilegedRole(t *testing.T) {
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00009")
	h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))

	path := "/api/v1/devices/" + agent.response.ID + "/posture"

	if rec := h.get(t, path, h.token(t, "alice", identity.RoleUser)); rec.Code != http.StatusForbidden {
		t.Errorf("ordinary user status = %d, want 403", rec.Code)
	}
	if rec := h.get(t, path, h.token(t, "ravi", identity.RoleAnalyst)); rec.Code != http.StatusOK {
		t.Errorf("analyst status = %d, want 200", rec.Code)
	}
}

func TestPostureViewReportsWhenNoneHasBeenCollected(t *testing.T) {
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00010")

	rec := h.get(t, "/api/v1/devices/"+agent.response.ID+"/posture",
		h.token(t, "ravi", identity.RoleAnalyst))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a device that has never reported", rec.Code)
	}
}

func TestPostureHistoryShowsChangeOverTime(t *testing.T) {
	// An investigator needs to see when a control was turned off, not only
	// that it is off now.
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00011")

	h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))
	h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture",
		`{"signals":{"disk_encryption":false,"os_name":"windows","os_version":"11"}}`))

	rec := h.get(t, "/api/v1/devices/"+agent.response.ID+"/posture/history",
		h.token(t, "ravi", identity.RoleAnalyst))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		History []struct {
			TrustScore int `json:"trust_score"`
		} `json:"history"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.History) != 2 {
		t.Fatalf("history has %d entries, want 2", len(body.History))
	}
	if body.History[0].TrustScore >= body.History[1].TrustScore {
		t.Error("history is not newest-first, or the drop was not recorded")
	}
}

func TestFleetListingCarriesTrustScores(t *testing.T) {
	h := newPostureHarness(t)
	agent := h.enroll(t, "device-uid-p00012")
	h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))

	rec := h.get(t, "/api/v1/devices", h.token(t, "ravi", identity.RoleAnalyst))

	var body struct {
		Devices []DeviceResponse `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, d := range body.Devices {
		if d.ID == agent.response.ID {
			found = true
			if d.TrustScore == nil {
				t.Error("the fleet listing has no trust score for a device that reported one")
			}
		}
	}
	if !found {
		t.Fatal("the enrolled device is missing from the fleet listing")
	}
}

func TestPostureRoutesAbsentWithoutAPostureService(t *testing.T) {
	h := newDeviceHarness(t)
	agent := h.enroll(t, "device-uid-p00013")

	rec := h.send(agent.signedRequest(t, http.MethodPost, "/api/v1/agent/posture", fullPosture))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when posture scoring is not configured", rec.Code)
	}
}
