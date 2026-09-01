package httpapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/reqctx"
	"github.com/netra/backend/internal/simulator"
)

// SimulatorService runs demonstration scenarios.
type SimulatorService interface {
	Run(ctx context.Context, scenario simulator.Scenario) (*simulator.Result, error)
}

type demoHandler struct {
	simulator SimulatorService
	recorder  audit.Recorder
}

// listScenarios returns what an operator can trigger.
func (h *demoHandler) listScenarios(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, r, http.StatusOK, map[string]any{
		"scenarios": simulator.Catalogue(),
		"notice": "Scenarios generate real events that travel the real ingest, risk and policy " +
			"path. No score, decision or incident is written directly.",
	})
}

// runScenario executes one scenario.
//
// It is an administrator action and it is audited: synthetic activity that
// looks real in the event stream must be traceable to the person who caused it.
func (h *demoHandler) runScenario(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name := chi.URLParam(r, "name")
	scenario, ok := simulator.Find(name)
	if !ok {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "No such scenario.")
		return
	}

	principal, _ := auth.FromContext(ctx)
	result, err := h.simulator.Run(ctx, scenario)
	if err != nil {
		logging.FromContext(ctx).Error("scenario failed", "scenario", name, "error", err.Error())
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error",
			"The scenario could not be completed.")
		return
	}

	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorUser,
		ActorID:    actorID(principal),
		Action:     audit.ActionScenarioRun,
		TargetType: "scenario",
		TargetID:   name,
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		Detail: map[string]any{
			"final_score":    result.FinalScore,
			"final_level":    result.FinalLevel,
			"final_decision": result.Decision,
			"session_id":     result.SessionID,
		},
	})

	WriteJSON(w, r, http.StatusOK, result)
}
