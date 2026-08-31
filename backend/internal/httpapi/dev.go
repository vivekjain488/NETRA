package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/reqctx"
)

// DevTokenRequest asks for a locally minted development token.
type DevTokenRequest struct {
	Subject     string   `json:"subject"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Department  string   `json:"department"`
	Roles       []string `json:"roles"`
}

// DevTokenResponse carries the minted token.
type DevTokenResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	Issuer      string   `json:"issuer"`
	Roles       []string `json:"roles"`
}

type devHandler struct {
	verifier *identity.DevVerifier
	recorder audit.Recorder
}

// mint issues a development token.
//
// This route exists only when NETRA_DEV_AUTH_ENABLED is set, which the
// configuration loader refuses outside a development environment. It is
// mounted conditionally rather than guarded inside the handler: a route that
// does not exist cannot be reached by a misconfigured deployment.
func (h *devHandler) mint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req DevTokenRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request",
			"The request body is not valid JSON for this endpoint.")
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "subject is required.")
		return
	}

	roles := identity.ParseRoles(req.Roles)
	token, err := h.verifier.Mint(req.Subject, req.Email, req.DisplayName, req.Department, roles)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "The token could not be issued.")
		return
	}

	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, string(role))
	}

	// Even in development, issuing an identity is worth recording: it explains
	// how a principal came to exist when the audit log is read later.
	audit.Log(ctx, h.recorder, logging.FromContext(ctx), audit.Entry{
		ActorType:  audit.ActorSystem,
		ActorID:    "dev-auth",
		Action:     audit.ActionDevTokenIssued,
		TargetType: "user",
		TargetID:   req.Subject,
		Result:     audit.ResultSuccess,
		RequestID:  reqctx.RequestID(ctx),
		Detail:     map[string]any{"roles": roleNames},
	})

	WriteJSON(w, r, http.StatusOK, DevTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		Issuer:      h.verifier.Issuer(),
		Roles:       roleNames,
	})
}
