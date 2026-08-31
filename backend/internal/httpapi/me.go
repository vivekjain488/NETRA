package httpapi

import (
	"net/http"

	"github.com/netra/backend/internal/auth"
	"github.com/netra/backend/internal/identity"
)

// MeResponse is what an authenticated user may learn about themselves.
//
// It is deliberately limited to the caller's own identity: spec §39 gives an
// ordinary USER the right to see their own security state and nothing more.
type MeResponse struct {
	UserID      string   `json:"user_id"`
	Subject     string   `json:"subject"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Department  string   `json:"department,omitempty"`
	Roles       []string `json:"roles"`
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "A bearer token is required.")
		return
	}

	roles := make([]string, 0, len(principal.Roles))
	for _, role := range principal.Roles {
		roles = append(roles, string(role))
	}

	WriteJSON(w, r, http.StatusOK, MeResponse{
		UserID:      principal.UserID.String(),
		Subject:     principal.Subject,
		Email:       principal.Email,
		DisplayName: principal.DisplayName,
		Department:  principal.Department,
		Roles:       roles,
	})
}

// roleSet is a small helper for declaring which roles may reach a route.
func roleSet(roles ...identity.Role) []identity.Role { return roles }
