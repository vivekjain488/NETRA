package policy

// DefaultPolicies is the shipped policy set (spec §17, §24).
//
// They map the risk bands onto responses, plus two rules that key on a
// specific combination rather than a bare score — because "critical resource
// reached from a new device" deserves a different answer from "score happens
// to be 72".
func DefaultPolicies() []Policy {
	intPtr := func(v int) *int { return &v }

	return []Policy{
		{
			PolicyID: "baseline-low", Version: 1, Priority: 100, Enabled: true,
			Name:        "Allow low-risk sessions",
			Description: "Routine access from a trusted user on a trusted device.",
			Conditions:  Conditions{Levels: []string{"LOW"}},
			Actions:     Actions{Decision: DecisionAllow},
			FailMode:    FailOpen,
		},
		{
			PolicyID: "baseline-medium", Version: 1, Priority: 90, Enabled: true,
			Name:        "Monitor medium-risk sessions",
			Description: "Access continues, but the session is recorded for review.",
			Conditions:  Conditions{Levels: []string{"MEDIUM"}},
			Actions:     Actions{Decision: DecisionAllowMonitor},
			FailMode:    FailOpen,
		},
		{
			PolicyID: "baseline-elevated", Version: 1, Priority: 80, Enabled: true,
			Name:        "Verify elevated-risk sessions",
			Description: "Additional verification before sensitive operations.",
			Conditions:  Conditions{Levels: []string{"ELEVATED"}},
			Actions: Actions{
				Decision: DecisionVerify,
				Message:  "Additional verification is required to continue.",
			},
			FailMode: FailSafe,
		},
		{
			PolicyID: "baseline-high", Version: 1, Priority: 70, Enabled: true,
			Name:        "Step up authentication at high risk",
			Description: "The user must re-authenticate before continuing.",
			Conditions:  Conditions{Levels: []string{"HIGH"}},
			Actions: Actions{
				Decision: DecisionStepUpMFA,
				AlertSOC: true,
				Message:  "Please confirm your identity to continue.",
			},
			FailMode: FailSafe,
		},
		{
			PolicyID: "baseline-critical", Version: 1, Priority: 10, Enabled: true,
			Name:        "Isolate critical-risk sessions",
			Description: "The session is isolated and an incident is opened for the SOC.",
			Conditions:  Conditions{Levels: []string{"CRITICAL"}},
			Actions: Actions{
				Decision:       DecisionIsolate,
				CreateIncident: true,
				AlertSOC:       true,
				Message:        "Access has been suspended. Your security team has been notified.",
			},
			FailMode: FailClosed,
		},
		{
			PolicyID: "critical-resource-guard", Version: 1, Priority: 20, Enabled: true,
			Name:        "Restrict critical resources above elevated risk",
			Description: "The same behaviour is treated differently when a CRITICAL resource is involved.",
			Conditions: Conditions{
				MinRisk:             intPtr(51),
				ResourceSensitivity: []string{"CRITICAL"},
			},
			Actions: Actions{
				Decision:       DecisionRestrict,
				CreateIncident: true,
				AlertSOC:       true,
				Message:        "Access to this resource is restricted at your current risk level.",
			},
			FailMode: FailClosed,
		},
		{
			PolicyID: "new-device-sensitive", Version: 1, Priority: 30, Enabled: true,
			Name:        "Step up on a new device reaching sensitive data",
			Description: "A device this user has never worked from, reaching classified material.",
			Conditions: Conditions{
				RequireFactors:      []string{"NEW_DEVICE"},
				ResourceSensitivity: []string{"SENSITIVE", "CRITICAL"},
			},
			Actions: Actions{
				Decision: DecisionStepUpMFA,
				AlertSOC: true,
				Message:  "Confirm your identity to use this device for sensitive resources.",
			},
			FailMode: FailClosed,
		},
		{
			PolicyID: "unattested-session", Version: 1, Priority: 5, Enabled: true,
			Name:        "Deny sessions without device attestation",
			Description: "A session should not exist without cryptographic device proof.",
			Conditions:  Conditions{RequireFactors: []string{"UNATTESTED_SESSION"}},
			Actions: Actions{
				Decision:       DecisionDeny,
				CreateIncident: true,
				AlertSOC:       true,
				Message:        "This session could not be verified.",
			},
			FailMode: FailClosed,
		},
	}
}
