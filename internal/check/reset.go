package check

import (
	"encoding/json"
	"slices"
	"time"
)

func hasManagedRoutes(route RoutingState) bool {
	return route.Pending || len(route.Quarantined) > 0 || len(route.Expected) > 0 || len(route.ModelBaselines) > 0 || len(route.GroupOffBaselines) > 0
}

// ResetAccountStates never opens, validates, or changes Magpie's production
// files. Cancellation and generation invalidation precede the state update,
// so a late response cannot recreate a hold or overwrite a newer probe.
func (s *Service) ResetAccountStates() (RoutingPreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preemptAccountProbesLocked()
	before, err := json.Marshal(s.state)
	if err != nil {
		return RoutingPreview{}, err
	}
	resetAllAccountMonitoringState(&s.state)
	route := &s.state.Route
	route.Audit = append(route.Audit, RoutingAudit{At: time.Now(), Action: "reset-monitoring"})
	if len(route.Audit) > 100 {
		route.Audit = slices.Clone(route.Audit[len(route.Audit)-100:])
	}
	if err := s.saveLocked(); err != nil {
		var previous State
		if json.Unmarshal(before, &previous) == nil {
			s.state = previous
		}
		return RoutingPreview{}, err
	}
	return RoutingPreview{Mode: "awaiting_detection", ProbeKeyID: route.ProbeKeyID}, nil
}

// Keep detection history, settings, account identities and temporary routing
// ownership. Until a new effective verdict or an explicit sync, even a restart
// must leave production permissions exactly as they were when reset was clicked.
func resetAllAccountMonitoringState(state *State) {
	state.Holds = make(map[string]QuarantineHold)
	for _, target := range state.AccountTargets {
		if target == nil {
			continue
		}
		target.RouteEligible = false
		target.State = "unverified"
		target.Reason = ""
		target.CheckedAt = time.Time{}
		target.NextCheckAt = time.Time{}
		target.ConsecutiveFails = 0
		target.ConsecutiveUnavailable = 0
		target.UnavailablePrompt = ""
		target.ConsecutivePasses = 0
		target.LastAutoPrompt = ""
		target.PromptRotation = 0
		target.LastFingerprintAt = time.Time{}
		target.NextFingerprintAt = time.Time{}
		target.FingerprintVersion = ""
	}
	state.Route.Quarantined = nil
	state.Route.ExpectedCodexCount = 0
	state.Route.AwaitingDetection = true
	state.Route.LastError = ""
}
