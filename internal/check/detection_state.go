package check

import "time"

// The scoring, three-failure threshold, isolation timers and two-pass recovery
// remain in policy.go. This adapter only separates connection faults and keeps
// the durable routing decision independent of a transient UI state.
func (s *Service) applyDetectionVerdictLocked(target *AccountTarget, verdict, prompt string, now time.Time) bool {
	if modelProvider(target.Model) != "codex" {
		return false // legacy API observations must not quarantine other providers
	}
	if verdict == "connection_error" {
		target.State = "connection_error"
		target.NextCheckAt = now.Add(s.timingForTargetLocked(target).unavailable())
		return false
	}
	hold, held := s.state.Holds[target.Account]
	var holdPtr *QuarantineHold
	if held {
		holdPtr = &hold
	}
	timing := s.timingForTargetLocked(target)
	first, release := objectiveTransitionWithTiming(target, holdPtr, verdict, prompt, now, timing)
	if first {
		newHold := startHoldWithTiming(*target, now, timing)
		if verdict == "http_401" || verdict == "http_404" {
			newHold.Cause = verdict
		}
		s.state.Holds[target.Account] = newHold
		target.RouteEligible = false
	} else if release {
		delete(s.state.Holds, target.Account)
		target.RouteEligible = true
	} else if held {
		s.state.Holds[target.Account] = hold
		target.RouteEligible = false
	} else if target.State == PhaseHealthy {
		target.RouteEligible = true
	}
	valid := verdict == "passed" || verdict == "failed" || verdict == "http_401" || verdict == "http_404" || first || release
	if valid {
		s.state.Route.AwaitingDetection = false
	}
	return valid
}

func accountRouteEligible(state State, account string) bool {
	if _, held := state.Holds[account]; held {
		return false
	}
	found := false
	for _, target := range state.AccountTargets {
		if target == nil || target.Account != account || !target.Enabled || target.Missing || modelProvider(target.Model) != "codex" {
			continue
		}
		found = true
		if !target.RouteEligible && target.State != PhaseHealthy {
			return false
		}
	}
	return found
}
