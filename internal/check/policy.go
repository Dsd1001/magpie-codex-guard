package check

import (
	"fmt"
	"time"
)

// Legacy constants remain for callers/tests but runtime decisions use TimingPolicy.
const (
	NormalInterval        = 30 * time.Minute
	SuspectInterval       = 2 * time.Minute
	HighRiskInterval      = 48 * time.Hour // historical
	LowRiskFirstInterval  = 6 * time.Hour
	LowRiskRepeatInterval = 24 * time.Hour
	UnavailableInterval   = 30 * time.Minute
)
const (
	PhaseHealthy     = "passed"
	PhaseSuspect     = "suspect"
	PhaseFingerprint = "fingerprint_pending" // historical
	PhaseHigh        = "quarantined_high"    // historical
	PhaseLow         = "quarantined_low"     // historical
	PhaseIsolated    = "quarantined"
	PhaseRecovery    = "recovery_confirm"
)

func phaseForRisk(string) string { return PhaseIsolated }
func isolatedInterval(hold QuarantineHold) time.Duration {
	return isolatedIntervalWithTiming(hold, DefaultTimingPolicy())
}
func isolatedIntervalWithTiming(hold QuarantineHold, timing TimingPolicy) time.Duration {
	if !hold.FirstRecheckDone {
		return timing.first()
	}
	return timing.repeat()
}

// objectiveTransition keeps the legacy test entrypoint with default timings.
func objectiveTransition(t *AccountTarget, h *QuarantineHold, verdict, prompt string, now time.Time) (bool, bool) {
	return objectiveTransitionWithTiming(t, h, verdict, prompt, now, DefaultTimingPolicy())
}

// Each complete fingerprint batch counts as one round. Three confirmed wrong
// answers isolate; unavailable rounds use a separate retry counter and isolate
// only after three attempts. Existing holds still require two valid passes.
func objectiveTransitionWithTiming(target *AccountTarget, hold *QuarantineHold, verdict, prompt string, now time.Time, timing TimingPolicy) (createHold, releaseHold bool) {
	target.CheckedAt = now
	if verdict != "passed" && verdict != "failed" {
		target.ConsecutivePasses = 0
		if hold != nil {
			// Recovery requires two consecutive valid passing checks. A
			// missing verdict breaks that streak, but never releases a hold.
			hold.ConfirmationPasses = 0
			hold.FirstRecheckDone = true
			target.State = PhaseIsolated
			target.Reason = "隔离复测不可用，尚未获得有效通过结果"
			hold.NextCheckAt = now.Add(timing.unavailable())
			target.NextCheckAt = hold.NextCheckAt
			return false, false
		}
		target.ConsecutiveUnavailable++
		target.State = "unavailable"
		target.Reason = fmt.Sprintf("检测不可用（连续 %d/3 轮），等待自动重试；保持账号调度", target.ConsecutiveUnavailable)
		target.NextCheckAt = now.Add(timing.unavailable())
		if target.ConsecutiveUnavailable >= 3 {
			target.State = PhaseIsolated
			target.LastAutoPrompt = prompt
			target.Reason = "自动检测连续三轮不可用，重试后仍未获得有效结果，隔离"
			return true, false
		}
		return false, false
	}
	target.ConsecutiveUnavailable = 0
	if hold != nil {
		if verdict == "passed" {
			hold.ConfirmationPasses++
			target.ConsecutivePasses = hold.ConfirmationPasses
			if hold.ConfirmationPasses >= 2 {
				target.State = PhaseHealthy
				target.Reason = "连续两次回答正确，解除隔离"
				target.NextCheckAt = now.Add(timing.normal())
				target.ConsecutiveFails = 0
				target.ConsecutivePasses = 0
				return false, true
			}
			target.State = PhaseRecovery
			target.Reason = "首次恢复正确，等待第二次确认"
			hold.NextCheckAt = now.Add(timing.recovery())
			target.NextCheckAt = hold.NextCheckAt
			return false, false
		}
		hold.ConfirmationPasses = 0
		hold.FirstRecheckDone = true
		hold.Cause = "objective_failed"
		target.ConsecutivePasses = 0
		target.ConsecutiveFails++
		target.State = PhaseIsolated
		target.Reason = "隔离复测仍回答错误"
		hold.NextCheckAt = now.Add(timing.repeat())
		target.NextCheckAt = hold.NextCheckAt
		return false, false
	}
	// Never combine failures from different questions, including direct API
	// callers that bypass the normal scheduler's same-question retry choice.
	if verdict == "failed" && target.ConsecutiveFails > 0 && target.LastAutoPrompt != "" && target.LastAutoPrompt != prompt {
		target.ConsecutiveFails = 0
	}
	target.LastAutoPrompt = prompt
	if verdict == "passed" {
		target.ConsecutiveFails = 0
		target.ConsecutivePasses = 0
		target.State = PhaseHealthy
		target.Reason = ""
		target.PromptRotation++
		target.NextCheckAt = now.Add(timing.normal())
		return false, false
	}
	target.ConsecutiveFails++
	target.ConsecutivePasses = 0
	target.State = PhaseSuspect
	target.Reason = fmt.Sprintf("同一道客观题连续 %d 次回答错误", target.ConsecutiveFails)
	target.NextCheckAt = now.Add(timing.suspect())
	threshold := 3
	if target.ConsecutiveFails >= threshold {
		target.State = PhaseIsolated
		if prompt == FingerprintPromptID {
			target.Reason = "指纹题连续三轮完整检测确认不一致，隔离"
		} else {
			target.Reason = "普通客观题连续三次回答错误，直接隔离"
		}
		target.NextCheckAt = now.Add(timing.first())
		return true, false
	}
	return false, false
}
func startHold(t AccountTarget, now time.Time) QuarantineHold {
	return startHoldWithTiming(t, now, DefaultTimingPolicy())
}
func startHoldWithTiming(t AccountTarget, now time.Time, timing TimingPolicy) QuarantineHold {
	hold := QuarantineHold{
		Account: t.Account, Model: t.Model, Prompt: t.LastAutoPrompt,
		Risk: "isolated", Reason: t.Reason,
		Since: now, NextCheckAt: now.Add(timing.first()),
	}
	if t.Reason == "自动检测不可用，未获得有效通过结果，直接隔离" || t.Reason == "自动检测连续三轮不可用，重试后仍未获得有效结果，隔离" {
		hold.Cause = "unavailable"
		hold.NextCheckAt = now.Add(timing.unavailable())
	}
	return hold
}

// Legacy internal helper: no longer used for new holds. Old fingerprint
// evidence is preserved, but it cannot alter isolation timing or risk.
func classifyHold(hold *QuarantineHold, report FingerprintReport, now time.Time) {
	hold.Fingerprint = report
	hold.Risk = "isolated"
	hold.Reason = "客观题连续失败，统一隔离"
	hold.NextCheckAt = now.Add(isolatedInterval(*hold))
}
