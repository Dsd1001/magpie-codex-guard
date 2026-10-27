package check

import (
	"fmt"
	"time"
)

const (
	NormalInterval        = 30 * time.Minute
	SuspectInterval       = 2 * time.Minute
	HighRiskInterval      = 48 * time.Hour
	LowRiskFirstInterval  = 6 * time.Hour
	LowRiskRepeatInterval = 24 * time.Hour
	UnavailableInterval   = 30 * time.Minute
)
const (
	PhaseHealthy     = "passed"
	PhaseSuspect     = "suspect"
	PhaseFingerprint = "fingerprint_pending"
	PhaseHigh        = "quarantined_high"
	PhaseLow         = "quarantined_low"
	PhaseRecovery    = "recovery_confirm"
)

func phaseForRisk(risk string) string {
	if risk == "high" {
		return PhaseHigh
	}
	return PhaseLow
}
func isolatedInterval(hold QuarantineHold) time.Duration {
	if hold.Risk == "high" {
		return HighRiskInterval
	}
	if !hold.FirstRecheckDone {
		return LowRiskFirstInterval
	}
	return LowRiskRepeatInterval
}

// objectiveTransition is deliberately pure: caller owns state persistence and
// must reconcile active production routes immediately after a hold mutation.
// Never interpret a failed HTTP request as an objective answer failure.
func objectiveTransition(target *AccountTarget, hold *QuarantineHold, verdict, prompt string, now time.Time) (createHold, releaseHold bool) {
	target.CheckedAt = now
	if verdict == "unavailable" {
		target.Reason = "上游请求不可用，本轮不计入质量结果"
		if hold != nil {
			if hold.Risk == "pending" {
				hold.NextCheckAt = now.Add(UnavailableInterval)
			} else if hold.ConfirmationPasses == 1 {
				hold.NextCheckAt = now.Add(UnavailableInterval)
			} else {
				hold.NextCheckAt = now.Add(isolatedInterval(*hold))
			}
			target.NextCheckAt = hold.NextCheckAt
		} else {
			target.State = "unavailable"
			target.NextCheckAt = now.Add(UnavailableInterval)
		}
		return false, false
	}
	if hold != nil && hold.Risk != "pending" {
		if verdict == "passed" {
			hold.ConfirmationPasses++
			target.ConsecutivePasses = hold.ConfirmationPasses
			if hold.ConfirmationPasses >= 2 {
				target.State = PhaseHealthy
				target.Reason = "连续两次恢复通过，解除隔离"
				target.NextCheckAt = now.Add(NormalInterval)
				target.ConsecutiveFails = 0
				target.ConsecutivePasses = 0
				return false, true
			}
			target.State = PhaseRecovery
			target.Reason = "首次恢复通过，2 分钟后再次确认"
			hold.NextCheckAt = now.Add(SuspectInterval)
			target.NextCheckAt = hold.NextCheckAt
			return false, false
		}
		hold.ConfirmationPasses = 0
		hold.FirstRecheckDone = true
		target.ConsecutivePasses = 0
		target.ConsecutiveFails++
		target.State = phaseForRisk(hold.Risk)
		target.Reason = fmt.Sprintf("隔离复测仍回答错误（%s风险）", hold.Risk)
		hold.NextCheckAt = now.Add(isolatedInterval(*hold))
		target.NextCheckAt = hold.NextCheckAt
		return false, false
	}
	if hold != nil && hold.Risk == "pending" {
		// An in-flight fingerprint must not be replaced by a different objective
		// test result or prematurely release an account.
		return false, false
	}
	target.LastAutoPrompt = prompt
	if verdict == "passed" {
		target.ConsecutiveFails = 0
		target.ConsecutivePasses = 0
		target.State = PhaseHealthy
		target.Reason = ""
		target.PromptRotation++
		target.NextCheckAt = now.Add(NormalInterval)
		return false, false
	}
	target.ConsecutiveFails++
	target.ConsecutivePasses = 0
	target.State = PhaseSuspect
	target.Reason = fmt.Sprintf("客观题连续 %d 次回答错误", target.ConsecutiveFails)
	target.NextCheckAt = now.Add(SuspectInterval)
	if target.ConsecutiveFails >= 3 {
		target.State = PhaseFingerprint
		target.Reason = "客观题连续三次失败，立即暂停生产路由并进行指纹复核"
		target.NextCheckAt = now
		return true, false
	}
	return false, false
}
func startHold(t AccountTarget, now time.Time) QuarantineHold {
	return QuarantineHold{
		Account: t.Account, Model: t.Model, Risk: "pending",
		Reason: "客观题连续三次失败，待模型指纹复核",
		Since:  now, NextCheckAt: now,
	}
}
func classifyHold(hold *QuarantineHold, report FingerprintReport, now time.Time) {
	hold.Fingerprint = report
	if report.Verdict == "mismatch" {
		hold.Risk = "high"
		hold.Reason = "客观题连续失败，且指纹明显偏离预期"
	} else {
		// match AND indeterminate are low risk, as explicitly requested.
		hold.Risk = "low"
		if report.Verdict == "indeterminate" {
			hold.Reason = "客观题连续失败；指纹无法判定，按低风险隔离"
		} else {
			hold.Reason = "客观题连续失败，指纹与预期类别一致"
		}
	}
	hold.NextCheckAt = now.Add(isolatedInterval(*hold))
}
