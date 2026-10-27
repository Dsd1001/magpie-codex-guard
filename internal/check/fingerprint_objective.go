package check

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// One complete three-sample fingerprint batch counts as ONE objective answer.
// Partial or inconclusive batches are neutral and can never trigger holds.
func fingerprintAsObjectiveVerdict(report FingerprintReport, expected string) string {
	if expected == "" || report.UsedOutputs != 3 {
		return "unavailable"
	}
	switch report.Verdict {
	case "match":
		return "passed"
	case "mismatch":
		return "failed"
	default:
		return "unavailable"
	}
}

// Fingerprints participate only in the ordinary automatic question bank.
// No separate risk-classification fingerprint is executed after three errors.
func (s *Service) TriggerAutomaticFingerprint(account, model string) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	if err := validateAccountModel(model); err != nil {
		return err
	}
	s.mu.Lock()
	id := accountTargetID(account, model)
	target := s.state.AccountTargets[id]
	if target == nil || !target.Enabled {
		s.mu.Unlock()
		return errors.New("账号模型组合未加入监测")
	}
	if s.accountProbeActive {
		s.mu.Unlock()
		return errors.New("已有账号检测正在执行")
	}
	if s.effectiveAutoPromptPolicyLocked().FingerprintMode != FingerprintObjective {
		s.mu.Unlock()
		return errors.New("模型指纹未加入自动客观题题库")
	}
	if s.state.Config.GatewayURL == "" || s.state.Config.GatewayKey == "" {
		s.mu.Unlock()
		return errors.New("专用检测 Gateway Key 未配置")
	}
	expected, refErr := resolveFingerprintReference(model, target.FingerprintExpected)
	runner := s.fingerprint
	before := *target
	target.State = "checking"
	target.Reason = "自动客观题 · 模型指纹检测中"
	if err := s.saveLocked(); err != nil {
		*target = before
		s.mu.Unlock()
		return err
	}
	s.accountProbeActive = true
	s.wg.Add(1)
	s.mu.Unlock()
	go s.runAutomaticFingerprint(s.ctx, account, model, expected, refErr, runner)
	return nil
}

func (s *Service) runAutomaticFingerprint(ctx context.Context, account, model, expected string, refErr error, runner FingerprintRunner) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		s.accountProbeActive = false
		s.mu.Unlock()
	}()

	report := FingerprintReport{Verdict: "indeterminate", UsedOutputs: 0}
	batch := ""
	if refErr != nil {
		report.Diagnostic = refErr.Error()
	} else {
		report, batch = s.sampleFingerprint(ctx, account, model, expected, runner)
	}
	verdict := fingerprintAsObjectiveVerdict(report, expected)
	now := time.Now()
	result := AccountResult{
		ID: Secret()[:12], Batch: batch, Account: account, Model: model,
		Prompt: FingerprintPromptID, PromptName: "自动客观题 · 模型指纹检测",
		Time: now, Verdict: verdict, Fingerprint: &report,
	}
	if refErr != nil {
		result.Error = report.Diagnostic
	}
	s.mu.Lock()
	s.addResult(result)
	routeChanged := false
	if t := s.state.AccountTargets[accountTargetID(account, model)]; t != nil {
		var holdPtr *QuarantineHold
		hold, held := s.state.Holds[account]
		if held {
			holdPtr = &hold
		}
		timing := s.timingForTargetLocked(t)
		first, release := objectiveTransitionWithTiming(t, holdPtr, verdict, FingerprintPromptID, now, timing)
		t.FingerprintVersion = report.Version
		t.LastFingerprintAt = now
		if first {
			s.state.Holds[account] = startHoldWithTiming(*t, now, timing)
			routeChanged = true
		} else if release {
			delete(s.state.Holds, account)
			routeChanged = true
		} else if held {
			s.state.Holds[account] = hold
		}
	}
	if err := s.saveLocked(); err != nil {
		s.health = err.Error()
		s.mu.Unlock()
		return // no routing changes unless the verdict was durable
	}
	active := s.state.Route.AutoApply
	s.mu.Unlock()
	if routeChanged && active {
		routingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := s.ApplyRouting(routingCtx, false)
		cancel()
		if err != nil {
			s.noteSchedulerError(fmt.Errorf("账号自动指纹隔离路由同步失败：%w", err))
		}
	}
}
