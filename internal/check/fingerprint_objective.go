package check

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// fingerprintAsObjectiveVerdict is deliberately conservative. It treats a
// strongly identified mismatch as one failed automatic question, but treats
// incomplete, ambiguous or unavailable fingerprints as UNAVAILABLE, never
// as objective failures. The scorer's "mismatch" verdict itself already
// requires strong local-reference evidence.
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

// TriggerAutomaticFingerprint is only available in the explicitly opted-in
// objective_rotation mode. Manual and 24-hour fingerprints still use
// TriggerFingerprint, which never changes objective streaks or quarantine.
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
		return errors.New("模型指纹未开启自动题库轮换")
	}
	if hold, ok := s.state.Holds[account]; ok && hold.Risk == "pending" {
		s.mu.Unlock()
		return errors.New("请先完成隔离指纹复核")
	}
	if s.state.Config.GatewayURL == "" || s.state.Config.GatewayKey == "" {
		s.mu.Unlock()
		return errors.New("专用检测 Gateway Key 未配置")
	}
	// Explicit target reference is required when fingerprint evidence may
	// contribute to production quarantine. Never guess a detector model ID
	// from a gateway alias or implicitly accept an unknown model.
	expected := target.FingerprintExpected
	runner := s.fingerprint
	before := *target
	target.State = "checking"
	target.Reason = "自动题库 · 模型指纹检测中"
	if err := s.saveLocked(); err != nil {
		*target = before
		s.mu.Unlock()
		return err
	}
	s.accountProbeActive = true
	s.wg.Add(1)
	s.mu.Unlock()
	go s.runAutomaticFingerprint(s.ctx, account, model, expected, runner)
	return nil
}

func (s *Service) runAutomaticFingerprint(ctx context.Context, account, model, expected string, runner FingerprintRunner) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		s.accountProbeActive = false
		s.mu.Unlock()
	}()

	report := FingerprintReport{Verdict: "indeterminate", Diagnostic: "该监测目标未设置指纹预期参考模型：请先在手动检测区保存", UsedOutputs: 0}
	batch := ""
	if expected != "" {
		report, batch = s.sampleFingerprint(ctx, account, model, expected, runner)
	}
	verdict := fingerprintAsObjectiveVerdict(report, expected)
	now := time.Now()
	result := AccountResult{
		ID: Secret()[:12], Batch: batch, Account: account, Model: model,
		Prompt: FingerprintPromptID, PromptName: "自动题库 · 模型指纹检测",
		Time: now, Verdict: verdict, Fingerprint: &report,
	}
	if expected == "" {
		result.Error = report.Diagnostic
	}
	// All sample rows + the final fingerprint report are persisted before
	// any routing action; no incomplete/ambiguous batch can create a hold.
	s.mu.Lock()
	s.addResult(result)
	needFinger, routeChanged := false, false
	if t := s.state.AccountTargets[accountTargetID(account, model)]; t != nil {
		var holdPtr *QuarantineHold
		hold, held := s.state.Holds[account]
		if held {
			holdPtr = &hold
		}
		first, release := objectiveTransition(t, holdPtr, verdict, FingerprintPromptID, now)
		t.FingerprintVersion = report.Version
		t.LastFingerprintAt = now
		if first {
			s.state.Holds[account] = startHold(*t, now)
			needFinger = true
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
		return // never update production routing without durable verdicts
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
	if needFinger {
		if !active || s.routeHasHold(account) || s.VerifyLiveHold(account) {
			// Preserve the existing after-third-failure risk classification.
			// It is separate from the three samples used to grade this turn.
			s.collectFingerprint(ctx, account, model)
		} else {
			s.noteSchedulerError(errors.New("生产路由未成功隔离，已停止指纹复核，等待路由修复"))
		}
	}
}
