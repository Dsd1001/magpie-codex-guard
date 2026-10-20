package check

import (
	"errors"
	"time"

	"github.com/Dsd1001/magpie-codex-guard/internal/fingerprint"
)

// FingerprintModelOption exposes only public labels from the pinned local
// reference library. It never contains account credentials or raw samples.
type FingerprintModelOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func FingerprintModelCatalog() ([]FingerprintModelOption, error) {
	d, err := fingerprint.Load()
	if err != nil {
		return nil, errors.New("模型指纹参考库加载失败")
	}
	out := make([]FingerprintModelOption, 0, len(d.Models()))
	for _, model := range d.Models() {
		out = append(out, FingerprintModelOption{ID: model.ID, Name: model.DisplayName})
	}
	return out, nil
}

// TriggerFingerprint is separate from objective grading. In manual/periodic
// modes, the result never modifies quarantine, recovery, or Gateway Key routing.
func (s *Service) TriggerFingerprint(account, model string, manual bool) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	if err := validateAccountModel(model); err != nil {
		return err
	}
	s.mu.Lock()
	target := s.state.AccountTargets[accountTargetID(account, model)]
	if target == nil || !target.Enabled {
		s.mu.Unlock()
		return errors.New("账号模型组合未加入监测")
	}
	if s.accountProbeActive {
		s.mu.Unlock()
		return errors.New("已有检测正在执行")
	}
	if !manual {
		if s.effectiveAutoPromptPolicyLocked().FingerprintMode != FingerprintPeriodic {
			s.mu.Unlock()
			return errors.New("自动周期指纹检测未开启")
		}
		if _, held := s.state.Holds[account]; held {
			s.mu.Unlock()
			return errors.New("隔离中的账号不能运行周期指纹检测")
		}
		if target.State != "passed" || target.ConsecutiveFails != 0 {
			s.mu.Unlock()
			return errors.New("周期指纹只对客观题正常的账号执行")
		}
	}
	if s.state.Config.GatewayURL == "" || s.state.Config.GatewayKey == "" {
		s.mu.Unlock()
		return errors.New("专用检测 Gateway Key 未配置")
	}
	expected := model
	if target.FingerprintExpected != "" {
		expected = target.FingerprintExpected
	}
	runner := s.fingerprint
	s.accountProbeActive = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); s.accountProbeActive = false; s.mu.Unlock() }()
		report, batch := s.sampleFingerprint(s.ctx, account, model, expected, runner)
		now := time.Now()
		name := "手动模型指纹检测"
		if !manual {
			name = "周期性模型指纹检测"
		}
		result := AccountResult{
			ID: Secret()[:12], Batch: batch, Account: account, Model: model,
			Prompt: FingerprintPromptID, PromptName: name, Verdict: report.Verdict,
			Time: now, Fingerprint: &report,
		}
		s.mu.Lock()
		s.addResult(result)
		if !manual {
			if t := s.state.AccountTargets[accountTargetID(account, model)]; t != nil {
				t.LastFingerprintAt = now
				t.NextFingerprintAt = now.Add(24 * time.Hour)
				t.FingerprintVersion = report.Version
			}
		}
		if err := s.store.Save(s.state); err != nil {
			s.health = err.Error()
		}
		s.mu.Unlock()
	}()
	return nil
}
