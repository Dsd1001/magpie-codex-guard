package check

import (
	"errors"
	"fmt"
	"time"

	"github.com/Dsd1001/magpie-codex-guard/internal/fingerprint"
)

// FingerprintModelOption exposes only public labels from the local reference bank.
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

func resolveFingerprintReference(model, override string) (string, error) {
	d, err := fingerprint.Load()
	if err != nil {
		return "", errors.New("模型指纹参考库加载失败")
	}
	expected := model
	if override != "" {
		expected = override
	}
	if id, supported := d.ResolveExpected(expected); supported {
		return id, nil
	}
	return "", fmt.Errorf("模型 %s 无法自动匹配指纹参考库，请核对模型或设置高级参考映射", expected)
}

// Manual fingerprint checks never change automatic counts, holds or routing.
// There is no standalone periodic or after-failure fingerprint job.
func (s *Service) TriggerFingerprint(account, model string, manual bool) error {
	if !manual {
		return errors.New("独立的自动指纹检测已移除；请将指纹题加入自动客观题")
	}
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
	if s.state.Config.GatewayURL == "" || s.state.Config.GatewayKey == "" {
		s.mu.Unlock()
		return errors.New("专用检测 Gateway Key 未配置")
	}
	expected, refErr := resolveFingerprintReference(model, target.FingerprintExpected)
	runner := s.fingerprint
	s.accountProbeActive = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); s.accountProbeActive = false; s.mu.Unlock() }()
		var report FingerprintReport
		var batch string
		if refErr != nil {
			report = FingerprintReport{Verdict: "indeterminate", Diagnostic: refErr.Error()}
		} else {
			report, batch = s.sampleFingerprint(s.ctx, account, model, expected, runner)
		}
		now := time.Now()
		result := AccountResult{
			ID: Secret()[:12], Batch: batch, Account: account, Model: model,
			Prompt: FingerprintPromptID, PromptName: "手动模型指纹检测",
			Verdict: report.Verdict, Time: now, Fingerprint: &report,
		}
		s.mu.Lock()
		s.addResult(result)
		if err := s.store.Save(s.state); err != nil {
			s.health = err.Error()
		}
		s.mu.Unlock()
	}()
	return nil
}
