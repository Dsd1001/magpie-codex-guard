package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Dsd1001/magpie-codex-guard/internal/fingerprint"
)

// SetAccountTarget enrolls a specified stable ID, model and fingerprint rubric.
func (s *Service) SetAccountTarget(account, model string, enabled bool) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	if err := validateAccountModel(model); err != nil {
		return err
	}
	dir, err := MagpieDir()
	if err != nil {
		return err
	}
	known, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return err
	}
	stable, err := ResolveAccountID(known, account)
	if err != nil {
		return err
	}
	id := accountTargetID(stable, model)
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.state.AccountTargets[id]
	if target == nil {
		target = &AccountTarget{Account: stable, Model: model, State: "unverified", Enabled: enabled}
		s.state.AccountTargets[id] = target
	}
	if _, held := s.state.Holds[stable]; held && !enabled {
		return errors.New("账号仍被隔离，不能通过停用监测清除隔离；请通过恢复流程处理")
	}
	before := *target
	target.Enabled = enabled
	if err := s.saveLocked(); err != nil {
		*target = before
		return err
	}
	return nil
}
func (s *Service) DeleteAccountTarget(account, model string) error {
	id := accountTargetID(account, model)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive {
		return errors.New("检测运行中，禁止修改目标")
	}
	if _, hold := s.state.Holds[account]; hold {
		return errors.New("账号仍被隔离，不能删除监测目标")
	}
	old, ok := s.state.AccountTargets[id]
	if !ok {
		return errors.New("未找到监测目标")
	}
	delete(s.state.AccountTargets, id)
	if err := s.saveLocked(); err != nil {
		s.state.AccountTargets[id] = old
		return err
	}
	return nil
}
func (s *Service) DiscoverAccountTargets(model string) (int, error) {
	if err := validateAccountModel(model); err != nil {
		return 0, err
	}
	dir, err := MagpieDir()
	if err != nil {
		return 0, err
	}
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive {
		return 0, errors.New("检测运行中")
	}
	created := []string{}
	for _, a := range accounts {
		id := accountTargetID(a.ID, model)
		if s.state.AccountTargets[id] == nil {
			s.state.AccountTargets[id] = &AccountTarget{Account: a.ID, Model: model, State: "unverified", Enabled: true}
			created = append(created, id)
		}
	}
	if err := s.saveLocked(); err != nil {
		for _, id := range created {
			delete(s.state.AccountTargets, id)
		}
		return 0, err
	}
	return len(created), nil
}
func (s *Service) TriggerAccount(account, model, prompt string, manual bool) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	if err := validateAccountModel(model); err != nil {
		return err
	}
	id := accountTargetID(account, model)
	s.mu.Lock()
	target := s.state.AccountTargets[id]
	if target == nil || !target.Enabled {
		s.mu.Unlock()
		return errors.New("账号模型组合未加入监测")
	}
	if s.accountProbeActive {
		s.mu.Unlock()
		return errors.New("已有账号检测正在执行")
	}
	if !manual {
		if hold, ok := s.state.Holds[account]; ok && hold.Risk == "pending" {
			s.mu.Unlock()
			return errors.New("请先执行指纹复核")
		}
	}
	p, ok := s.findPromptLocked(prompt)
	if !ok {
		s.mu.Unlock()
		return errors.New("检测题目不存在")
	}
	if !manual && !p.Automatic {
		s.mu.Unlock()
		return errors.New("该题目未配置可靠的自动答案")
	}
	if s.state.Config.GatewayURL == "" || s.state.Config.GatewayKey == "" {
		s.mu.Unlock()
		return errors.New("专用检测 Gateway Key 未配置")
	}
	if !manual {
		target.State = "checking"
		target.Reason = "检测中"
	}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.accountProbeActive = true
	s.wg.Add(1)
	s.mu.Unlock()
	go s.runAccount(s.ctx, account, model, p, manual)
	return nil
}
func (s *Service) addResult(result AccountResult) {
	s.state.AccountResults = append(s.state.AccountResults, result)
	if len(s.state.AccountResults) > 300 {
		s.state.AccountResults = append([]AccountResult(nil), s.state.AccountResults[len(s.state.AccountResults)-300:]...)
	}
}
func (s *Service) runAccount(parent context.Context, account, model string, p Prompt, manual bool) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); s.accountProbeActive = false; s.mu.Unlock() }()
	cfg, err := s.reserveRequest()
	var answer string
	var tokens int
	if err == nil {
		ctx, cancel := context.WithTimeout(parent, 180*time.Second)
		s.mu.Lock()
		alias := s.state.Alias
		s.mu.Unlock()
		answer, tokens, err = CallAccount(ctx, cfg, "quality-probe/"+alias+"/"+model, account, p.Text)
		cancel()
	}
	verdict := "unavailable"
	if err == nil {
		verdict = gradeConfiguredPrompt(p, answer)
	}
	now := time.Now()
	r := AccountResult{ID: Secret()[:12], Account: account, Model: model, Prompt: p.ID, PromptName: p.Name, Verdict: verdict, Time: now, Tokens: tokens, Answer: answer}
	if len(r.Answer) > 8192 {
		r.Answer = r.Answer[:8192]
	}
	if err != nil {
		r.Error = err.Error()
	}
	s.mu.Lock()
	s.addResult(r)
	needFinger, routeChanged := false, false
	if !manual && p.Automatic {
		id := accountTargetID(account, model)
		if t := s.state.AccountTargets[id]; t != nil {
			var holdPtr *QuarantineHold
			hold, held := s.state.Holds[account]
			if held {
				holdPtr = &hold
			}
			first, release := objectiveTransition(t, holdPtr, verdict, p.ID, now)
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
	}
	if err := s.saveLocked(); err != nil {
		s.health = err.Error()
		s.mu.Unlock()
		return // never modify production keys from non-durable probe evidence
	}
	active := s.state.Route.AutoApply
	s.mu.Unlock()
	if routeChanged && active {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		_, err := s.ApplyRouting(ctx, false)
		cancel()
		if err != nil {
			s.noteSchedulerError(fmt.Errorf("账号隔离路由同步失败：%w", err))
		}
	}
	if needFinger {
		if !active || s.routeHasHold(account) {
			s.collectFingerprint(parent, account, model)
		} else {
			s.noteSchedulerError(errors.New("生产路由未成功隔离，已停止指纹复核，等待路由修复"))
		}
	}
}
func (s *Service) routeHasHold(account string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Route.Quarantined[account] && !s.state.Route.Pending
}
func (s *Service) collectFingerprint(parent context.Context, account, model string) {
	s.mu.Lock()
	hold, ok := s.state.Holds[account]
	if !ok || hold.Risk != "pending" {
		s.mu.Unlock()
		return
	}
	alias := s.state.Alias
	expected := model
	if t := s.state.AccountTargets[accountTargetID(account, model)]; t != nil && t.FingerprintExpected != "" {
		expected = t.FingerprintExpected
	}
	runner := s.fingerprint
	s.mu.Unlock()
	challenges := newFingerprintChallenges()
	batch := Secret()[:12]
	outputs := []fingerprint.Output{}
	issue := ""
	for _, ch := range challenges {
		cfg, err := s.reserveRequest()
		var answer string
		var tokens int
		if err == nil {
			ctx, cancel := context.WithTimeout(parent, 180*time.Second)
			answer, tokens, err = CallAccount(ctx, cfg, "quality-probe/"+alias+"/"+model, account, ch.Prompt)
			cancel()
		}
		r := AccountResult{ID: Secret()[:12], Batch: batch, Account: account, Model: model, Prompt: "fingerprint-sample", PromptName: "模型指纹采样", Time: time.Now(), Answer: answer, Tokens: tokens, Verdict: "passed", ExpectedCount: ch.ExpectedCount}
		if err != nil {
			r.Verdict = "unavailable"
			r.Error = err.Error()
			issue = err.Error()
		}
		if len(r.Answer) > 8192 {
			r.Answer = r.Answer[:8192]
		}
		s.mu.Lock()
		s.addResult(r)
		if e := s.store.Save(s.state); e != nil {
			s.health = e.Error()
		}
		s.mu.Unlock()
		if err != nil {
			break
		}
		outputs = append(outputs, fingerprint.Output{Text: answer, ExpectedCount: ch.ExpectedCount})
	}
	// Even when one request failed, the local runner reports the pinned
	// detector version. An incomplete batch is NEVER evidence of a mismatch.
	report := runner.Evaluate(outputs, expected)
	if len(outputs) != 3 {
		report.Verdict = "indeterminate"
		report.UsedOutputs = len(outputs)
		if issue != "" {
			report.Diagnostic = "采样失败：" + issue
		}
	}
	now := time.Now()
	s.mu.Lock()
	hold, ok = s.state.Holds[account]
	if !ok || hold.Risk != "pending" {
		s.mu.Unlock()
		return
	}
	classifyHold(&hold, report, now)
	s.state.Holds[account] = hold
	if t := s.state.AccountTargets[accountTargetID(account, model)]; t != nil {
		t.State = phaseForRisk(hold.Risk)
		t.NextCheckAt = hold.NextCheckAt
		t.Reason = hold.Reason
		t.FingerprintVersion = report.Version
	}
	s.addResult(AccountResult{ID: Secret()[:12], Batch: batch, Account: account, Model: model, Prompt: "fingerprint", PromptName: "指纹复核结论", Verdict: hold.Risk, Time: now, Fingerprint: &report})
	if err := s.saveLocked(); err != nil {
		s.health = err.Error()
	}
	s.mu.Unlock()
}

// resuming an interrupted pending-fingerprint stage never re-runs the third
// objective check. Only one account request batch can be active at a time.
func (s *Service) TriggerPendingFingerprint(account string) error {
	s.mu.Lock()
	hold, ok := s.state.Holds[account]
	if !ok || hold.Risk != "pending" {
		s.mu.Unlock()
		return errors.New("账号无待复核状态")
	}
	if s.accountProbeActive {
		s.mu.Unlock()
		return errors.New("检测服务繁忙")
	}
	if s.state.Config.GatewayURL == "" || s.state.Config.GatewayKey == "" {
		s.mu.Unlock()
		return errors.New("尚未配置网关")
	}
	s.accountProbeActive = true
	s.wg.Add(1)
	active := s.state.Route.AutoApply
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); s.accountProbeActive = false; s.mu.Unlock() }()
		if active {
			ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
			_, err := s.ApplyRouting(ctx, false)
			cancel()
			if err != nil {
				s.noteSchedulerError(err)
				return
			}
			if !s.routeHasHold(account) {
				return
			}
		}
		s.collectFingerprint(s.ctx, account, hold.Model)
	}()
	return nil
}
func (s *Service) configureTargetFingerprint(account, model, expected string) error {
	if expected != "" {
		if strings.ContainsAny(expected, "\r\n") || len(expected) > 128 {
			return errors.New("指纹预期模型无效")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.state.AccountTargets[accountTargetID(account, model)]
	if t == nil {
		return errors.New("监测目标不存在")
	}
	if _, ok := s.state.Holds[account]; ok {
		return errors.New("隔离中不能修改指纹预期模型")
	}
	t.FingerprintExpected = expected
	return s.saveLocked()
}
