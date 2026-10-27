package check

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	maxCustomPrompts  = 40
	maxPromptName     = 100
	maxPromptText     = 24000
	maxPromptGuidance = 4000
	maxAnswers        = 8
	maxAnswerLength   = 240
)

// Automatic custom prompts must have a deterministic exact-answer rubric.
// Creative/open-ended questions can be added in manual mode without any key.
func validateCustomPrompt(name, promptText, guidance string, automatic bool, answers []string) ([]string, error) {
	if strings.TrimSpace(name) == "" || len(name) > maxPromptName {
		return nil, errors.New("题目名称必须填写，长度不超过 100 字节")
	}
	if strings.TrimSpace(promptText) == "" || len(promptText) > maxPromptText {
		return nil, errors.New("题目内容必须填写，长度不超过 24000 字节")
	}
	if len(guidance) > maxPromptGuidance {
		return nil, errors.New("人工判断参考不超过 4000 字节")
	}
	for _, field := range []string{name, promptText, guidance} {
		for _, r := range field {
			if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
				return nil, errors.New("题目内容不能包含控制字符")
			}
		}
	}
	if len(answers) > maxAnswers {
		return nil, fmt.Errorf("最多配置 %d 个等价正确答案", maxAnswers)
	}
	clean := make([]string, 0, len(answers))
	for _, a := range answers {
		a = strings.TrimSpace(a)
		if a == "" || len(a) > maxAnswerLength || strings.ContainsAny(a, "\r\n\x00") {
			return nil, errors.New("每个预期答案必须为单行且不超过 240 字节")
		}
		if !slices.ContainsFunc(clean, func(x string) bool { return normalizeExpectedAnswer(x) == normalizeExpectedAnswer(a) }) {
			clean = append(clean, a)
		}
	}
	if automatic && len(clean) == 0 {
		return nil, errors.New("自动检测必须配置至少一个明确的预期正确答案")
	}
	return clean, nil
}

func normalizeExpectedAnswer(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(s)), " "))
}

func validAutomaticCustom(p Prompt) bool {
	if !p.Custom || !p.Automatic || len(p.ExpectedAnswers) == 0 || len(p.ExpectedAnswers) > maxAnswers {
		return false
	}
	_, err := validateCustomPrompt(p.Name, p.Text, p.Guidance, true, p.ExpectedAnswers)
	return err == nil
}

// gradeConfiguredPrompt is used ONLY for controlled automatic questions.
// Exact normalized comparison (not substring search, fuzzy scoring or LLM
// opinion) prevents a stray number from being treated as a passing answer.
func gradeConfiguredPrompt(p Prompt, answer string) string {
	if !p.Custom {
		return Grade(p.ID, answer)
	}
	if !validAutomaticCustom(p) {
		return "manual"
	}
	got := normalizeExpectedAnswer(answer)
	for _, expected := range p.ExpectedAnswers {
		if got == normalizeExpectedAnswer(expected) {
			return "passed"
		}
	}
	return "failed"
}

func (s *Service) findPromptLocked(id string) (Prompt, bool) {
	if p, ok := FindPrompt(id); ok {
		return p, true
	}
	for _, p := range s.state.CustomPrompts {
		if p.ID == id {
			p.Custom = true
			p.Kind = "objective"
			p.Automatic = validAutomaticCustom(p)
			return p, true
		}
	}
	return Prompt{}, false
}

func (s *Service) promptCatalogLocked() []Prompt {
	list := append([]Prompt{}, Prompts...)
	for _, p := range s.state.CustomPrompts {
		p.Custom = true
		p.Kind = "objective"
		p.Automatic = validAutomaticCustom(p)
		list = append(list, p)
	}
	return list
}

func (s *Service) PromptCatalog() []Prompt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.promptCatalogLocked()
}

func (s *Service) AddCustomPrompt(name, promptText, guidance string, automatic bool, answers []string) (Prompt, error) {
	clean, err := validateCustomPrompt(name, promptText, guidance, automatic, answers)
	if err != nil {
		return Prompt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive || len(s.running) > 0 {
		return Prompt{}, errors.New("检测正在执行，请完成后再修改题库")
	}
	if len(s.state.CustomPrompts) >= maxCustomPrompts {
		return Prompt{}, errors.New("自定义题库最多保存 40 道题")
	}
	p := Prompt{
		ID: "custom-" + Secret()[:16], Kind: "objective", Name: strings.TrimSpace(name),
		Text: promptText, Guidance: guidance, Automatic: automatic, Custom: true,
		ExpectedAnswers: clean,
	}
	s.state.CustomPrompts = append(s.state.CustomPrompts, p)
	if err := s.store.Save(s.state); err != nil {
		s.state.CustomPrompts = s.state.CustomPrompts[:len(s.state.CustomPrompts)-1]
		return Prompt{}, err
	}
	return p, nil
}

// Editing an automatic rubric invalidates past verdict streaks from that
// question, but deliberately retains quarantine hold until fresh passes.
func (s *Service) resetTargetsForPromptLocked(id string) map[string]AccountTarget {
	before := map[string]AccountTarget{}
	for k, target := range s.state.AccountTargets {
		if target == nil || target.LastAutoPrompt != id {
			continue
		}
		before[k] = *target
		target.ConsecutiveFails = 0
		target.ConsecutivePasses = 0
		target.LastAutoPrompt = ""
		target.CheckedAt = time.Time{}
		target.NextCheckAt = time.Time{}
		target.State = "unverified"
		target.Reason = "自动检测题目配置已变更，等待重新核验"
		target.PromptRotation = 0
	}
	return before
}

func (s *Service) restoreTargetsLocked(before map[string]AccountTarget) {
	for id, t := range before {
		if target := s.state.AccountTargets[id]; target != nil {
			*target = t
		}
	}
}

func (s *Service) UpdateCustomPrompt(id, name, promptText, guidance string, automatic bool, answers []string) error {
	clean, err := validateCustomPrompt(name, promptText, guidance, automatic, answers)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive || len(s.running) > 0 {
		return errors.New("检测正在执行，请完成后再修改题库")
	}
	for i := range s.state.CustomPrompts {
		if s.state.CustomPrompts[i].ID != id {
			continue
		}
		before := s.state.CustomPrompts[i]
		updated := Prompt{
			ID: id, Kind: "objective", Name: strings.TrimSpace(name), Text: promptText,
			Guidance: guidance, Automatic: automatic, Custom: true, ExpectedAnswers: clean,
		}
		rubricChanged := before.Text != updated.Text || before.Automatic != updated.Automatic ||
			!slices.Equal(before.ExpectedAnswers, updated.ExpectedAnswers)
		if rubricChanged {
			for _, hold := range s.state.Holds {
				if hold.Prompt == id {
					return errors.New("该题目正用于隔离恢复，解除隔离之前不能修改判分规则")
				}
			}
		}
		previousSelection := s.state.AutoPromptPolicy
		s.state.CustomPrompts[i] = updated
		var targets map[string]AccountTarget
		if rubricChanged {
			targets = s.resetTargetsForPromptLocked(id)
		}
		s.reconcileAutoPromptPolicyLocked()
		if err := s.store.Save(s.state); err != nil {
			s.state.CustomPrompts[i] = before
			s.state.AutoPromptPolicy = previousSelection
			s.restoreTargetsLocked(targets)
			return err
		}
		return nil
	}
	return errors.New("找不到自定义题目；内置题目不可编辑")
}

func (s *Service) DeleteCustomPrompt(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive || len(s.running) > 0 {
		return errors.New("检测正在执行，请完成后再修改题库")
	}
	for i, p := range s.state.CustomPrompts {
		if p.ID != id {
			continue
		}
		for _, hold := range s.state.Holds {
			if hold.Prompt == id {
				return errors.New("该题目正用于隔离恢复，解除隔离之前不能删除")
			}
		}
		before := append([]Prompt{}, s.state.CustomPrompts...)
		previousSelection := s.state.AutoPromptPolicy
		targets := s.resetTargetsForPromptLocked(id)
		s.state.CustomPrompts = append(s.state.CustomPrompts[:i:i], s.state.CustomPrompts[i+1:]...)
		s.reconcileAutoPromptPolicyLocked()
		if err := s.store.Save(s.state); err != nil {
			s.state.CustomPrompts = before
			s.state.AutoPromptPolicy = previousSelection
			s.restoreTargetsLocked(targets)
			return err
		}
		return nil
	}
	return errors.New("找不到自定义题目；内置题目不可删除")
}
