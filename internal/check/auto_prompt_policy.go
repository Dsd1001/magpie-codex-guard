package check

import (
	"errors"
	"slices"
	"time"
)

// AutoPromptPolicy is independent of the production routing controller.
// Configured distinguishes existing installs (legacy: all eligible prompts
// rotate) from an explicitly saved allowlist.
type AutoPromptPolicy struct {
	Configured bool     `json:"configured"`
	Rotate     bool     `json:"rotate"`
	PromptIDs  []string `json:"prompt_ids"`
}

func (s *Service) eligibleAutoPromptsLocked() []Prompt {
	var prompts []Prompt
	for _, prompt := range Prompts {
		if prompt.Automatic {
			prompts = append(prompts, prompt)
		}
	}
	for _, prompt := range s.state.CustomPrompts {
		if validAutomaticCustom(prompt) {
			prompts = append(prompts, prompt)
		}
	}
	return prompts
}

func (s *Service) effectiveAutoPromptPolicyLocked() AutoPromptPolicy {
	policy := s.state.AutoPromptPolicy
	if policy.Configured {
		return AutoPromptPolicy{
			Configured: true, Rotate: policy.Rotate,
			PromptIDs: slices.Clone(policy.PromptIDs),
		}
	}
	// Backward compatible: existing installations still use all enabled
	// auto questions until the operator saves their own selection.
	eligible := s.eligibleAutoPromptsLocked()
	ids := make([]string, 0, len(eligible))
	for _, prompt := range eligible {
		ids = append(ids, prompt.ID)
	}
	return AutoPromptPolicy{Configured: false, Rotate: true, PromptIDs: ids}
}

func (s *Service) AutoPromptSettings() AutoPromptPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effectiveAutoPromptPolicyLocked()
}

func (s *Service) activeAccountPromptsLocked() []Prompt {
	policy := s.effectiveAutoPromptPolicyLocked()
	available := make(map[string]Prompt)
	for _, prompt := range s.eligibleAutoPromptsLocked() {
		available[prompt.ID] = prompt
	}
	selected := make([]Prompt, 0, len(policy.PromptIDs))
	for _, id := range policy.PromptIDs {
		if prompt, exists := available[id]; exists {
			selected = append(selected, prompt)
		}
	}
	return selected
}

// resetAutoPromptStreaksLocked clears results collected under the old policy.
// It does NOT remove quarantine holds or update production gateway keys.
// A new check can run on the next scheduler tick under the new rubric.
func (s *Service) resetAutoPromptStreaksLocked() map[string]AccountTarget {
	before := make(map[string]AccountTarget, len(s.state.AccountTargets))
	for id, target := range s.state.AccountTargets {
		if target == nil {
			continue
		}
		before[id] = *target
		target.ConsecutiveFails = 0
		target.ConsecutivePasses = 0
		target.LastAutoPrompt = ""
		target.PromptRotation = 0
		target.CheckedAt = time.Time{}
		target.NextCheckAt = time.Time{}
		target.State = "unverified"
		target.Reason = "自动题库设置已改变，需重新确认检测结果"
	}
	return before
}

// ConfigureAutoPrompts validates every selected ID server-side. Manual-only,
// deleted or malformed questions can never enter the automatic quarantine
// scheduler even when a client bypasses the browser UI.
func (s *Service) ConfigureAutoPrompts(ids []string, rotate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive || len(s.running) > 0 {
		return errors.New("有检测正在运行，请结束后再更新自动检测题库")
	}
	available := s.eligibleAutoPromptsLocked()
	if len(ids) == 0 {
		return errors.New("自动检测题库至少需要选择一道支持自动判分的题目")
	}
	if len(ids) > len(available) {
		return errors.New("自动检测题库包含重复或不可用的题目")
	}
	known := make(map[string]bool, len(available))
	for _, prompt := range available {
		known[prompt.ID] = true
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !known[id] {
			return errors.New("自动检测题库包含手动题、未知题或已经停用的题目")
		}
		if seen[id] {
			return errors.New("自动检测题库包含重复题目")
		}
		seen[id] = true
	}
	current := s.effectiveAutoPromptPolicyLocked()
	desired := AutoPromptPolicy{
		Configured: true, Rotate: rotate,
		PromptIDs: slices.Clone(ids),
	}
	policyChanged := current.Rotate != desired.Rotate || !slices.Equal(current.PromptIDs, desired.PromptIDs)
	if !policyChanged && s.state.AutoPromptPolicy.Configured {
		return nil
	}
	before := s.state.AutoPromptPolicy
	s.state.AutoPromptPolicy = desired
	var targets map[string]AccountTarget
	if policyChanged {
		targets = s.resetAutoPromptStreaksLocked()
	}
	if err := s.store.Save(s.state); err != nil {
		s.state.AutoPromptPolicy = before
		s.restoreTargetsLocked(targets)
		return err
	}
	return nil
}

// reconcileAutoPromptPolicyLocked removes a custom prompt when it is deleted
// or switched to manual mode. A configured allowlist never silently expands
// to include new questions; when it becomes empty, use the safe built-in milk
// question rather than issuing a blind/ungraded probe.
func (s *Service) reconcileAutoPromptPolicyLocked() {
	if !s.state.AutoPromptPolicy.Configured {
		return
	}
	known := map[string]bool{}
	for _, p := range s.eligibleAutoPromptsLocked() {
		known[p.ID] = true
	}
	var selected []string
	for _, id := range s.state.AutoPromptPolicy.PromptIDs {
		if known[id] {
			selected = append(selected, id)
		}
	}
	if len(selected) == 0 {
		selected = []string{"milk"}
	}
	s.state.AutoPromptPolicy.PromptIDs = selected
}
