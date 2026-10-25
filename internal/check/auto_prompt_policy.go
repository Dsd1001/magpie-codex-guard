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
	Configured      bool     `json:"configured"`
	Rotate          bool     `json:"rotate"`
	PromptIDs       []string `json:"prompt_ids"`
	FingerprintMode string   `json:"fingerprint_mode"` // after_failures | periodic_24h | objective_rotation | off
}

const (
	FingerprintOnFailure = "after_failures"
	FingerprintPeriodic  = "periodic_24h"
	FingerprintObjective = "objective_rotation"
	FingerprintOff       = "off"
)

func effectiveFingerprintMode(mode string) string {
	if mode == "" {
		return FingerprintOnFailure
	}
	return mode
}

func (s *Service) eligibleAutoPromptsLocked() []Prompt {
	var prompts []Prompt
	for _, prompt := range Prompts {
		if prompt.Automatic && prompt.Kind != "fingerprint" {
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
			PromptIDs:       slices.Clone(policy.PromptIDs),
			FingerprintMode: effectiveFingerprintMode(policy.FingerprintMode),
		}
	}
	// Backward compatible: existing installations still use all enabled
	// auto questions until the operator saves their own selection.
	eligible := s.eligibleAutoPromptsLocked()
	ids := make([]string, 0, len(eligible))
	for _, prompt := range eligible {
		ids = append(ids, prompt.ID)
	}
	return AutoPromptPolicy{Configured: false, Rotate: true, PromptIDs: ids, FingerprintMode: effectiveFingerprintMode(policy.FingerprintMode)}
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
	if policy.FingerprintMode == FingerprintObjective {
		if prompt, ok := FindPrompt(FingerprintPromptID); ok {
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
		if _, held := s.state.Holds[target.Account]; held {
			// Changing the question bank must never erase the state or
			// next recheck time of an already quarantined account.
			continue
		}
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
// ConfigureAutoPrompts retains compatibility with callers that only change
// objective questions. They never silently disable fingerprint quarantine.
func (s *Service) ConfigureAutoPrompts(ids []string, rotate bool) error {
	return s.ConfigureDetectionPrompts(ids, rotate, "")
}

// The new objective_rotation mode is opt-in. Other fingerprint modes remain
// independent of objective grading and preserve their prior schedules.
func (s *Service) ConfigureDetectionPrompts(ids []string, rotate bool, fingerprintMode string) error {

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive || len(s.running) > 0 {
		return errors.New("有检测正在运行，请结束后再更新自动检测题库")
	}
	current := s.effectiveAutoPromptPolicyLocked()
	if fingerprintMode == "" {
		fingerprintMode = current.FingerprintMode
	}
	if fingerprintMode != FingerprintOnFailure && fingerprintMode != FingerprintPeriodic && fingerprintMode != FingerprintObjective && fingerprintMode != FingerprintOff {
		return errors.New("无效的指纹检测触发模式")
	}
	available := s.eligibleAutoPromptsLocked()
	if len(ids) == 0 && fingerprintMode != FingerprintObjective {
		return errors.New("自动检测题库至少需要选择一道支持自动判分的题目")
	}
	if fingerprintMode == FingerprintObjective && len(ids) > 0 && !rotate {
		return errors.New("指纹参与客观题轮换时，请开启按轮次轮换")
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
	desired := AutoPromptPolicy{
		Configured: true, Rotate: rotate, PromptIDs: slices.Clone(ids), FingerprintMode: fingerprintMode,
	}
	fingerprintChanged := current.FingerprintMode != desired.FingerprintMode
	objectiveChanged := current.Rotate != desired.Rotate ||
		!slices.Equal(current.PromptIDs, desired.PromptIDs) ||
		(fingerprintChanged && (current.FingerprintMode == FingerprintObjective || desired.FingerprintMode == FingerprintObjective))
	if !objectiveChanged && !fingerprintChanged && s.state.AutoPromptPolicy.Configured {
		return nil
	}
	before := s.state.AutoPromptPolicy
	var targets map[string]AccountTarget
	if objectiveChanged {
		targets = s.resetAutoPromptStreaksLocked()
	} else if fingerprintChanged {
		targets = make(map[string]AccountTarget, len(s.state.AccountTargets))
		for id, t := range s.state.AccountTargets {
			if t != nil {
				targets[id] = *t
			}
		}
	}
	s.state.AutoPromptPolicy = desired
	// Enabling a periodic job does not cause an immediate burst of 3 requests
	// per target. It becomes due after 24 hours, persisted across restarts.
	if fingerprintChanged && desired.FingerprintMode == FingerprintPeriodic {
		next := time.Now().Add(24 * time.Hour)
		for _, t := range s.state.AccountTargets {
			if t != nil {
				t.NextFingerprintAt = next
			}
		}
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
	if len(selected) == 0 && effectiveFingerprintMode(s.state.AutoPromptPolicy.FingerprintMode) != FingerprintObjective {
		selected = []string{"milk"}
	}
	s.state.AutoPromptPolicy.PromptIDs = selected
}
