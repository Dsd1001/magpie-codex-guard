package check

import (
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestFreshInstallDefaultsToFingerprintDetectionWithoutRouting(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	policy := s.AutoPromptSettings()
	if !policy.Configured || !slices.Equal(policy.PromptIDs, []string{FingerprintPromptID}) {
		t.Fatalf("new installation must use fingerprint as default objective: %+v", policy)
	}
	if s.state.Route.ScheduleEnabled || s.state.Route.AutoApply {
		t.Fatal("selecting a default question must not enable automatic scheduling or production routing")
	}
	s.Close()

	reopened, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	policy = reopened.AutoPromptSettings()
	if !policy.Configured || !slices.Equal(policy.PromptIDs, []string{FingerprintPromptID}) {
		t.Fatalf("fresh-install fingerprint selection not persisted: %+v", policy)
	}
}

func TestLegacyUnconfiguredQuestionPoolAndHoldSurviveUpgrade(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an alpha.23 installation that never explicitly saved its bank.
	s.state.AutoPromptPolicy = AutoPromptPolicy{
		Configured: false, Rotate: true, PromptIDs: []string{"milk"},
		FingerprintMode: FingerprintOff,
	}
	when := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	s.state.Holds["legacy"] = QuarantineHold{
		Account: "legacy", Model: "codex/gpt-6.1-sol",
		Prompt: "milk", Risk: "isolated", NextCheckAt: when,
	}
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	reopened, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	policy := reopened.AutoPromptSettings()
	if policy.Configured || !slices.Equal(policy.PromptIDs, []string{"milk"}) {
		t.Fatalf("existing legacy question pool was silently changed: %+v", policy)
	}
	if h := reopened.state.Holds["legacy"]; h.Prompt != "milk" || !h.NextCheckAt.Equal(when) {
		t.Fatalf("existing hold changed during upgrade: %+v", h)
	}
}

func TestCustomQuestionSelectionPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureAutoPrompts([]string{"milk"}, false); err != nil {
		t.Fatal(err)
	}
	s.Close()

	reopened, err := New(dir, filepath.Join(dir, "gate.js"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	policy := reopened.AutoPromptSettings()
	if !policy.Configured || policy.Rotate || !slices.Equal(policy.PromptIDs, []string{"milk"}) {
		t.Fatalf("explicit question selection was changed: %+v", policy)
	}
}
