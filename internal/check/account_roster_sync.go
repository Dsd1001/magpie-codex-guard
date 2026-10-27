package check

import (
	"errors"
	"sort"
	"time"
)

// AccountRosterSync describes a safe, credential-free monitoring update.
// Removed sign-ins remain as explicitly marked missing targets: their
// existing holds, timestamps, history, and expected reference are untouched.
type AccountRosterSync struct {
	LiveCount int `json:"live_count"`
	Added     int `json:"added"`
	Missing   int `json:"missing"`
	Restored  int `json:"restored"`
}

// ConfigureAccountAutoSync is opt-in because each newly discovered login can
// consume quota. It never grants production routing permissions by itself.
func (s *Service) ConfigureAccountAutoSync(enabled bool, confirm string) error {
	if enabled && confirm != "AUTO_SYNC_CODEX_ACCOUNTS" {
		return errors.New("启用新账号自动检测需要明确确认")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state.Route.AutoSyncAccounts
	s.state.Route.AutoSyncAccounts = enabled
	if err := s.saveLocked(); err != nil {
		s.state.Route.AutoSyncAccounts = previous
		return err
	}
	return nil
}

// SyncLiveAccountTargets refreshes only monitoring targets. It does NOT edit
// caller-keys.json, quarantine Holds, route baselines, or the expected count.
// A deleted (possibly held) account is retained as a tombstone, with a missing
// label and no auto probes. Reappearing IDs retain their original hold state.
func (s *Service) SyncLiveAccountTargets() (AccountRosterSync, error) {
	dir, err := MagpieDir()
	if err != nil {
		return AccountRosterSync{}, err
	}
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return AccountRosterSync{}, err
	}
	live := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		live[a.ID] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive {
		return AccountRosterSync{}, errors.New("检测运行中，稍后重试账号同步")
	}
	models := map[string]bool{}
	for _, t := range s.state.AccountTargets {
		if t != nil && t.Enabled && validateAccountModel(t.Model) == nil {
			models[t.Model] = true
		}
	}
	if len(models) == 0 {
		return AccountRosterSync{}, errors.New("先添加至少一个已启用的 Codex 监测模型")
	}
	modelIDs := make([]string, 0, len(models))
	for m := range models {
		modelIDs = append(modelIDs, m)
	}
	sort.Strings(modelIDs)
	result := AccountRosterSync{LiveCount: len(accounts)}
	old := make(map[string]*AccountTarget, len(s.state.AccountTargets))
	for k, t := range s.state.AccountTargets {
		if t == nil {
			continue
		}
		copy := *t
		old[k] = &copy
		present := live[t.Account]
		if !present {
			result.Missing++
		}
		if t.Missing && present {
			result.Restored++
		}
		t.Missing = !present
	}
	for _, a := range accounts {
		for _, model := range modelIDs {
			if !matchesAccountModel(a, model) {
				continue
			}
			id := accountTargetID(a.ID, model)
			if s.state.AccountTargets[id] != nil {
				continue
			}
			t := &AccountTarget{
				Account: a.ID, Model: model, Enabled: true, State: "unverified",
			}
			if s.effectiveAutoPromptPolicyLocked().FingerprintMode == FingerprintPeriodic {
				t.NextFingerprintAt = time.Now().Add(24 * time.Hour)
			}
			s.state.AccountTargets[id] = t
			result.Added++
		}
	}
	modified := result.Added > 0 || result.Restored > 0
	if !modified {
		for k, t := range s.state.AccountTargets {
			if old[k] != nil && old[k].Missing != t.Missing {
				modified = true
				break
			}
		}
	}
	if modified {
		if err := s.saveLocked(); err != nil {
			s.state.AccountTargets = old
			return AccountRosterSync{}, err
		}
	}
	return result, nil
}
