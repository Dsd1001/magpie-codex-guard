package check

import (
	"sort"
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

// Account discovery is automatic. Retain the old endpoint for older clients.
func (s *Service) ConfigureAccountAutoSync(_ bool, _ string) error { return nil }

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
	models := map[string]bool{}
	for _, t := range s.state.AccountTargets {
		if t != nil && t.Enabled && modelProvider(t.Model) == "codex" && validateAccountModel(t.Model) == nil {
			models[t.Model] = true
		}
	}
	modelIDs := make([]string, 0, len(models))
	for m := range models {
		modelIDs = append(modelIDs, m)
	}
	sort.Strings(modelIDs)
	result := AccountRosterSync{LiveCount: len(routingKnownIDs(accounts))}
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
		if accountProvider(a) != "codex" {
			continue
		}
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
