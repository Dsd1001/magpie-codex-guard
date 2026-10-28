package check

import (
	"context"
	"errors"
	"sort"
	"time"
)

// ScheduleOneAccount has a single-flight guard across objective probes and
// three-sample fingerprint-as-objective checks. Persisted NextCheckAt does not
// reset on restarts; quarantined accounts only retest their held model.
func (s *Service) ScheduleOneAccount(now time.Time) error {
	return s.scheduleOneAccount(now, true)
}

// Under an unresolved route conflict normal read-only checks can continue,
// but a third failure must not create a NEW hold without the capability to
// synchronize production keys. Already isolated accounts can still recover.
func (s *Service) scheduleOneAccount(now time.Time, allowNewHolds bool) error {
	// Never repeatedly probe a deleted login. Its held account ID stays in
	// SQLite (tombstone) and in the route exclusion set until explicitly
	// retired; a future login with the same stable ID stays quarantined.
	dir, err := MagpieDir()
	if err != nil {
		return err
	}
	discovered, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, a := range discovered {
		live[a.ID] = true
	}
	s.mu.Lock()
	if !s.state.Route.ScheduleEnabled || s.accountProbeActive || s.state.Route.Pending {
		s.mu.Unlock()
		return nil
	}
	type candidate struct {
		account, model, prompt string
		priority               int
		due                    time.Time
	}
	candidates := []candidate{}
	prompts := s.activeAccountPromptsLocked()
	policy := s.effectiveAutoPromptPolicyLocked()
	rotate := policy.Rotate
	if len(prompts) == 0 {
		s.mu.Unlock()
		return errors.New("没有可自动判分的客观题")
	}
	for _, t := range s.state.AccountTargets {
		if t == nil || !t.Enabled || !live[t.Account] {
			continue
		}
		hold, held := s.state.Holds[t.Account]
		if !allowNewHolds && !held {
			// A reliable mismatch can create a hold, so no unheld target
			// may run while routing cannot safely isolate.
			continue
		}
		if held && hold.Model != t.Model {
			continue
		}
		due := t.NextCheckAt
		if held {
			due = hold.NextCheckAt
		}
		if !due.IsZero() && now.Before(due) {
			continue
		}
		prompt := selectAutomaticPrompt(*t, held, rotate, prompts)
		priority := 3
		if held {
			priority = 2
			if hold.ConfirmationPasses > 0 {
				priority = 0
			}
		} else if t.ConsecutiveFails > 0 || t.ConsecutiveUnavailable > 0 {
			priority = 1
		}
		candidates = append(candidates, candidate{account: t.Account, model: t.Model, prompt: prompt, due: due, priority: priority})
	}
	s.mu.Unlock()
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		if !a.due.Equal(b.due) {
			return a.due.Before(b.due)
		}
		if a.account != b.account {
			return a.account < b.account
		}
		return a.model < b.model
	})
	next := candidates[0]
	return s.TriggerAccount(next.account, next.model, next.prompt, false)
}
func selectAutomaticPrompt(t AccountTarget, isolated, rotate bool, prompts []Prompt) string {
	if len(prompts) == 0 {
		return ""
	}
	if (isolated || t.ConsecutiveFails > 0) && t.LastAutoPrompt != "" {
		for _, p := range prompts {
			if p.ID == t.LastAutoPrompt {
				return p.ID
			}
		}
	}
	if !rotate {
		return prompts[0].ID
	}
	return prompts[int(t.PromptRotation%uint64(len(prompts)))].ID
}

func (s *Service) StartAccountScheduler() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// On startup, reconcile persisted holds against Magpie before probing.
		for {
			s.schedulerTick(time.Now())
			s.mu.Lock()
			interval := s.state.TimingPolicy.scan()
			s.mu.Unlock()
			timer := time.NewTimer(interval)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-s.scheduleWake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
}
func (s *Service) schedulerTick(now time.Time) {
	s.mu.Lock()
	syncAccounts := s.state.Route.AutoSyncAccounts
	s.mu.Unlock()
	if syncAccounts {
		if _, err := s.SyncLiveAccountTargets(); err != nil &&
			err.Error() != "检测运行中，稍后重试账号同步" {
			s.noteSchedulerError(err)
		}
	}
	s.mu.Lock()
	auto := s.state.Route.AutoApply
	pending := s.state.Route.Pending
	s.mu.Unlock()
	allowNewHolds := true
	if auto && !pending {
		ctx, cancel := context.WithTimeout(s.ctx, 9*time.Second)
		_, err := s.ApplyRouting(ctx, false)
		cancel()
		if err != nil {
			s.noteSchedulerError(err)
			// Never overwrite out-of-band edits. Only permit read-only
			// checks when the LIVE gateway still excludes EVERY held account.
			// Pending and unsafe quarantines remain blocked.
			if checkErr := s.verifySafeReadOnlyProbes(); checkErr != nil {
				s.noteSchedulerError(checkErr)
				return
			}
			allowNewHolds = false
		}
	}
	if err := s.scheduleOneAccount(now, allowNewHolds); err != nil {
		s.noteSchedulerError(err)
	}
}
func (s *Service) noteSchedulerError(err error) {
	if err == nil {
		return
	}
	message := err.Error()
	if len(message) > 280 {
		message = message[:280]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Route.LastError == message {
		return
	}
	s.state.Route.LastError = message
	if e := s.store.Save(s.state); e != nil {
		s.health = e.Error()
	}
}

// Enabling the scheduled probes does not enable production-key mutation.
func (s *Service) AccountScheduleEnabled(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state.Route.ScheduleEnabled
	s.state.Route.ScheduleEnabled = enabled
	if err := s.store.Save(s.state); err != nil {
		s.state.Route.ScheduleEnabled = old
		return err
	}
	return nil
}
