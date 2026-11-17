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

// Detection is independent of production whitelist edits.
func (s *Service) scheduleOneAccount(now time.Time, _ bool) error {
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
	if !s.state.Route.ScheduleEnabled || s.accountProbeActive {
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
		if t == nil || !t.Enabled || !live[t.Account] || modelProvider(t.Model) != "codex" {
			continue
		}
		hold, held := s.state.Holds[t.Account]
		if held && hold.Model != t.Model {
			continue
		}
		due := t.NextCheckAt
		if held {
			due = hold.NextCheckAt
			if t.State == "connection_error" && t.NextCheckAt.After(due) {
				due = t.NextCheckAt
			}
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
	// An incomplete fingerprint batch must retry the same question, even
	// when rotating a mixed automatic question bank.
	if t.ConsecutiveUnavailable > 0 && t.UnavailablePrompt != "" {
		for _, p := range prompts {
			if p.ID == t.UnavailablePrompt {
				return p.ID
			}
		}
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
	if _, err := s.SyncLiveAccountTargets(); err != nil {
		s.noteSchedulerError(err)
	}
	s.mu.Lock()
	auto := s.state.Route.AutoApply
	awaiting := s.state.Route.AwaitingDetection
	s.mu.Unlock()
	if auto && !awaiting {
		ctx, cancel := context.WithTimeout(s.ctx, 9*time.Second)
		_, err := s.applyAutomaticRouting(ctx)
		cancel()
		if err != nil {
			s.noteSchedulerError(err)
		}
	}
	// File contention or an administrator editing account picks must not
	// prevent probes, isolation decisions, or recovery checks from running.
	if err := s.scheduleOneAccount(now, true); err != nil {
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
