package check

import (
	"context"
	"errors"
	"sort"
	"time"
)

// ScheduleOneAccount has a single-flight guard across objective probes and
// three-sample fingerprint checks. Persisted NextCheckAt does not reset on
// process restarts. A pending fingerprint is prioritized ahead of healthy
// hourly probes; an isolated account's held model is the only recovery target.
func (s *Service) ScheduleOneAccount(now time.Time) error {
	s.mu.Lock()
	if !s.state.Route.ScheduleEnabled || s.accountProbeActive || s.state.Route.Pending {
		s.mu.Unlock()
		return nil
	}
	type candidate struct {
		account, model, prompt string
		priority               int
		due                    time.Time
		pending                bool
	}
	candidates := []candidate{}
	prompts := s.activeAccountPromptsLocked()
	rotate := s.effectiveAutoPromptPolicyLocked().Rotate
	if len(prompts) == 0 {
		s.mu.Unlock()
		return errors.New("没有可自动判分的客观题")
	}
	for _, t := range s.state.AccountTargets {
		if t == nil || !t.Enabled {
			continue
		}
		hold, held := s.state.Holds[t.Account]
		if held && hold.Model != t.Model {
			continue
		}
		if held && hold.Risk == "pending" {
			// Retry after transient runtime errors without forgetting the hold.
			if hold.NextCheckAt.IsZero() || !now.Before(hold.NextCheckAt) {
				candidates = append(candidates, candidate{account: t.Account, model: t.Model, pending: true, priority: 0, due: hold.NextCheckAt})
			}
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
		} else if t.ConsecutiveFails > 0 {
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
	if next.pending {
		return s.TriggerPendingFingerprint(next.account)
	}
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
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		// On startup, reconcile persisted holds against Magpie before probing.
		s.schedulerTick(time.Now())
		for {
			select {
			case <-s.ctx.Done():
				return
			case now := <-tick.C:
				s.schedulerTick(now)
			}
		}
	}()
}
func (s *Service) schedulerTick(now time.Time) {
	s.mu.Lock()
	auto := s.state.Route.AutoApply
	pending := s.state.Route.Pending
	s.mu.Unlock()
	if auto && !pending {
		ctx, cancel := context.WithTimeout(s.ctx, 9*time.Second)
		_, err := s.ApplyRouting(ctx, false)
		cancel()
		if err != nil {
			s.noteSchedulerError(err)
			// A production-routing conflict must not proceed as if isolated.
			return
		}
	}
	if err := s.ScheduleOneAccount(now); err != nil {
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
