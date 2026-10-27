package check

import (
	"errors"
	"fmt"
	"time"
)

// TimingPolicy is persisted in seconds. All intervals are based on completed
// checks; changing a policy does not silently alter already scheduled holds.
type TimingPolicy struct {
	NormalSeconds           int `json:"normal_seconds"`
	SuspectSeconds          int `json:"suspect_seconds"`
	QuarantineFirstSeconds  int `json:"quarantine_first_seconds"`
	QuarantineRepeatSeconds int `json:"quarantine_repeat_seconds"`
	RecoverySeconds         int `json:"recovery_seconds"`
	UnavailableSeconds      int `json:"unavailable_seconds"`
	RequestTimeoutSeconds   int `json:"request_timeout_seconds"`
	ScanSeconds             int `json:"scan_seconds"`
}

func DefaultTimingPolicy() TimingPolicy {
	return TimingPolicy{
		NormalSeconds: 1800, SuspectSeconds: 120,
		QuarantineFirstSeconds: 21600, QuarantineRepeatSeconds: 86400,
		RecoverySeconds: 120, UnavailableSeconds: 1800,
		RequestTimeoutSeconds: 180, ScanSeconds: 60,
	}
}

func (p TimingPolicy) validate() error {
	for _, rule := range []struct {
		name            string
		value, min, max int
	}{
		{"正常检测", p.NormalSeconds, 60, 604800},
		{"错误复测", p.SuspectSeconds, 30, 86400},
		{"隔离首次复测", p.QuarantineFirstSeconds, 60, 2592000},
		{"隔离后续复测", p.QuarantineRepeatSeconds, 60, 2592000},
		{"恢复确认", p.RecoverySeconds, 30, 86400},
		{"请求不可用重试", p.UnavailableSeconds, 30, 604800},
		{"单次请求超时", p.RequestTimeoutSeconds, 10, 900},
		{"调度扫描", p.ScanSeconds, 10, 3600},
	} {
		if rule.value < rule.min || rule.value > rule.max {
			return fmt.Errorf("%s必须在 %d 到 %d 秒之间", rule.name, rule.min, rule.max)
		}
	}
	return nil
}
func (p TimingPolicy) normal() time.Duration  { return time.Duration(p.NormalSeconds) * time.Second }
func (p TimingPolicy) suspect() time.Duration { return time.Duration(p.SuspectSeconds) * time.Second }
func (p TimingPolicy) first() time.Duration {
	return time.Duration(p.QuarantineFirstSeconds) * time.Second
}
func (p TimingPolicy) repeat() time.Duration {
	return time.Duration(p.QuarantineRepeatSeconds) * time.Second
}
func (p TimingPolicy) recovery() time.Duration { return time.Duration(p.RecoverySeconds) * time.Second }
func (p TimingPolicy) unavailable() time.Duration {
	return time.Duration(p.UnavailableSeconds) * time.Second
}
func (p TimingPolicy) timeout() time.Duration {
	return time.Duration(p.RequestTimeoutSeconds) * time.Second
}
func (p TimingPolicy) scan() time.Duration { return time.Duration(p.ScanSeconds) * time.Second }

func (s *Service) timingForTargetLocked(t *AccountTarget) TimingPolicy {
	if t != nil && t.TimingOverride != nil {
		p := *t.TimingOverride
		p.ScanSeconds = s.state.TimingPolicy.ScanSeconds // scan loop is global
		return p
	}
	return s.state.TimingPolicy
}

// Timeout is captured at request start. Changes apply to subsequent requests.
func (s *Service) requestTimeout(account, model string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timingForTargetLocked(s.state.AccountTargets[accountTargetID(account, model)]).timeout()
}

func (s *Service) notifyScheduleChangedLocked() {
	if s.scheduleWake != nil {
		select {
		case s.scheduleWake <- struct{}{}:
		default:
		}
	}
}

// ConfigureTimingPolicy changes the global policy or a single target override.
// inherit clears the target override. With reschedule=false (the safe default),
// existing NextCheckAt values are unchanged, including active quarantine.
// With reschedule=true outstanding deadlines are recalculated but holds,
// evidence and recovery counts are never cleared.
func (s *Service) ConfigureTimingPolicy(policy TimingPolicy, account, model string, inherit, reschedule bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountProbeActive || len(s.running) > 0 {
		return errors.New("有检测正在执行，请结束后再修改检测时间")
	}
	if (account == "") != (model == "") {
		return errors.New("必须同时指定账号和模型")
	}
	if !inherit || account == "" {
		if err := policy.validate(); err != nil {
			return err
		}
	}
	if account == "" && inherit {
		return errors.New("全局时间策略不能继承")
	}
	var target *AccountTarget
	if account != "" {
		target = s.state.AccountTargets[accountTargetID(account, model)]
		if target == nil {
			return errors.New("监测目标不存在")
		}
	}
	oldPolicy := s.state.TimingPolicy
	oldTargets := make(map[string]AccountTarget, len(s.state.AccountTargets))
	for id, t := range s.state.AccountTargets {
		if t != nil {
			oldTargets[id] = *t
		}
	}
	oldHolds := make(map[string]QuarantineHold, len(s.state.Holds))
	for id, h := range s.state.Holds {
		oldHolds[id] = h
	}
	if target != nil {
		if inherit {
			target.TimingOverride = nil
		} else {
			p := policy
			p.ScanSeconds = s.state.TimingPolicy.ScanSeconds
			target.TimingOverride = &p
		}
	} else {
		s.state.TimingPolicy = policy
	}
	if reschedule {
		now := time.Now()
		for _, t := range s.state.AccountTargets {
			if t != nil && (target == nil || t == target) {
				s.rescheduleTargetLocked(t, now)
			}
		}
	}
	if err := s.saveLocked(); err != nil {
		s.state.TimingPolicy = oldPolicy
		s.restoreTargetsLocked(oldTargets)
		s.state.Holds = oldHolds
		return err
	}
	if target == nil && oldPolicy.ScanSeconds != policy.ScanSeconds {
		s.notifyScheduleChangedLocked()
	}
	return nil
}

func (s *Service) rescheduleTargetLocked(t *AccountTarget, now time.Time) {
	p := s.timingForTargetLocked(t)
	if hold, held := s.state.Holds[t.Account]; held && hold.Model == t.Model {
		var anchor time.Time
		var interval time.Duration
		switch {
		case hold.ConfirmationPasses > 0:
			anchor, interval = t.CheckedAt, p.recovery()
		case !hold.FirstRecheckDone:
			anchor, interval = hold.Since, p.first()
		default:
			anchor, interval = t.CheckedAt, p.repeat()
		}
		if anchor.IsZero() {
			return
		}
		next := anchor.Add(interval)
		if next.Before(now) {
			next = now
		}
		hold.NextCheckAt = next
		t.NextCheckAt = next
		s.state.Holds[t.Account] = hold
		return
	}
	if t.CheckedAt.IsZero() {
		return
	}
	interval := p.normal()
	switch {
	case t.State == "unavailable":
		interval = p.unavailable()
	case t.ConsecutiveFails > 0:
		interval = p.suspect()
	}
	next := t.CheckedAt.Add(interval)
	if next.Before(now) {
		next = now
	}
	t.NextCheckAt = next
}
