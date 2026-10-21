package check

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// strictSubsequenceRemoval accepts only order-preserving deletions from a
// finite allowlist. Empty allowlists mean ALLOW ALL in Magpie and are never
// accepted here. Additions, reordering and duplicates require human review.
func strictSubsequenceRemoval(before, after []string) ([]string, bool) {
	if len(after) == 0 || len(after) >= len(before) {
		return nil, false
	}
	seen := map[string]bool{}
	for _, ref := range before {
		if seen[ref] {
			return nil, false
		}
		seen[ref] = true
	}
	pos, remaining := 0, map[string]bool{}
	for _, ref := range after {
		if remaining[ref] {
			return nil, false
		}
		remaining[ref] = true
		for pos < len(before) && before[pos] != ref {
			pos++
		}
		if pos == len(before) {
			return nil, false
		}
		pos++
	}
	removed := []string{}
	for _, ref := range before {
		if !remaining[ref] {
			removed = append(removed, ref)
		}
	}
	return removed, len(removed) > 0
}

func clonedScopes(input map[string][]string) map[string][]string {
	out := make(map[string][]string, len(input))
	for id, scope := range input {
		out[id] = slices.Clone(scope)
	}
	return out
}

// verifyHeldAccountsExcluded checks the live Magpie key file rather than the
// last database journal. No identity/pin is silently trusted as proof of
// isolation. A production key without a Codex entry is UNRESTRICTED for Codex.
func verifyHeldAccountsExcluded(state State, keys []privateGatewayKey, codex []CodexAccount) error {
	excluded, err := routingExcluded(state, codex)
	if err != nil {
		return err
	}
	held := map[string]bool{}
	for _, id := range excluded {
		held[strings.ToLower(id)] = true
	}
	probeSeen := false
	for _, k := range keys {
		if k.ID == state.Route.ProbeKeyID {
			probeSeen = true
			if k.Off {
				return errors.New("检测专用 Gateway Key 已停用，暂停检测")
			}
			continue
		}
		if k.Off || len(held) == 0 {
			continue
		}
		codexScoped := false
		for _, ref := range k.Accounts {
			provider, id, found := strings.Cut(ref, "/")
			if found && strings.EqualFold(provider, "codex") {
				codexScoped = true
				if held[strings.ToLower(id)] {
					return errors.New("有隔离账号仍在生产 Key 白名单中，暂停依赖隔离的检测")
				}
			}
		}
		if !codexScoped {
			return errors.New("生产 Key 没有 Codex 显式白名单，无法证明已隔离账号未放行")
		}
	}
	if !probeSeen {
		return errors.New("找不到检测专用 Gateway Key，暂停检测")
	}
	return nil
}

// acceptSafeNarrowingsLocked runs only while ApplyRouting holds the Magpie
// caller-keys.json flock and the service mutex. It never writes Magpie's key
// file, never widens permissions, and persists both the administrator's
// deletion and a minimal audit entry before any subsequent route planning.
func (s *Service) acceptSafeNarrowingsLocked(keys []privateGatewayKey, codex []CodexAccount) (bool, error) {
	route := s.state.Route
	if route.Pending || len(route.Expected) == 0 {
		return false, nil
	}
	baselines := clonedScopes(route.Baselines)
	expected := clonedScopes(route.Expected)
	changed := false
	for _, key := range keys {
		prior, known := route.Expected[key.ID]
		if !known {
			continue
		}
		beforeOff, tracked := route.ExpectedOff[key.ID]
		if !tracked || key.Off != beforeOff {
			return false, nil // unknown or edited enable/disable state: never accept
		}
		if slices.Equal(key.Accounts, prior) {
			continue
		}
		if key.ID == route.ProbeKeyID {
			return false, nil // never auto-adopt changes to the probe key
		}
		removed, ok := strictSubsequenceRemoval(prior, key.Accounts)
		if !ok || len(baselines[key.ID]) == 0 {
			return false, nil
		}
		removedSet := map[string]bool{}
		for _, item := range removed {
			if !slices.Contains(baselines[key.ID], item) {
				return false, nil
			}
			removedSet[item] = true
		}
		filtered := make([]string, 0, len(baselines[key.ID]))
		for _, item := range baselines[key.ID] {
			if !removedSet[item] {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) == 0 {
			return false, nil // never rewrite the baseline to ALLOW ALL
		}
		baselines[key.ID] = filtered
		expected[key.ID] = slices.Clone(key.Accounts)
		changed = true
	}
	if !changed {
		return false, nil
	}
	if err := verifyHeldAccountsExcluded(s.state, keys, codex); err != nil {
		return false, nil
	}
	projected := s.state
	projected.Route = route
	projected.Route.Baselines = baselines
	projected.Route.Expected = expected
	// An admin narrowing is accepted only if the projected current isolation
	// plan matches ALL live keys with no changes required. No production key is
	// ever rewritten by the acceptance transaction.
	preview, _, _, err := makeRoutingPreview(projected, keys, codex)
	if err != nil || len(preview.Keys) != len(keys) {
		return false, nil
	}
	for _, plan := range preview.Keys {
		if plan.Changed {
			return false, nil
		}
	}
	s.state.Route.Baselines = baselines
	s.state.Route.Expected = expected
	s.state.Route.LastError = ""
	s.state.Route.Audit = append(s.state.Route.Audit, RoutingAudit{
		At:          time.Now(),
		Action:      "admin-scope-narrowing-accepted",
		KeyCount:    len(keys),
		Quarantined: slices.Clone(preview.Quarantined),
	})
	if len(s.state.Route.Audit) > 100 {
		s.state.Route.Audit = slices.Clone(s.state.Route.Audit[len(s.state.Route.Audit)-100:])
	}
	if err := s.store.Save(s.state); err != nil {
		s.state.Route = route
		return false, fmt.Errorf("管理员白名单收缩记录保存失败：%w", err)
	}
	return true, nil
}

// verifySafeReadOnlyProbes provides a fallback when production scope drift
// blocks write-capable reconciliation. It never touches caller-keys.json and
// does NOT authorize changing production routes.
func (s *Service) verifySafeReadOnlyProbes() error {
	dir, err := MagpieDir()
	if err != nil {
		return err
	}
	// Serialise the live safety check with Magpie administrative writes.
	lock := flock.New(filepath.Join(dir, "caller-keys.json.lock"))
	held, err := lock.TryLockContext(context.Background(), 100*time.Millisecond)
	if err != nil || !held {
		return errors.New("路由配置被其他进程占用，暂停依赖隔离的自动检测")
	}
	defer lock.Unlock()
	codex, _, keys, err := readRouterInputs(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Route.Pending {
		return errors.New("路由写入事务未完成，暂停检测")
	}
	if err := verifyProbeKey(s.state, keys); err != nil {
		return err
	}
	return verifyHeldAccountsExcluded(s.state, keys, codex)
}

// VerifyLiveHold ensures a newly quarantined or pending account is actually
// absent from all enabled production keys before it receives fingerprint work.
func (s *Service) VerifyLiveHold(account string) bool {
	if err := s.verifySafeReadOnlyProbes(); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, held := s.state.Holds[account]
	return held && !s.state.Route.Pending
}
