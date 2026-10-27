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
		if hold, ok := state.Holds[id]; ok && modelProvider(hold.Model) != "" && modelProvider(hold.Model) != "codex" {
			continue
		}
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
		if k.Off {
			continue
		}
		for provider := range heldAPIProviders(state) {
			if len(k.Models) == 0 {
				return errors.New("API 隔离上游仍对生产 Key 开放")
			}
			for _, pattern := range k.Models {
				p, m, ok := strings.Cut(pattern, "/")
				if !ok || !providerIDPattern.MatchString(p) || p == "group" || p == provider || m == "" {
					return errors.New("API 隔离模型白名单无法证明已阻止生产访问")
				}
			}
		}
		if len(held) == 0 {
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

// ApproveCurrentScopes explicitly accepts an administrator's already-applied
// finite production whitelist changes, including NEW login accounts. This
// function NEVER writes caller-keys.json and never changes Holds. Unknown
// accounts, live quarantined accounts, probe-key edits, empty allowlists,
// changed key statuses and uncommitted transactions are rejected.
func (s *Service) ApproveCurrentScopes(ctx context.Context, confirm string) (RoutingPreview, error) {
	if confirm != "APPROVE_CURRENT_PRODUCTION_SCOPES" {
		return RoutingPreview{}, errors.New("确认短语错误：拒绝采用生产白名单")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	route := s.state.Route
	if !route.AutoApply || route.Pending {
		return RoutingPreview{}, errors.New("自动隔离尚未启用或路由事务未完成")
	}
	dir, err := MagpieDir()
	if err != nil {
		return RoutingPreview{}, err
	}
	lock := flock.New(filepath.Join(dir, "caller-keys.json.lock"))
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(wait, 20*time.Millisecond)
	if err != nil || !locked {
		return RoutingPreview{}, errors.New("无法取得 Gateway Key 文件锁")
	}
	defer lock.Unlock()

	codex, _, keys, err := readRouterInputs(dir)
	if err != nil {
		return RoutingPreview{}, err
	}
	if route.ExpectedCodexCount > 0 && len(routingKnownIDs(codex)) != route.ExpectedCodexCount {
		return RoutingPreview{}, errors.New("实际账号数量与预期不一致，请先检查账号列表")
	}
	if err = verifyProbeKey(s.state, keys); err != nil {
		return RoutingPreview{}, err
	}
	if err = verifyHeldAccountsExcluded(s.state, keys, codex); err != nil {
		return RoutingPreview{}, err
	}

	known := map[string]bool{}
	for _, a := range codex {
		known[a.ID] = true
	}
	excluded, err := routingExcluded(s.state, codex)
	if err != nil {
		return RoutingPreview{}, err
	}
	holds := map[string]bool{}
	for _, id := range excluded {
		holds[strings.ToLower(id)] = true
	}
	expected := clonedScopes(route.Expected)
	baselines := clonedScopes(route.Baselines)
	changes := 0
	for _, key := range keys {
		previous, tracked := route.Expected[key.ID]
		off, offTracked := route.ExpectedOff[key.ID]
		if key.ID == route.ProbeKeyID {
			if tracked && (!slices.Equal(key.Accounts, previous) || !offTracked || key.Off != off) {
				return RoutingPreview{}, errors.New("检测 Key 的白名单/启用状态发生变化，禁止自动采用")
			}
			continue
		}
		baseline, baselineKnown := baselines[key.ID]
		if !tracked || !baselineKnown || !offTracked || off != key.Off {
			return RoutingPreview{}, errors.New("存在未管理的 Key 或启用状态变化，需要人工单独核对")
		}
		if slices.Equal(previous, key.Accounts) {
			// Still remove orphaned logins from the *private* baseline on
			// adoption, so their access cannot be restored in the future.
			continue
		}
		if len(key.Accounts) == 0 {
			return RoutingPreview{}, errors.New("空白名单表示允许全部账号，拒绝采用")
		}
		// All account refs must be unique; duplicates/reordering cannot be
		// treated as an authorization change.
		present := map[string]bool{}
		for _, ref := range key.Accounts {
			if present[ref] {
				return RoutingPreview{}, errors.New("生产 Key 出现重复账号")
			}
			present[ref] = true
		}
		// Preserve historical baseline for currently held *live* logins,
		// but drop every deleted login from that baseline even if held.
		updated := make([]string, 0, len(baseline)+len(key.Accounts))
		for _, ref := range baseline {
			provider, id, ok := strings.Cut(ref, "/")
			if ok && strings.EqualFold(provider, "codex") && !known[id] {
				continue
			}
			if slices.Contains(previous, ref) && !present[ref] {
				continue // explicit administrator deletion
			}
			updated = append(updated, ref)
		}
		for _, ref := range key.Accounts {
			if slices.Contains(previous, ref) {
				continue
			}
			provider, id, valid := strings.Cut(ref, "/")
			if !valid || !strings.EqualFold(provider, "codex") || !known[id] || holds[strings.ToLower(id)] {
				return RoutingPreview{}, errors.New("生产 Key 新增条目不是当前已登录且未隔离的 Codex 账号，禁止采用")
			}
			if !slices.Contains(updated, ref) {
				updated = append(updated, ref)
			}
		}
		if len(updated) == 0 {
			return RoutingPreview{}, errors.New("基线不能为空")
		}
		baselines[key.ID] = updated
		expected[key.ID] = slices.Clone(key.Accounts)
		changes++
	}
	if changes == 0 {
		return RoutingPreview{}, errors.New("没有需要确认的新生产白名单变化")
	}
	projected := s.state
	projected.Route = route
	projected.Route.Expected = expected
	projected.Route.Baselines = baselines
	preview, _, _, err := makeRoutingPreview(projected, keys, codex)
	if err != nil {
		return RoutingPreview{}, err
	}
	for _, p := range preview.Keys {
		if p.Changed {
			return RoutingPreview{}, fmt.Errorf("当前白名单与隔离后的安全路由不一致（%s：%d→%d），禁止采用", p.KeyID, len(p.Before), len(p.After))
		}
	}

	old := s.state.Route
	s.state.Route.Expected = expected
	s.state.Route.Baselines = baselines
	s.state.Route.LastError = ""
	s.state.Route.Audit = append(s.state.Route.Audit, RoutingAudit{
		At: time.Now(), Action: "admin-scope-change-approved",
		KeyCount: len(keys), Quarantined: slices.Clone(excluded),
	})
	if len(s.state.Route.Audit) > 100 {
		s.state.Route.Audit = slices.Clone(s.state.Route.Audit[len(s.state.Route.Audit)-100:])
	}
	if err := s.store.Save(s.state); err != nil {
		s.state.Route = old
		return RoutingPreview{}, fmt.Errorf("无法保存已确认的白名单基线：%w", err)
	}
	preview.LastError = ""
	return preview, nil
}
