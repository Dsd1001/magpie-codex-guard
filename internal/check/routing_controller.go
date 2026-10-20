package check

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// RoutingState persists original permissions and a write-ahead journal. No
// production route is ever modified without explicit opt-in.
type RoutingState struct {
	ExpectedCodexCount int                 `json:"expected_codex_count,omitempty"`
	ProbeKeyID         string              `json:"probe_key_id,omitempty"`
	ScheduleEnabled    bool                `json:"schedule_enabled"`
	AutoApply          bool                `json:"auto_apply"`
	Baselines          map[string][]string `json:"baselines,omitempty"`
	Expected           map[string][]string `json:"expected,omitempty"`
	BaselineOff        map[string]bool     `json:"baseline_off,omitempty"`
	ExpectedOff        map[string]bool     `json:"expected_off,omitempty"`
	PreviousOff        map[string]bool     `json:"previous_off,omitempty"`
	Previous           map[string][]string `json:"previous,omitempty"`
	PendingQuarantine  []string            `json:"pending_quarantine,omitempty"`
	Quarantined        map[string]bool     `json:"quarantined,omitempty"`
	Pending            bool                `json:"pending"`
	PendingRestore     bool                `json:"pending_restore,omitempty"`
	LastError          string              `json:"last_error,omitempty"`
	LastApplied        time.Time           `json:"last_applied,omitempty"`
	Audit              []RoutingAudit      `json:"audit,omitempty"`
}

type RoutingAudit struct {
	At          time.Time `json:"at"`
	Action      string    `json:"action"`
	KeyCount    int       `json:"key_count"`
	Quarantined []string  `json:"quarantined"`
}

type RoutingPreview struct {
	Mode         string            `json:"mode"`
	Pending      bool              `json:"pending"`
	LastError    string            `json:"last_error,omitempty"`
	ProbeKeyID   string            `json:"probe_key_id,omitempty"`
	AccountCount int               `json:"account_count"`
	Quarantined  []string          `json:"quarantined"`
	Keys         []PlannedKeyScope `json:"keys"`
}

// This mirrors the exact fields in Magpie's caller-keys.json. All unknown
// fields (including secret and usage settings) remain untouched in raw JSON.
type privateGatewayKey struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Secret   string   `json:"secret"`
	Accounts []string `json:"accounts"`
	Off      bool     `json:"off"`
}

// GatewayKeyLabel holds ONLY public identifiers and display names.
// Never expose the privateGatewayKey (which includes the secret) through
// an HTTP API, a browser error, or a logging statement.
type GatewayKeyLabel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Off  bool   `json:"off"`
}

func GatewayKeyLabels() ([]GatewayKeyLabel, error) {
	dir, err := MagpieDir()
	if err != nil {
		return nil, err
	}
	_, keys, err := loadKeyDocuments(filepath.Join(dir, "caller-keys.json"))
	if err != nil {
		return nil, err
	}
	out := make([]GatewayKeyLabel, 0, len(keys))
	for _, key := range keys {
		out = append(out, GatewayKeyLabel{ID: key.ID, Name: key.Name, Off: key.Off})
	}
	return out, nil
}

func loadKeyDocuments(path string) ([]map[string]json.RawMessage, []privateGatewayKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Magpie Gateway Key 配置不可读：%w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("Gateway Key 文件必须是普通文件，不能是符号链接")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("Gateway Key 文件权限过宽；拒绝自动管理")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, errors.New("Gateway Key 文件读取失败")
	}
	if len(raw) > 4*1024*1024 {
		return nil, nil, errors.New("Gateway Key 文件超过安全上限")
	}
	var rawKeys []map[string]json.RawMessage
	var keys []privateGatewayKey
	if err := json.Unmarshal(raw, &rawKeys); err != nil {
		return nil, nil, errors.New("Gateway Key 数据格式不正确")
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, nil, errors.New("Gateway Key 数据格式不正确")
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("尚未找到任何 Gateway Key")
	}
	if len(keys) != len(rawKeys) {
		return nil, nil, errors.New("Gateway Key 列表长度不一致")
	}
	return rawKeys, keys, nil
}

func routingKnownIDs(codex []CodexAccount) []string {
	ids := make([]string, 0, len(codex))
	for _, a := range codex {
		ids = append(ids, a.ID)
	}
	return ids
}

// routingExcluded holds quarantined accounts until ALL enabled model checks
// for that account have passed twice. A single failed probe is NOT evidence
// of degraded quality. Network/quota failures do not affect the counters.
// routingExcluded is driven only by persisted account holds. A failed probe
// that has not reached the fingerprint stage is never enough to isolate.
func routingExcluded(state State, codex []CodexAccount) ([]string, error) {
	excluded := map[string]bool{}
	for account := range state.Holds {
		stable, err := ResolveAccountID(codex, account)
		if err != nil {
			return nil, fmt.Errorf("隔离账号身份无法解析，拒绝放行：%w", err)
		}
		excluded[stable] = true
	}
	out := make([]string, 0, len(excluded))
	for id := range excluded {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// makeRoutingPreview checks for out-of-band edits before constructing any
// changes. A new production key is enrolled automatically; an old key
// changed by an administrator is NOT silently overwritten.
func makeRoutingPreview(state State, keys []privateGatewayKey, codex []CodexAccount) (RoutingPreview, map[string][]string, map[string]bool, error) {
	route := state.Route
	if route.Pending {
		return RoutingPreview{}, nil, nil, errors.New("上次路由更新未完成；请人工核对 Gateway Key 配置")
	}
	if route.ProbeKeyID == "" {
		return RoutingPreview{}, nil, nil, errors.New("未配置检测专用 Gateway Key ID")
	}
	if route.ExpectedCodexCount > 0 && len(codex) != route.ExpectedCodexCount {
		return RoutingPreview{}, nil, nil, fmt.Errorf("Magpie 发现 %d 个 Codex 账号，与期望数量 %d 不一致；拒绝自动修改路由", len(codex), route.ExpectedCodexCount)
	}
	baselines := make(map[string][]string, len(keys))
	offBaselines := make(map[string]bool, len(keys))
	source := make([]GatewayKeyScope, 0, len(keys))
	probeFound := false
	for _, k := range keys {
		if k.ID == "" {
			return RoutingPreview{}, nil, nil, errors.New("Gateway Key 存在空 ID")
		}
		expected, known := route.Expected[k.ID]
		if known && !slices.Equal(k.Accounts, expected) {
			return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 白名单被外部修改，已暂停自动路由；不会覆盖管理员设置", k.ID)
		}
		if expectedOff, expectedKnown := route.ExpectedOff[k.ID]; expectedKnown && k.Off != expectedOff {
			return RoutingPreview{}, nil, nil, fmt.Errorf("生产 Key %s 的启用状态被外部修改，拒绝覆盖", k.ID)
		}
		if previousOff, previousKnown := route.BaselineOff[k.ID]; previousKnown {
			offBaselines[k.ID] = previousOff
		} else {
			// A key enrolled for the first time saves its original enabled state.
			offBaselines[k.ID] = k.Off
		}
		if baseline, known := route.Baselines[k.ID]; known {
			baselines[k.ID] = slices.Clone(baseline)
		} else {
			if known {
				return RoutingPreview{}, nil, nil, errors.New("持久化路由基线缺失，拒绝恢复")
			}
			baselines[k.ID] = slices.Clone(k.Accounts)
		}
		if k.ID == route.ProbeKeyID {
			probeFound = true
			if k.Off {
				return RoutingPreview{}, nil, nil, errors.New("检测专用 Gateway Key 已被禁用")
			}
			// The probe key must be able to reach every account, including
			// the quarantined ones, or recoveries could never be proved.
			for _, ref := range k.Accounts {
				if strings.HasPrefix(strings.ToLower(ref), "codex/") {
					for _, a := range codex {
						if !slices.ContainsFunc(k.Accounts, func(x string) bool { return strings.EqualFold(x, "codex/"+a.ID) }) {
							return RoutingPreview{}, nil, nil, errors.New("检测 Key 不能访问所有 Codex 账号")
						}
					}
					break
				}
			}
		}
		source = append(source, GatewayKeyScope{ID: k.ID, Accounts: baselines[k.ID], Off: offBaselines[k.ID]})
	}
	if !probeFound {
		return RoutingPreview{}, nil, nil, errors.New("配置的检测 Key 不存在")
	}
	excluded, err := routingExcluded(state, codex)
	if err != nil {
		return RoutingPreview{}, nil, nil, err
	}
	plan, err := PlanCodexQuarantine(source, route.ProbeKeyID, routingKnownIDs(codex), excluded)
	if err != nil {
		return RoutingPreview{}, nil, nil, err
	}
	// Changed means an update relative to the LIVE key store, not the
	// original baseline. Recovery must restore keys modified earlier.
	for i := range plan {
		plan[i].Changed = !slices.Equal(keys[i].Accounts, plan[i].After) ||
			keys[i].Off != plan[i].OffAfter
		plan[i].OffBefore = keys[i].Off
	}
	mode := "observe_only"
	if route.AutoApply {
		mode = "active"
	}
	return RoutingPreview{Mode: mode, Pending: route.Pending, LastError: route.LastError, ProbeKeyID: route.ProbeKeyID, AccountCount: len(codex), Quarantined: excluded, Keys: plan}, baselines, offBaselines, nil
}

// readRouterInputs uses only local configuration. The login file carries
// credentials, but discovery returns account IDs and names alone.
func readRouterInputs(dir string) ([]CodexAccount, []map[string]json.RawMessage, []privateGatewayKey, error) {
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, keys, err := loadKeyDocuments(filepath.Join(dir, "caller-keys.json"))
	return accounts, raw, keys, err
}

func verifyProbeKey(state State, keys []privateGatewayKey) error {
	for _, k := range keys {
		if k.ID != state.Route.ProbeKeyID {
			continue
		}
		if len(state.Config.GatewayKey) < 16 || subtle.ConstantTimeCompare([]byte(k.Secret), []byte(state.Config.GatewayKey)) != 1 {
			return errors.New("控制台 Gateway Key 不是独立检测 Key；拒绝自动改变生产路由")
		}
		return nil
	}
	return errors.New("检测 Key 不存在")
}

func (s *Service) RoutingPreview() (RoutingPreview, error) {
	dir, err := MagpieDir()
	if err != nil {
		return RoutingPreview{}, err
	}
	codex, _, keys, err := readRouterInputs(dir)
	if err != nil {
		return RoutingPreview{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := verifyProbeKey(s.state, keys); err != nil {
		return RoutingPreview{}, err
	}
	preview, _, _, err := makeRoutingPreview(s.state, keys, codex)
	return preview, err
}

func (s *Service) ConfigureRouting(probeKeyID string, active bool, confirm string) error {
	if probeKeyID == "" || len(probeKeyID) > 120 || strings.ContainsAny(probeKeyID, "\r\n/") {
		return errors.New("请输入有效的检测 Key ID")
	}
	if active && confirm != "ENABLE_ALL_PRODUCTION_KEYS" {
		return errors.New("必须明确确认将管理全部生产 Gateway Key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	route := &s.state.Route
	if route.Pending {
		return errors.New("未完成的路由更新需人工确认")
	}
	if route.ProbeKeyID != "" && route.ProbeKeyID != probeKeyID && len(route.Baselines) > 0 {
		return errors.New("已有隔离管理历史，不允许直接更换检测 Key")
	}
	previous := *route
	route.ProbeKeyID, route.AutoApply = probeKeyID, active
	if err := s.store.Save(s.state); err != nil {
		*route = previous
		return err
	}
	return nil
}

// ApplyRouting performs one atomic multi-key file update under the SAME
// cross-process .lock used by Magpie's access.Update. A write-ahead marker
// leaves crash recovery in an explicit blocked state rather than guessing.
func (s *Service) ApplyRouting(ctx context.Context, restore bool) (RoutingPreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !restore && !s.state.Route.AutoApply {
		return RoutingPreview{}, errors.New("自动路由仍是观察模式，禁止修改生产 Key")
	}
	dir, err := MagpieDir()
	if err != nil {
		return RoutingPreview{}, err
	}
	lock := flock.New(filepath.Join(dir, "caller-keys.json.lock"))
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	held, err := lock.TryLockContext(waitCtx, 20*time.Millisecond)
	if err != nil || !held {
		return RoutingPreview{}, errors.New("无法取得 Magpie Gateway Key 文件锁，未进行路由更新")
	}
	defer lock.Unlock()

	codex, rawKeys, keys, err := readRouterInputs(dir)
	if err != nil {
		return RoutingPreview{}, err
	}
	if err = verifyProbeKey(s.state, keys); err != nil {
		return RoutingPreview{}, err
	}
	projected := s.state
	if restore {
		projected.Route.Quarantined = nil
		projected.Holds = map[string]QuarantineHold{}
		projected.AccountTargets = make(map[string]*AccountTarget, len(s.state.AccountTargets))
		for key, t := range s.state.AccountTargets {
			// Preview must never mutate the actual state before the key
			// file and the journal are both safely committed.
			copy := *t
			copy.ConsecutiveFails = 0
			projected.AccountTargets[key] = &copy
		}
	}
	preview, baselines, offBaselines, err := makeRoutingPreview(projected, keys, codex)
	if err != nil {
		return RoutingPreview{}, err
	}
	if restore {
		preview.Mode = "observe_only"
		preview.Quarantined = nil
	}
	after := map[string][]string{}
	afterOff := map[string]bool{}
	changed := false
	for i, plan := range preview.Keys {
		after[plan.KeyID] = slices.Clone(plan.After)
		afterOff[plan.KeyID] = plan.OffAfter
		if !plan.Changed {
			continue
		}
		changed = true
		if len(plan.After) == 0 && len(preview.Quarantined) > 0 && !plan.OffAfter {
			return RoutingPreview{}, errors.New("隔离后空白名单将误放行全部账号，拒绝写入")
		}
		data, err := json.Marshal(plan.After)
		if err != nil {
			return RoutingPreview{}, err
		}
		rawKeys[i]["accounts"] = data
		if plan.OffAfter {
			rawKeys[i]["off"] = json.RawMessage("true")
		} else {
			rawKeys[i]["off"] = json.RawMessage("false")
		}
	}
	if !changed {
		// A new key's baseline must be remembered even if it needs no
		// rewrite. Avoid a pointless SQLite fsync every scheduler tick.
		previous := s.state.Route
		different := !maps.EqualFunc(previous.Baselines, baselines, slices.Equal) ||
			!maps.EqualFunc(previous.Expected, after, slices.Equal)
		if !maps.Equal(previous.BaselineOff, offBaselines) || !maps.Equal(previous.ExpectedOff, afterOff) {
			different = true
		}
		if !slices.Equal(sortedQuarantined(previous.Quarantined), preview.Quarantined) {
			different = true
		}
		if restore && previous.AutoApply {
			different = true
		}
		if previous.LastError != "" {
			different = true
		}
		if !different {
			return preview, nil
		}
		s.state.Route.Baselines = baselines
		s.state.Route.Expected = after
		s.state.Route.BaselineOff = offBaselines
		s.state.Route.ExpectedOff = afterOff
		s.state.Route.Quarantined = quarantineSet(preview.Quarantined)
		s.state.Route.LastError = ""
		if restore {
			s.state.Route.AutoApply = false
			s.state.Route.Quarantined = nil
			s.state.Holds = map[string]QuarantineHold{}
			for _, t := range s.state.AccountTargets {
				t.ConsecutiveFails = 0
			}
		}
		return preview, s.store.Save(s.state)
	}

	// Persist both the baseline and desired state BEFORE replacing Magpie's
	// config, so interruption never silently forgets whom we quarantined.
	route := &s.state.Route
	route.Pending = true
	route.PendingRestore = restore
	route.Previous = make(map[string][]string, len(keys))
	route.PreviousOff = make(map[string]bool, len(keys))
	for _, k := range keys {
		route.Previous[k.ID] = slices.Clone(k.Accounts)
		route.PreviousOff[k.ID] = k.Off
	}
	route.PendingQuarantine = slices.Clone(preview.Quarantined)
	route.Baselines = baselines
	route.Expected = after
	route.BaselineOff = offBaselines
	route.ExpectedOff = afterOff
	if err := s.store.Save(s.state); err != nil {
		return RoutingPreview{}, err
	}

	b, err := json.MarshalIndent(rawKeys, "", "  ")
	if err != nil {
		route.LastError = "路由编码失败"
		return RoutingPreview{}, err
	}
	path := filepath.Join(dir, "caller-keys.json")
	if err = AtomicWrite(path, append(b, '\n')); err != nil {
		route.LastError = "更新 Magpie Gateway Key 文件失败；需人工核实后继续"
		_ = s.store.Save(s.state)
		return RoutingPreview{}, err
	}
	// Verify immediately. The lock serializes Magpie administrative writes.
	_, actual, err := loadKeyDocuments(path)
	if err == nil {
		if len(actual) != len(keys) {
			err = errors.New("Gateway Key 写后数量改变")
		}
		for i, k := range actual {
			if err == nil && (k.ID != keys[i].ID || !slices.Equal(k.Accounts, after[k.ID]) || k.Off != afterOff[k.ID]) {
				err = errors.New("Gateway Key 写后验证失败")
			}
		}
	}
	if err != nil {
		route.LastError = "路由更新验证失败，自动隔离已停止"
		_ = s.store.Save(s.state)
		return RoutingPreview{}, err
	}
	route.Pending = false
	route.PendingRestore = false
	route.Previous = nil
	route.PreviousOff = nil
	route.PendingQuarantine = nil
	route.Quarantined = quarantineSet(preview.Quarantined)
	if restore {
		route.AutoApply = false
		route.Quarantined = nil
		s.state.Holds = map[string]QuarantineHold{}
		for _, t := range s.state.AccountTargets {
			t.ConsecutiveFails = 0
		}
	}
	route.LastError = ""
	route.LastApplied = time.Now()
	action := "quarantine"
	if restore {
		action = "restore"
	}
	route.Audit = append(route.Audit, RoutingAudit{At: route.LastApplied, Action: action, KeyCount: len(after), Quarantined: slices.Clone(preview.Quarantined)})
	if len(route.Audit) > 100 {
		route.Audit = slices.Clone(route.Audit[len(route.Audit)-100:])
	}
	if err := s.store.Save(s.state); err != nil {
		return RoutingPreview{}, err
	}
	return preview, nil
}

// sortedQuarantined returns stable IDs for display without any credentials.
func sortedQuarantined(m map[string]bool) []string {
	var ids []string
	for id, on := range m {
		if on {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
func quarantineSet(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// RecoverRoutingJournal never writes the Gateway Key file. It is an
// explicit operator action after an interrupted transaction. If the
// file is neither exactly the before state nor exactly the target state,
// recovery refuses to guess, preventing privilege widening.
func (s *Service) RecoverRoutingJournal(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	route := &s.state.Route
	if !route.Pending {
		return "", errors.New("没有待恢复的路由操作")
	}
	dir, err := MagpieDir()
	if err != nil {
		return "", err
	}
	lock := flock.New(filepath.Join(dir, "caller-keys.json.lock"))
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ok, err := lock.TryLockContext(wait, 20*time.Millisecond)
	if err != nil || !ok {
		return "", errors.New("无法取得 Magpie Gateway Key 文件锁")
	}
	defer lock.Unlock()
	_, keys, err := loadKeyDocuments(filepath.Join(dir, "caller-keys.json"))
	if err != nil {
		return "", err
	}
	beforeOK, afterOK := len(keys) == len(route.Previous), len(keys) == len(route.Expected)
	for _, k := range keys {
		before, existsBefore := route.Previous[k.ID]
		after, existsAfter := route.Expected[k.ID]
		if !existsBefore || !slices.Equal(k.Accounts, before) || k.Off != route.PreviousOff[k.ID] {
			beforeOK = false
		}
		if !existsAfter || !slices.Equal(k.Accounts, after) || k.Off != route.ExpectedOff[k.ID] {
			afterOK = false
		}
	}
	if !beforeOK && !afterOK {
		return "", errors.New("路由状态混合或被外部更改，拒绝自动恢复；需要管理员人工核对")
	}
	action := "completed"
	if afterOK {
		route.Quarantined = quarantineSet(route.PendingQuarantine)
		if route.PendingRestore {
			route.AutoApply = false
			route.Quarantined = nil
			s.state.Holds = map[string]QuarantineHold{}
			for _, t := range s.state.AccountTargets {
				t.ConsecutiveFails = 0
			}
		}
	} else {
		route.Expected = route.Previous
		route.ExpectedOff = route.PreviousOff
		route.AutoApply = false
		route.LastError = "上次写入未执行；已关闭自动隔离，需人工核对后重新开启"
		action = "aborted"
	}
	route.Pending = false
	route.PendingRestore = false
	route.Previous = nil
	route.PreviousOff = nil
	route.PendingQuarantine = nil
	route.Audit = append(route.Audit, RoutingAudit{At: time.Now(), Action: "recover-" + action, KeyCount: len(keys), Quarantined: sortedQuarantined(route.Quarantined)})
	if len(route.Audit) > 100 {
		route.Audit = slices.Clone(route.Audit[len(route.Audit)-100:])
	}
	if err := s.store.Save(s.state); err != nil {
		return "", err
	}
	return action, nil
}

// ConfigureExpectedAccountCount makes missing sign-ins fail closed rather
// than silently removing accounts from the production pool.
func (s *Service) ConfigureExpectedAccountCount(count int) error {
	if count < 0 || count > 100 {
		return errors.New("预期账号数量须在 0 到 100 之间")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state.Route.ExpectedCodexCount
	s.state.Route.ExpectedCodexCount = count
	if err := s.store.Save(s.state); err != nil {
		s.state.Route.ExpectedCodexCount = previous
		return err
	}
	return nil
}
