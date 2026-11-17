package check

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/gofrs/flock"
)

// RoutingState persists original permissions and a write-ahead journal. No
// production route is ever modified without explicit opt-in.
type RoutingState struct {
	AwaitingDetection      bool                `json:"awaiting_detection,omitempty"`
	ExpectedCodexCount     int                 `json:"expected_codex_count,omitempty"`
	ProbeKeyID             string              `json:"probe_key_id,omitempty"`
	ScheduleEnabled        bool                `json:"schedule_enabled"`
	AutoSyncAccounts       bool                `json:"auto_sync_accounts,omitempty"`
	AutoApply              bool                `json:"auto_apply"`
	Baselines              map[string][]string `json:"baselines,omitempty"`
	Expected               map[string][]string `json:"expected,omitempty"`
	BaselineOff            map[string]bool     `json:"baseline_off,omitempty"`
	ExpectedOff            map[string]bool     `json:"expected_off,omitempty"`
	PreviousOff            map[string]bool     `json:"previous_off,omitempty"`
	Previous               map[string][]string `json:"previous,omitempty"`
	PendingQuarantine      []string            `json:"pending_quarantine,omitempty"`
	Quarantined            map[string]bool     `json:"quarantined,omitempty"`
	Pending                bool                `json:"pending"`
	PendingRestore         bool                `json:"pending_restore,omitempty"`
	LastError              string              `json:"last_error,omitempty"`
	LastApplied            time.Time           `json:"last_applied,omitempty"`
	Audit                  []RoutingAudit      `json:"audit,omitempty"`
	ModelBaselines         map[string][]string `json:"model_baselines,omitempty"`
	ModelExpected          map[string][]string `json:"model_expected,omitempty"`
	ModelPrevious          map[string][]string `json:"model_previous,omitempty"`
	GroupOffBaselines      map[string][]string `json:"group_off_baselines,omitempty"`
	GroupOffExpected       map[string][]string `json:"group_off_expected,omitempty"`
	GroupOffMembers        map[string][]string `json:"group_off_members,omitempty"`
	GroupOffPrevious       map[string][]string `json:"group_off_previous,omitempty"`
	GroupOffTarget         map[string][]string `json:"group_off_target,omitempty"`
	GroupOffPendingMembers map[string][]string `json:"group_off_pending_members,omitempty"`
	GroupOffNextBaselines  map[string][]string `json:"group_off_next_baselines,omitempty"`
	GroupOffNextExpected   map[string][]string `json:"group_off_next_expected,omitempty"`
	GroupOffNextMembers    map[string][]string `json:"group_off_next_members,omitempty"`
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
	Excluded     []string          `json:"excluded"`
	Keys         []PlannedKeyScope `json:"keys"`
}

// This mirrors the exact fields in Magpie's caller-keys.json. All unknown
// fields (including secret and usage settings) remain untouched in raw JSON.
type privateGatewayKey struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Secret   string   `json:"secret"`
	Accounts []string `json:"accounts"`
	Models   []string `json:"models"`
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
		if accountProvider(a) != "codex" {
			continue
		}
		ids = append(ids, a.ID)
	}
	return ids
}

// routingExcluded is derived from current live Codex accounts, not historical
// account allowlists. Pending accounts are excluded without being quarantined.
func routingExcluded(state State, codex []CodexAccount) ([]string, error) {
	var excluded []string
	for _, a := range codex {
		if accountProvider(a) == "codex" && !accountRouteEligible(state, a.ID) {
			excluded = append(excluded, a.ID)
		}
	}
	sort.Strings(excluded)
	return excluded, nil
}

func liveCodexHolds(state State, codex []CodexAccount) []string {
	var held []string
	for _, a := range codex {
		if accountProvider(a) == "codex" {
			if _, ok := state.Holds[a.ID]; ok {
				held = append(held, a.ID)
			}
		}
	}
	sort.Strings(held)
	return held
}

// A saved before/after image is only a transaction journal, never an approval
// gate. The live non-Codex account picks and administrator OFF setting win.
func makeRoutingPreview(state State, keys []privateGatewayKey, codex []CodexAccount) (RoutingPreview, map[string][]string, map[string]bool, error) {
	source := make([]GatewayKeyScope, 0, len(keys))
	baselines, offBaselines := map[string][]string{}, map[string]bool{}
	for _, k := range keys {
		off := administratorKeyOff(state.Route, k)
		source = append(source, GatewayKeyScope{ID: k.ID, Accounts: slices.Clone(k.Accounts), Off: off})
		baselines[k.ID] = slices.Clone(k.Accounts)
		offBaselines[k.ID] = off
	}
	excluded, err := routingExcluded(state, codex)
	if err != nil {
		return RoutingPreview{}, nil, nil, err
	}
	plan, err := PlanCodexQuarantine(source, state.Route.ProbeKeyID, routingKnownIDs(codex), excluded)
	if err != nil {
		return RoutingPreview{}, nil, nil, err
	}
	if err := attachAPIModelScopes(state, keys, plan); err != nil {
		return RoutingPreview{}, nil, nil, err
	}
	for i, k := range keys {
		plan[i].Before = slices.Clone(k.Accounts)
		plan[i].OffBefore = k.Off
		plan[i].Changed = !slices.Equal(k.Accounts, plan[i].After) || !slices.Equal(k.Models, plan[i].ModelsAfter) || k.Off != plan[i].OffAfter
	}
	mode := "observe_only"
	if state.Route.AutoApply {
		mode = "active"
	}
	return RoutingPreview{Mode: mode, Pending: state.Route.Pending, LastError: state.Route.LastError,
		ProbeKeyID: state.Route.ProbeKeyID, AccountCount: len(routingKnownIDs(codex)),
		Quarantined: liveCodexHolds(state, codex), Excluded: excluded, Keys: plan}, baselines, offBaselines, nil
}

func readRouterInputs(dir string) ([]CodexAccount, []map[string]json.RawMessage, []privateGatewayKey, error) {
	accounts, err := DiscoverCodexAccounts(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, keys, err := loadKeyDocuments(filepath.Join(dir, "caller-keys.json"))
	return accounts, raw, keys, err
}

func verifyProbeKey(state State, keys []privateGatewayKey) error {
	_, err := probeKeyByID(keys, state.Route.ProbeKeyID)
	return err
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
	state := s.state
	state.Route = routingStateAfterInterruptedWrite(state.Route)
	preview, _, _, err := makeRoutingPreview(state, keys, codex)
	return preview, err
}

// Compatibility entrypoint. The selected key may change between rounds.
func (s *Service) ConfigureRouting(probeKeyID string, active bool, _ string) error {
	s.mu.Lock()
	schedule := s.state.Route.ScheduleEnabled
	s.mu.Unlock()
	return s.ConfigureController(context.Background(), probeKeyID, 0, active, schedule, "")
}

// Account lists are always recomputed from durable detection state. Temporary
// model/group restrictions retain ownership only so they can be removed later.
// If a previous transaction was interrupted, rebase against the current files
// and converge automatically rather than asking for historical approval.
func routingStateAfterInterruptedWrite(route RoutingState) RoutingState {
	if !route.Pending {
		return route
	}
	route.GroupOffBaselines = clonedScopes(route.GroupOffBaselines)
	route.GroupOffExpected = clonedScopes(route.GroupOffExpected)
	route.GroupOffMembers = clonedScopes(route.GroupOffMembers)
	for id, base := range route.GroupOffNextBaselines {
		route.GroupOffBaselines[id] = slices.Clone(base)
	}
	for id, expected := range route.GroupOffNextExpected {
		route.GroupOffExpected[id] = slices.Clone(expected)
	}
	for id, members := range route.GroupOffNextMembers {
		route.GroupOffMembers[id] = slices.Clone(members)
	}
	return route
}

func clearRoutingJournal(route *RoutingState) {
	route.Pending = false
	route.PendingRestore = false
	route.Previous = nil
	route.PreviousOff = nil
	route.ModelPrevious = nil
	route.PendingQuarantine = nil
	route.GroupOffPrevious = nil
	route.GroupOffTarget = nil
	route.GroupOffPendingMembers = nil
	route.GroupOffNextBaselines = nil
	route.GroupOffNextExpected = nil
	route.GroupOffNextMembers = nil
}

// ApplyRouting is also the independent manual sync action. The scheduler only
// calls it when AutoApply is enabled. restore is retained for old API callers
// but now means reset monitoring ONLY, never restore historical permissions.
func (s *Service) ApplyRouting(ctx context.Context, restore bool) (RoutingPreview, error) {
	if restore {
		return s.ResetAccountStates()
	}
	return s.applyRouting(ctx, false)
}

func (s *Service) applyAutomaticRouting(ctx context.Context) (RoutingPreview, error) {
	return s.applyRouting(ctx, true)
}

func (s *Service) applyRouting(ctx context.Context, automatic bool) (RoutingPreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Recheck cancellation/settings after acquiring the lock. A scheduler
	// handoff queued before reset must not write pending-account permissions
	// after reset, nor continue after the administrator disables automation.
	if err := ctx.Err(); err != nil {
		return RoutingPreview{}, err
	}
	if automatic && (!s.state.Route.AutoApply || s.state.Route.AwaitingDetection) {
		return RoutingPreview{Mode: "awaiting_detection", ProbeKeyID: s.state.Route.ProbeKeyID}, nil
	}
	dir, err := MagpieDir()
	if err != nil {
		return RoutingPreview{}, err
	}
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	lock := flock.New(filepath.Join(dir, "caller-keys.json.lock"))
	held, err := lock.TryLockContext(wait, 20*time.Millisecond)
	if err != nil || !held {
		return RoutingPreview{}, errors.New("无法取得 Magpie Gateway Key 文件锁，本次路由同步未执行")
	}
	defer lock.Unlock()
	providersLock := flock.New(filepath.Join(dir, "providers.json.lock"))
	held, err = providersLock.TryLockContext(wait, 20*time.Millisecond)
	if err != nil || !held {
		return RoutingPreview{}, errors.New("无法取得 Magpie Providers 文件锁，本次路由同步未执行")
	}
	defer providersLock.Unlock()
	codex, rawKeys, keys, err := readRouterInputs(dir)
	if err != nil {
		return RoutingPreview{}, err
	}
	keyPath := filepath.Join(dir, "caller-keys.json")
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return RoutingPreview{}, err
	}
	keyHash := sha256.Sum256(keyBytes)
	previous := s.state.Route
	planning := s.state
	planning.Route = routingStateAfterInterruptedWrite(previous)
	preview, _, offBaselines, err := makeRoutingPreview(planning, keys, codex)
	if err != nil {
		return RoutingPreview{}, err
	}
	groups, err := planRoutingGroupOff(dir, planning.Route, codex, preview.Excluded, false)
	if err != nil {
		return RoutingPreview{}, err
	}
	route := planning.Route
	route.ExpectedCodexCount = 0
	route.Baselines = nil // obsolete account-approval state
	route.Expected = map[string][]string{}
	route.BaselineOff, route.ExpectedOff = offBaselines, map[string]bool{}
	route.ModelBaselines, route.ModelExpected = map[string][]string{}, map[string][]string{}
	keysChanged := false
	for i, plan := range preview.Keys {
		route.Expected[plan.KeyID] = slices.Clone(plan.After)
		route.ExpectedOff[plan.KeyID] = plan.OffAfter
		route.ModelBaselines[plan.KeyID] = slices.Clone(plan.ModelsBaseline)
		route.ModelExpected[plan.KeyID] = slices.Clone(plan.ModelsAfter)
		if !plan.Changed {
			continue
		}
		keysChanged = true
		if !slices.Equal(keys[i].Accounts, plan.After) {
			rawKeys[i]["accounts"], err = json.Marshal(plan.After)
			if err != nil {
				return RoutingPreview{}, err
			}
		}
		if !slices.Equal(keys[i].Models, plan.ModelsAfter) {
			rawKeys[i]["models"], err = json.Marshal(plan.ModelsAfter)
			if err != nil {
				return RoutingPreview{}, err
			}
		}
		if keys[i].Off != plan.OffAfter {
			rawKeys[i]["off"], _ = json.Marshal(plan.OffAfter)
		}
	}
	changed := keysChanged || groups.changed
	if changed {
		route.Pending = true
		route.PendingRestore = false
		route.Previous, route.PreviousOff, route.ModelPrevious = map[string][]string{}, map[string]bool{}, map[string][]string{}
		for _, k := range keys {
			route.Previous[k.ID] = slices.Clone(k.Accounts)
			route.PreviousOff[k.ID] = k.Off
			route.ModelPrevious[k.ID] = slices.Clone(k.Models)
		}
		route.PendingQuarantine = slices.Clone(preview.Quarantined)
		route.GroupOffPrevious = clonedScopes(groups.before)
		route.GroupOffTarget = clonedScopes(groups.target)
		route.GroupOffPendingMembers = clonedScopes(groups.pendingMembers)
		route.GroupOffNextBaselines = clonedScopes(groups.baselines)
		route.GroupOffNextExpected = clonedScopes(groups.expected)
		route.GroupOffNextMembers = clonedScopes(groups.members)
		s.state.Route = route
		if err := s.store.Save(s.state); err != nil {
			s.state.Route = previous
			return RoutingPreview{}, err
		}
		if keysChanged {
			current, err := os.ReadFile(keyPath)
			if err != nil || sha256.Sum256(current) != keyHash {
				return RoutingPreview{}, errors.New("Gateway Key 配置在同步期间改变，将按最新配置重试")
			}
			encoded, err := json.MarshalIndent(rawKeys, "", "  ")
			if err != nil {
				return RoutingPreview{}, err
			}
			if err := AtomicWrite(keyPath, append(encoded, '\n')); err != nil {
				return RoutingPreview{}, err
			}
		}
		_, actual, err := loadKeyDocuments(keyPath)
		if err != nil {
			return RoutingPreview{}, err
		}
		if len(actual) != len(keys) {
			return RoutingPreview{}, errors.New("Gateway Key 写后数量改变")
		}
		for i, k := range actual {
			if k.ID != keys[i].ID || !slices.Equal(k.Accounts, route.Expected[k.ID]) || k.Off != route.ExpectedOff[k.ID] || !slices.Equal(k.Models, route.ModelExpected[k.ID]) {
				return RoutingPreview{}, errors.New("Gateway Key 写后验证失败，将保留事务并重试")
			}
		}
		if err := writeGroupOffDocument(dir, groups); err != nil {
			return RoutingPreview{}, err
		}
	}
	pendingRoute := s.state.Route
	clearRoutingJournal(&route)
	route.GroupOffBaselines, route.GroupOffExpected, route.GroupOffMembers = clonedScopes(groups.baselines), clonedScopes(groups.expected), clonedScopes(groups.members)
	route.Quarantined = quarantineSet(preview.Quarantined)
	route.AwaitingDetection = false
	route.LastError = ""
	if changed {
		route.LastApplied = time.Now()
		route.Audit = append(slices.Clone(route.Audit), RoutingAudit{At: route.LastApplied, Action: "sync", KeyCount: len(keys), Quarantined: slices.Clone(preview.Quarantined)})
		if len(route.Audit) > 100 {
			route.Audit = slices.Clone(route.Audit[len(route.Audit)-100:])
		}
	}
	if !reflect.DeepEqual(previous, route) || changed {
		s.state.Route = route
		if err := s.store.Save(s.state); err != nil {
			s.state.Route = pendingRoute
			return RoutingPreview{}, err
		}
	}
	preview.Pending, preview.LastError = false, ""
	return preview, nil
}

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
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// Recovery is the same deterministic reconciliation as a normal sync. It
// never requires an administrator to approve an old account allowlist.
func (s *Service) RecoverRoutingJournal(ctx context.Context) (string, error) {
	if _, err := s.ApplyRouting(ctx, false); err != nil {
		return "", err
	}
	return "reconciled", nil
}

// Retained for clients of earlier releases; no account-count gate remains.
func (s *Service) ConfigureExpectedAccountCount(_ int) error { return nil }
