// Package check provides fixed Codex/API-key probes and production-key quarantine.
// It does not disable providers globally or execute untrusted model-generated code.
package check

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	GatewayURL string `json:"gateway_url"`
	GatewayKey string `json:"gateway_key,omitempty"`
	DailyLimit int    `json:"daily_limit"`
}

type AccountTarget struct {
	Account             string        `json:"account"`
	Model               string        `json:"model"`
	Enabled             bool          `json:"enabled"`
	State               string        `json:"state"`
	Reason              string        `json:"reason,omitempty"`
	CheckedAt           time.Time     `json:"checked_at,omitempty"`
	NextCheckAt         time.Time     `json:"next_check_at,omitempty"`
	ConsecutiveFails    int           `json:"consecutive_fails"`
	ConsecutivePasses   int           `json:"consecutive_passes"`
	LastAutoPrompt      string        `json:"last_auto_prompt,omitempty"`
	PromptRotation      uint64        `json:"prompt_rotation,omitempty"`
	FingerprintExpected string        `json:"fingerprint_expected,omitempty"`
	TimingOverride      *TimingPolicy `json:"timing_override,omitempty"`
	Missing             bool          `json:"missing,omitempty"`
	FingerprintVersion  string        `json:"fingerprint_version,omitempty"`
	LastFingerprintAt   time.Time     `json:"last_fingerprint_at,omitempty"`
	NextFingerprintAt   time.Time     `json:"next_fingerprint_at,omitempty"`
}

type FingerprintCandidate struct {
	Model       string  `json:"model"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
}
type FingerprintReport struct {
	Verdict     string                 `json:"verdict"` // match, mismatch, indeterminate
	Prediction  string                 `json:"prediction,omitempty"`
	Probability float64                `json:"probability,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Diagnostic  string                 `json:"diagnostic,omitempty"`
	Candidates  []FingerprintCandidate `json:"candidates,omitempty"`
	UsedOutputs int                    `json:"used_outputs"`
}
type AccountResult struct {
	ID            string             `json:"id"`
	Batch         string             `json:"batch,omitempty"`
	Account       string             `json:"account"`
	Model         string             `json:"model"`
	Prompt        string             `json:"prompt"`
	PromptName    string             `json:"prompt_name,omitempty"`
	Verdict       string             `json:"verdict"`
	Time          time.Time          `json:"time"`
	Answer        string             `json:"answer,omitempty"`
	Error         string             `json:"error,omitempty"`
	Tokens        int                `json:"tokens"`
	ExpectedCount int                `json:"expected_count,omitempty"`
	Fingerprint   *FingerprintReport `json:"fingerprint,omitempty"`
}
type QuarantineHold struct {
	Account            string            `json:"account"` // stable login ID, not email
	Model              string            `json:"model"`
	Risk               string            `json:"risk"` // isolated; legacy pending/high/low are migrated
	Prompt             string            `json:"prompt,omitempty"`
	Reason             string            `json:"reason"`
	Since              time.Time         `json:"since"`
	NextCheckAt        time.Time         `json:"next_check_at"`
	FirstRecheckDone   bool              `json:"first_recheck_done"`
	ConfirmationPasses int               `json:"confirmation_passes"`
	Fingerprint        FingerprintReport `json:"fingerprint"`
}

type State struct {
	Config           Config                    `json:"config"`
	AccountTargets   map[string]*AccountTarget `json:"account_targets"`
	AccountResults   []AccountResult           `json:"account_results"`
	CustomPrompts    []Prompt                  `json:"custom_prompts,omitempty"`
	AutoPromptPolicy AutoPromptPolicy          `json:"auto_prompt_policy"`
	TimingPolicy     TimingPolicy              `json:"timing_policy"`
	Holds            map[string]QuarantineHold `json:"holds"`
	Route            RoutingState              `json:"route"`
	Alias            string                    `json:"alias"`
	Spent            map[string]int            `json:"spent,omitempty"` // actual reserved outgoing HTTP attempts
}

type Service struct {
	mu                 sync.Mutex
	state              State
	dir, gate          string
	running            map[string]bool // prevents changes while account checks are in progress
	accountProbeActive bool
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	store              *Store
	health             string
	fingerprint        FingerprintRunner
	scheduleWake       chan struct{}
}

func Secret() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func New(dir, gate string) (*Service, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		return nil, err
	}
	s := &Service{dir: dir, gate: gate, store: store, running: map[string]bool{}, scheduleWake: make(chan struct{}, 1)}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.state = State{Config: Config{DailyLimit: 600}, TimingPolicy: DefaultTimingPolicy(), AccountTargets: map[string]*AccountTarget{}, AccountResults: []AccountResult{}, Holds: map[string]QuarantineHold{}, Alias: Secret(), Spent: map[string]int{}}
	if err := store.Load(&s.state); err != nil {
		store.Close()
		return nil, err
	}
	if s.state.AccountTargets == nil {
		s.state.AccountTargets = map[string]*AccountTarget{}
	}
	if s.state.Holds == nil {
		s.state.Holds = map[string]QuarantineHold{}
	}
	if s.state.Spent == nil {
		s.state.Spent = map[string]int{}
	}
	if s.state.Alias == "" {
		s.state.Alias = Secret()
	}
	if s.state.Config.DailyLimit <= 0 {
		s.state.Config.DailyLimit = 600
	}
	if err := s.state.TimingPolicy.validate(); err != nil {
		store.Close()
		return nil, err
	}
	for _, t := range s.state.AccountTargets {
		if t == nil {
			continue
		}
		if t.TimingOverride != nil {
			if err := t.TimingOverride.validate(); err != nil {
				store.Close()
				return nil, err
			}
		}
		if t.State == "checking" {
			t.State = "unavailable"
			t.Reason = "后台重启，中断的检测不计入错误"
			t.NextCheckAt = time.Now().Add(s.timingForTargetLocked(t).unavailable())
		}
	}
	// Preserve existing route exclusions and deadlines; remove the obsolete
	// high/low/pending distinction without silently releasing any hold.
	for account, hold := range s.state.Holds {
		if hold.Risk != "isolated" {
			hold.Risk = "isolated"
		}
		if hold.Prompt == "" {
			for _, t := range s.state.AccountTargets {
				if t != nil && t.Account == account && t.Model == hold.Model {
					hold.Prompt = t.LastAutoPrompt
					break
				}
			}
		}
		if hold.Prompt == "" {
			hold.Prompt = "milk"
		}
		if hold.NextCheckAt.IsZero() {
			hold.NextCheckAt = time.Now()
		}
		s.state.Holds[account] = hold
		for _, t := range s.state.AccountTargets {
			if t != nil && t.Account == account && t.Model == hold.Model {
				t.State = PhaseIsolated
				t.NextCheckAt = hold.NextCheckAt
				t.LastAutoPrompt = hold.Prompt
			}
		}
	}
	// Retire the legacy standalone fingerprint modes on upgrade. Historical
	// holds are retained, not re-fingerprinted.
	if s.state.AutoPromptPolicy.FingerprintMode != FingerprintObjective {
		s.state.AutoPromptPolicy.FingerprintMode = FingerprintOff
	}
	s.fingerprint = NewFingerprintRunner()
	if err := s.saveLocked(); err != nil {
		store.Close()
		return nil, err
	}
	return s, nil
}
func (s *Service) Close() { s.cancel(); s.wg.Wait(); s.store.Close() }

func AtomicWrite(name string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".guard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), name)
}
func (s *Service) saveLocked() error {
	if err := s.store.Save(s.state); err != nil {
		s.health = err.Error()
		return err
	}
	// No middleware rewrite is needed: probes use the native Codex model ID
	// and X-Magpie-Account. Do not mutate installed plugin code on state saves.
	// The legacy gate argument remains accepted for old plugin launchers.
	s.health = ""
	return nil
}
func (s *Service) Snapshot() (State, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.state)
	var out State
	_ = json.Unmarshal(b, &out)
	out.Config.GatewayKey = ""
	out.Alias = ""
	return out, s.health
}
func (s *Service) Configure(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.GatewayKey == "" {
		c.GatewayKey = s.state.Config.GatewayKey
	}
	if c.DailyLimit < 1 || c.DailyLimit > 10000 {
		return errors.New("每日请求预算必须在 1 到 10000 之间")
	}
	if err := ValidateGateway(c.GatewayURL); err != nil {
		return err
	}
	if strings.TrimSpace(c.GatewayKey) == "" {
		return errors.New("必须配置专用检测 Gateway Key")
	}
	old := s.state.Config
	s.state.Config = c
	if err := s.saveLocked(); err != nil {
		s.state.Config = old
		return err
	}
	return nil
}
func (s *Service) reserveRequest() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.state.Config
	if cfg.GatewayURL == "" || cfg.GatewayKey == "" {
		return cfg, errors.New("网关或检测 Key 尚未配置")
	}
	day := time.Now().UTC().Format("2006-01-02")
	if s.state.Spent[day] >= cfg.DailyLimit {
		return cfg, errors.New("每日检测请求预算已耗尽")
	}
	s.state.Spent[day]++
	if err := s.store.Save(s.state); err != nil {
		s.state.Spent[day]--
		return cfg, err
	}
	return cfg, nil
}

func (s *Service) reconcileOrphanHoldsLocked() {
	// Never silently clear Holds on account deletion, login expiry, or rubric edits.
	// An orphan hold blocks restore and requires explicit operator recovery.
}
