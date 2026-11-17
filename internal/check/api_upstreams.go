package check

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// APIEnrollment contains public identities, never upstream credentials.
// Enrollment is explicit; merely adding a provider does not spend probe quota.
type APIEnrollment struct {
	Provider string `json:"provider"`
	KeyID    string `json:"key_id"`
	Name     string `json:"name"`
}

var providerIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var apiModelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)

type providerDocument struct {
	Providers []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Key  string `json:"key"`
		Keys []struct {
			Key string `json:"key"`
			Off bool   `json:"off,omitempty"`
		} `json:"keys"`
		Models []string `json:"models"`
	} `json:"providers"`
}

func readProviderDocument(dir string) (providerDocument, error) {
	var d providerDocument
	b, err := os.ReadFile(filepath.Join(dir, "providers.json"))
	if err != nil {
		return d, err
	}
	if len(b) > 8*1024*1024 || json.Unmarshal(b, &d) != nil {
		return d, errors.New("Magpie API provider configuration is invalid")
	}
	return d, nil
}

func discoverAPIAccounts(dir string) ([]CodexAccount, error) {
	b, err := os.ReadFile(filepath.Join(dir, "api-upstreams.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var enrolled []APIEnrollment
	if len(b) > 64*1024 || json.Unmarshal(b, &enrolled) != nil {
		return nil, errors.New("API upstream enrollment is invalid")
	}
	d, err := readProviderDocument(dir)
	if err != nil {
		return nil, err
	}
	out := []CodexAccount{}
	seen := map[string]bool{}
	for _, e := range enrolled {
		if !providerIDPattern.MatchString(e.Provider) || e.Provider == "codex" || len(e.KeyID) != 10 {
			return nil, errors.New("invalid API upstream identity")
		}
		found := false
		pin := ""
		for _, p := range d.Providers {
			if p.ID != e.Provider {
				continue
			}
			keys := []string{}
			if p.Key != "" {
				keys = append(keys, p.Key)
			}
			for _, k := range p.Keys {
				if !k.Off && k.Key != "" && !slices.Contains(keys, k.Key) && p.Key != "" {
					keys = append(keys, k.Key)
				}
			}
			for _, key := range keys {
				if key == "" {
					continue
				}
				sum := sha256.Sum256([]byte(key))
				if hex.EncodeToString(sum[:5]) == e.KeyID {
					found = true
					// pinTo matches the routing trace ID. Magpie uses the
					// provider ID for one active key and provider#keyID for
					// several; candidate.who() is a different namespace.
					pin = e.Provider
					if len(keys) > 1 {
						pin += "#" + e.KeyID
					}
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("enrolled API upstream %s has no matching saved key", e.Provider)
		}
		sum := sha256.Sum256([]byte("magpie api\n" + e.Provider + "\n" + e.KeyID))
		id := hex.EncodeToString(sum[:8])
		if seen[id] {
			return nil, errors.New("duplicate API upstream enrollment")
		}
		seen[id] = true
		name := e.Name
		if name == "" {
			name = e.Provider
		}
		out = append(out, CodexAccount{ID: id, User: name + " · API", Provider: e.Provider, Pin: pin})
	}
	return out, nil
}

func accountProvider(a CodexAccount) string {
	if a.Provider == "" {
		return "codex"
	}
	return a.Provider
}
func modelProvider(model string) string { p, _, _ := strings.Cut(model, "/"); return p }
func matchesAccountModel(a CodexAccount, model string) bool {
	return accountProvider(a) == modelProvider(model)
}

func apiProviderNames(dir string) ([]string, error) {
	d, err := readProviderDocument(dir)
	if err != nil {
		return nil, err
	}
	out := []string{"codex"}
	for _, p := range d.Providers {
		if providerIDPattern.MatchString(p.ID) && !slices.Contains(out, p.ID) {
			out = append(out, p.ID)
		}
	}
	sort.Strings(out)
	return out, nil
}

func enrolledAPIModels() []Model {
	dir, err := MagpieDir()
	if err != nil {
		return nil
	}
	accounts, err := discoverAPIAccounts(dir)
	if err != nil {
		return nil
	}
	d, err := readProviderDocument(dir)
	if err != nil {
		return nil
	}
	enrolled := map[string]bool{}
	for _, a := range accounts {
		enrolled[a.Provider] = true
	}
	out := []Model{}
	for _, p := range d.Providers {
		if !enrolled[p.ID] {
			continue
		}
		for _, m := range p.Models {
			id := p.ID + "/" + m
			if apiModelPattern.MatchString(id) {
				out = append(out, Model{ID: id, Group: p.ID})
			}
		}
	}
	return out
}
func isEnrolledAPIModel(id string) bool {
	for _, m := range enrolledAPIModels() {
		if m.ID == id {
			return true
		}
	}
	return false
}

// nonCodexModelScopes returns the existing explicit non-Codex models. It is
// safe to keep a Gateway Key enabled with this scope when no Codex account is
// eligible. Never expand groups or a wildcard model list: those may route to
// the quarantined Codex provider through an alias.
func nonCodexModelScopes(models, providers []string) ([]string, bool) {
	if len(models) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(models))
	for _, pattern := range models {
		provider, name, ok := strings.Cut(pattern, "/")
		if !ok || name == "" || strings.ContainsAny(name, "/\\") || provider == "group" || !slices.Contains(providers, provider) {
			return nil, false
		}
		if provider != "codex" {
			out = append(out, pattern)
		}
	}
	return out, len(out) > 0
}

// administratorKeyOff distinguishes an unchanged Guard-owned emergency OFF
// from an administrator disabling an otherwise enabled key.
func administratorKeyOff(route RoutingState, key privateGatewayKey) bool {
	baseline, known := route.BaselineOff[key.ID]
	expected, tracked := route.ExpectedOff[key.ID]
	if known && tracked && !baseline && expected && key.Off == expected {
		return false
	}
	return key.Off
}

func codexModelPattern(scope string) bool {
	provider, _, ok := strings.Cut(scope, "/")
	return ok && provider == "codex"
}

// Only restore Codex scopes removed by Guard. Later administrator edits to
// non-Codex scopes (including removals) must never be replaced by an old list.
func modelBaselineForKey(route RoutingState, key privateGatewayKey) []string {
	base, known := route.ModelBaselines[key.ID]
	expected, tracked := route.ModelExpected[key.ID]
	if !known || !tracked || slices.Equal(base, expected) {
		return slices.Clone(key.Models)
	}
	if slices.Equal(key.Models, expected) {
		return slices.Clone(base)
	}
	out := slices.Clone(key.Models)
	// An empty live scope means the administrator explicitly allowed all.
	if len(out) == 0 {
		return out
	}
	for _, scope := range base {
		if codexModelPattern(scope) && !slices.Contains(expected, scope) && !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	return out
}

func modelScopesMayUseCodex(models []string) bool {
	if len(models) == 0 {
		return true
	}
	for _, scope := range models {
		provider, _, ok := strings.Cut(scope, "/")
		// Aliases and provider globs cannot be proven non-Codex here. Keep
		// their existing conservative all-isolated handling.
		if !ok || provider == "group" || provider == "codex" || strings.ContainsAny(provider, "*?[") {
			return true
		}
	}
	return false
}

// Kept under the historical helper name, but now ONLY Codex is managed.
// Legacy API-provider Holds cannot restrict other provider model permissions.
func attachAPIModelScopes(state State, keys []privateGatewayKey, plan []PlannedKeyScope) error {
	var providers []string
	for i, k := range keys {
		base := modelBaselineForKey(state.Route, k)
		plan[i].ModelsBaseline = slices.Clone(base)
		plan[i].ModelsBefore = slices.Clone(k.Models)
		plan[i].ModelsAfter = slices.Clone(k.Models)
		adminOff := administratorKeyOff(state.Route, k)
		if plan[i].IsProbe || adminOff || !modelScopesMayUseCodex(base) {
			plan[i].After = slices.Clone(k.Accounts)
			plan[i].OffAfter = k.Off
			plan[i].CodexBlocked = false
			if plan[i].IsProbe {
				plan[i].ModelsBaseline = slices.Clone(k.Models)
			}
			plan[i].Changed = false
			continue
		}
		plan[i].ModelsAfter = slices.Clone(base)
		if plan[i].CodexBlocked {
			if providers == nil {
				dir, err := MagpieDir()
				if err == nil {
					providers, err = apiProviderNames(dir)
				}
				if err != nil {
					providers = []string{}
				}
			}
			if withoutCodex, safe := nonCodexModelScopes(base, providers); safe {
				plan[i].ModelsAfter = withoutCodex
				plan[i].OffAfter = false
			} else {
				// Preserve the existing fail-closed fallback for aliases or
				// scopes that cannot safely retain an independent provider.
				plan[i].OffAfter = true
			}
		}
		plan[i].Changed = !slices.Equal(k.Accounts, plan[i].After) || !slices.Equal(k.Models, plan[i].ModelsAfter) || k.Off != plan[i].OffAfter
	}
	return nil
}
