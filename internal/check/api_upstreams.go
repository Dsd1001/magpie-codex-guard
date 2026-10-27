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

func heldAPIProviders(state State) map[string]bool {
	out := map[string]bool{}
	for _, hold := range state.Holds {
		if p := modelProvider(hold.Model); p != "" && p != "codex" {
			out[p] = true
		}
	}
	return out
}

// Explicit provider patterns avoid group aliases or provider wildcards that
// could admit an excluded upstream through another name. Unsupported scopes
// are rejected rather than widened or silently treated as isolated.
func apiModelScope(baseline []string, held map[string]bool, providers []string) ([]string, bool, error) {
	if len(held) == 0 {
		return slices.Clone(baseline), false, nil
	}
	patterns := slices.Clone(baseline)
	if len(patterns) == 0 {
		for _, p := range providers {
			patterns = append(patterns, p+"/*")
		}
	}
	out := []string{}
	for _, pattern := range patterns {
		p, m, ok := strings.Cut(pattern, "/")
		if !ok || !providerIDPattern.MatchString(p) || p == "group" || m == "" || strings.ContainsAny(m, "/\\") {
			return nil, false, errors.New("API isolation requires explicit provider model scopes; routing-group scopes require review")
		}
		if !held[p] {
			out = append(out, pattern)
		}
	}
	if len(out) == 0 {
		return slices.Clone(baseline), true, nil
	} // empty means allow-all: turn this key off instead
	return out, false, nil
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

func attachAPIModelScopes(state State, keys []privateGatewayKey, plan []PlannedKeyScope) error {
	held := heldAPIProviders(state)
	providers := []string{}
	if len(held) > 0 {
		dir, err := MagpieDir()
		if err != nil {
			return err
		}
		providers, err = apiProviderNames(dir)
		if err != nil {
			return err
		}
	}
	for i, k := range keys {
		if expected, ok := state.Route.ModelExpected[k.ID]; ok && !slices.Equal(expected, k.Models) {
			return fmt.Errorf("Gateway Key %s model scope changed outside the controller", k.ID)
		}
		baseline, ok := state.Route.ModelBaselines[k.ID]
		if !ok {
			baseline = k.Models
		}
		plan[i].ModelsBaseline = slices.Clone(baseline)
		plan[i].ModelsBefore = slices.Clone(k.Models)
		plan[i].ModelsAfter = slices.Clone(baseline)
		baselineOff, tracked := state.Route.BaselineOff[k.ID]
		if !tracked {
			baselineOff = k.Off
		}
		if k.ID != state.Route.ProbeKeyID && !baselineOff {
			after, block, err := apiModelScope(baseline, held, providers)
			if err != nil {
				return err
			}
			plan[i].ModelsAfter = after
			plan[i].OffAfter = plan[i].OffAfter || block
		}
		plan[i].Changed = plan[i].Changed || !slices.Equal(k.Models, plan[i].ModelsAfter) || k.Off != plan[i].OffAfter
	}
	return nil
}
