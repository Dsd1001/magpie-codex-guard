package check

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// groupOffPlan manages only auto groups in which Codex shares a model with
// an independent provider. It never changes the membership, keys, or rules.
type groupOffPlan struct {
	raw            map[string]json.RawMessage
	groups         []map[string]json.RawMessage
	before         map[string][]string // changed groups only, for crash recovery
	target         map[string][]string // changed groups only, for crash recovery
	pendingMembers map[string][]string // group membership at journal creation
	baselines      map[string][]string // Guard-owned restrictions only
	expected       map[string][]string
	members        map[string][]string
	changed        bool
	sourceHash     [32]byte // reject intervening Magpie provider edits
}

type groupOffRecord struct {
	ID       string   `json:"id"`
	Members  []string `json:"members"`
	Off      []string `json:"off"`
	Routing  string   `json:"routing"`
	Disabled bool     `json:"disabled"`
	Hidden   bool     `json:"hidden"`
}

func readGroupOffDocument(dir string) (map[string]json.RawMessage, []map[string]json.RawMessage, error) {
	doc, groups, _, err := readGroupOffDocumentSnapshot(dir)
	return doc, groups, err
}

func readGroupOffDocumentSnapshot(dir string) (map[string]json.RawMessage, []map[string]json.RawMessage, [32]byte, error) {
	var empty [32]byte
	path := filepath.Join(dir, "providers.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil, empty, nil // older/isolated test fixtures without providers
	}
	if err != nil {
		return nil, nil, empty, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, empty, errors.New("providers.json must be a private regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, empty, err
	}
	if len(b) > 8*1024*1024 {
		return nil, nil, empty, errors.New("providers.json exceeds safe size")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil || doc == nil {
		return nil, nil, empty, errors.New("providers.json is invalid")
	}
	var groups []map[string]json.RawMessage
	if raw, ok := doc["groups"]; ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, nil, empty, errors.New("providers.json groups are invalid")
		}
	}
	return doc, groups, sha256.Sum256(b), nil
}
func groupOffRecords(groups []map[string]json.RawMessage) (map[string]groupOffRecord, error) {
	out := map[string]groupOffRecord{}
	for _, raw := range groups {
		var rec groupOffRecord
		b, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(b, &rec) != nil || rec.ID == "" {
			return nil, errors.New("invalid routing group in providers.json")
		}
		if _, exists := out[rec.ID]; exists {
			return nil, fmt.Errorf("duplicate routing group %s", rec.ID)
		}
		out[rec.ID] = rec
	}
	return out, nil
}

func codexGroupMembers(members []string) ([]string, bool) {
	var codex []string
	independent := false
	for _, member := range members {
		provider, model, ok := strings.Cut(member, "/")
		if !ok || !providerIDPattern.MatchString(provider) || model == "" || strings.ContainsAny(model, "/\\") {
			return nil, false // nested groups and pattern aliases need human review
		}
		if provider == "codex" {
			codex = append(codex, member)
		} else {
			independent = true
		}
	}
	return codex, len(codex) > 0 && independent
}

func allCodexHeld(codex []CodexAccount, excluded []string) bool {
	for _, a := range codex {
		if accountProvider(a) != "codex" {
			continue
		}
		if !slices.Contains(excluded, a.ID) {
			return false
		}
	}
	return true // no live Codex account is also unavailable for production
}

func withCodexOff(baseline, codex []string) []string {
	out := slices.Clone(baseline)
	for _, member := range codex {
		if !slices.Contains(out, member) {
			out = append(out, member)
		}
	}
	return out
}

// planRoutingGroupOff is deliberately strict: manual groups cannot honor
// member Off, administrators' existing Off choices are kept, and external
// edits to a Guard-owned group are rebased without changing its configuration.
func planRoutingGroupOff(dir string, route RoutingState, codex []CodexAccount, excluded []string, restore bool) (groupOffPlan, error) {
	var plan groupOffPlan
	var err error
	plan.raw, plan.groups, plan.sourceHash, err = readGroupOffDocumentSnapshot(dir)
	if err != nil {
		return plan, err
	}
	_, err = groupOffRecords(plan.groups)
	if err != nil {
		return plan, err
	}
	plan.before, plan.target = map[string][]string{}, map[string][]string{}
	plan.pendingMembers = map[string][]string{}
	plan.baselines, plan.expected, plan.members = map[string][]string{}, map[string][]string{}, map[string][]string{}
	all := !restore && allCodexHeld(codex, excluded)

	for i, raw := range plan.groups {
		var rec groupOffRecord
		b, _ := json.Marshal(raw)
		if err := json.Unmarshal(b, &rec); err != nil {
			return plan, err
		}
		base, tracked := route.GroupOffBaselines[rec.ID]
		codexMembers, eligible := codexGroupMembers(rec.Members)
		if !tracked && (!all || !eligible || rec.Hidden || rec.Disabled) {
			continue
		}
		if rec.Routing == "manual" && !tracked {
			continue // Key-level fail-closed protection still applies.
		}
		if tracked {
			// Remove only our previous additions, retaining all administrator
			// member/off/priority/strategy changes. No historical approval.
			previousBase := base
			base = slices.Clone(rec.Off)
			for _, added := range route.GroupOffExpected[rec.ID] {
				if strings.HasPrefix(added, "codex/") && !slices.Contains(previousBase, added) {
					base = slices.DeleteFunc(base, func(value string) bool { return value == added })
				}
			}
		} else {
			base = slices.Clone(rec.Off)
		}
		desired := slices.Clone(base)
		manage := all && eligible && rec.Routing != "manual" && !rec.Hidden && !rec.Disabled
		if manage {
			desired = withCodexOff(base, codexMembers)
			fallback := false
			for _, member := range rec.Members {
				if !strings.HasPrefix(member, "codex/") && !slices.Contains(desired, member) {
					fallback = true
				}
			}
			if !fallback && !tracked {
				continue
			}
		}
		// Account for set-equivalent administrator ordering without churning
		// providers.json or rewriting an unrelated presentation preference.
		left, right := slices.Clone(desired), slices.Clone(rec.Off)
		slices.Sort(left)
		slices.Sort(right)
		if slices.Equal(left, right) {
			desired = slices.Clone(rec.Off)
		}
		if slices.Equal(desired, rec.Off) && !tracked {
			continue // already off by its owner; don't claim it
		}
		if manage {
			plan.baselines[rec.ID] = slices.Clone(base)
			plan.expected[rec.ID] = slices.Clone(desired)
			plan.members[rec.ID] = slices.Clone(rec.Members)
		}
		if !slices.Equal(rec.Off, desired) {
			plan.changed = true
			plan.before[rec.ID] = slices.Clone(rec.Off)
			plan.target[rec.ID] = slices.Clone(desired)
			plan.pendingMembers[rec.ID] = slices.Clone(rec.Members)
			encoded, err := json.Marshal(desired)
			if err != nil {
				return plan, err
			}
			if len(desired) == 0 {
				delete(plan.groups[i], "off")
			} else {
				plan.groups[i]["off"] = encoded
			}
		}
	}
	return plan, nil
}

func writeGroupOffDocument(dir string, plan groupOffPlan) error {
	if !plan.changed {
		return nil
	}
	if plan.sourceHash != ([32]byte{}) {
		current, err := os.ReadFile(filepath.Join(dir, "providers.json"))
		if err != nil || sha256.Sum256(current) != plan.sourceHash {
			return errors.New("providers.json changed during routing transaction; refusing to overwrite")
		}
	}
	groups, err := json.Marshal(plan.groups)
	if err != nil {
		return err
	}
	plan.raw["groups"] = groups
	b, err := json.MarshalIndent(plan.raw, "", "  ")
	if err != nil {
		return err
	}
	if err := AtomicWrite(filepath.Join(dir, "providers.json"), append(b, '\n')); err != nil {
		return err
	}
	return verifyGroupOffValues(dir, plan.target)
}

func verifyGroupOffValues(dir string, expected map[string][]string) error {
	_, groups, err := readGroupOffDocument(dir)
	if err != nil {
		return err
	}
	records, err := groupOffRecords(groups)
	if err != nil {
		return err
	}
	for id, off := range expected {
		live, ok := records[id]
		if !ok || !slices.Equal(live.Off, off) {
			return fmt.Errorf("routing group %s Off value does not match expected value", id)
		}
	}
	return nil
}

// groupOffJournalStatus compares all changed groups with the transaction's
// before and after images. A mixed file is never silently restored.
