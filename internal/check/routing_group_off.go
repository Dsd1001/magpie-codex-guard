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
	var total int
	for _, a := range codex {
		if accountProvider(a) != "codex" {
			continue
		}
		total++
		if !slices.Contains(excluded, a.ID) {
			return false
		}
	}
	return total > 0
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
// edits to a Guard-owned group are rejected instead of overwritten.
func planRoutingGroupOff(dir string, route RoutingState, codex []CodexAccount, excluded []string, restore bool) (groupOffPlan, error) {
	var plan groupOffPlan
	var err error
	plan.raw, plan.groups, plan.sourceHash, err = readGroupOffDocumentSnapshot(dir)
	if err != nil {
		return plan, err
	}
	records, err := groupOffRecords(plan.groups)
	if err != nil {
		return plan, err
	}
	plan.before, plan.target = map[string][]string{}, map[string][]string{}
	plan.pendingMembers = map[string][]string{}
	plan.baselines, plan.expected, plan.members = map[string][]string{}, map[string][]string{}, map[string][]string{}
	all := !restore && allCodexHeld(codex, excluded)

	// A previously owned group must still exist and have identical members.
	for id, expected := range route.GroupOffExpected {
		live, exists := records[id]
		if !exists || !slices.Equal(live.Off, expected) || !slices.Equal(live.Members, route.GroupOffMembers[id]) {
			return plan, fmt.Errorf("routing group %s changed outside Codex Guard; refusing to overwrite", id)
		}
		if _, ok := route.GroupOffBaselines[id]; !ok {
			return plan, fmt.Errorf("routing group %s is missing its Off baseline", id)
		}
	}
	for id := range route.GroupOffBaselines {
		if _, ok := route.GroupOffExpected[id]; !ok {
			return plan, fmt.Errorf("routing group %s is missing its tracked state", id)
		}
	}
	for i, raw := range plan.groups {
		var rec groupOffRecord
		b, _ := json.Marshal(raw)
		if err := json.Unmarshal(b, &rec); err != nil {
			return plan, err
		}
		base, tracked := route.GroupOffBaselines[rec.ID]
		codexMembers, eligible := codexGroupMembers(rec.Members)
		if !tracked && (!all || !eligible || !strings.HasPrefix(rec.ID, "auto-") || rec.Hidden || rec.Disabled) {
			continue
		}
		if rec.Routing == "manual" {
			if tracked {
				return plan, fmt.Errorf("managed routing group %s was switched to manual routing", rec.ID)
			}
			// Manual routing ignores member Off. Do not modify this group;
			// the restricted Gateway Key still denies all direct Codex calls.
			continue
		}
		if !tracked {
			base = slices.Clone(rec.Off)
		}
		desired := slices.Clone(base)
		if all {
			if !eligible {
				return plan, fmt.Errorf("routing group %s no longer has a safe non-Codex fallback", rec.ID)
			}
			desired = withCodexOff(base, codexMembers)
			if len(desired) >= len(rec.Members) {
				if tracked {
					return plan, fmt.Errorf("managed routing group %s has no live fallback", rec.ID)
				}
				// No eligible independent member: keep this group unchanged.
				// The Key model scope remains the fail-closed boundary.
				continue
			}
		}
		if slices.Equal(desired, rec.Off) && !tracked {
			continue // already off by its owner; don't claim it
		}
		if all {
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
func groupOffJournalStatus(dir string, route RoutingState) (before, after bool, err error) {
	before, after = true, true
	if len(route.GroupOffPrevious) == 0 && len(route.GroupOffTarget) == 0 {
		return true, true, nil
	}
	_, groups, err := readGroupOffDocument(dir)
	if err != nil {
		return false, false, err
	}
	records, err := groupOffRecords(groups)
	if err != nil {
		return false, false, err
	}
	for id, previous := range route.GroupOffPrevious {
		live, ok := records[id]
		if !ok || !slices.Equal(live.Members, route.GroupOffPendingMembers[id]) {
			return false, false, fmt.Errorf("routing group %s changed during interrupted transaction", id)
		}
		if !slices.Equal(live.Off, previous) {
			before = false
		}
		if !slices.Equal(live.Off, route.GroupOffTarget[id]) {
			after = false
		}
	}
	return before, after, nil
}

// completeGroupOffJournal is used only by the explicit recovery action,
// under both routing locks. The Key file must already match its target.
// It never expands any Gateway Key model or account permission.
func completeGroupOffJournal(dir string, route RoutingState) error {
	before, after, err := groupOffJournalStatus(dir, route)
	if err != nil {
		return err
	}
	if after {
		return nil
	}
	if !before {
		return errors.New("routing groups differ from both journal images")
	}
	raw, groups, hash, err := readGroupOffDocumentSnapshot(dir)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, group := range groups {
		var id string
		if err := json.Unmarshal(group["id"], &id); err != nil {
			return err
		}
		desired, tracked := route.GroupOffTarget[id]
		if !tracked {
			continue
		}
		seen[id] = true
		if len(desired) == 0 {
			delete(group, "off")
		} else {
			b, err := json.Marshal(desired)
			if err != nil {
				return err
			}
			group["off"] = b
		}
	}
	if len(seen) != len(route.GroupOffTarget) {
		return errors.New("routing group disappeared during journal recovery")
	}
	return writeGroupOffDocument(dir, groupOffPlan{raw: raw, groups: groups, sourceHash: hash, target: route.GroupOffTarget, changed: true})
}
