package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"meteorcloud/meteorcli/internal/config"
	"meteorcloud/meteorcli/internal/state"
)

// AppliedFile is the state file with what runs per workload. The Python agent
// wrote the same shape (without a version), so an imported file keeps working.
const AppliedFile = "applied-software.json"

// appliedVersion is the format of AppliedFile.
const appliedVersion = 1

// knownKeys are the entry fields this version writes; others are kept.
var knownKeys = []string{"release_id", "revision", "item", "rolled_back_from", "reapply"}

// rolledBack records a release that failed its health check on this device:
// it is not tried again until the desired release changes.
type rolledBack struct {
	ReleaseID string `json:"release_id"`
	Revision  int64  `json:"revision"`
	Reason    string `json:"reason"`
}

// applied is one workload's entry.
type applied struct {
	ReleaseID string
	// Revision is a high-water mark: an older signed revision is refused.
	Revision int64
	// Item is the applied desired item, what a later failed update rolls back to.
	Item           json.RawMessage
	RolledBackFrom *rolledBack
	// Reapply says the running workload no longer matches what was applied;
	// it stays set until an apply succeeds.
	Reapply bool
	// extra keeps fields this version does not know.
	extra config.Object
}

// appliedState is AppliedFile in memory: workload key to entry.
type appliedState map[string]*applied

// loadApplied reads AppliedFile. A missing or damaged file is an empty state
// (a damaged one has been moved aside).
func loadApplied(st *state.Store) (appliedState, error) {
	var raw map[string]json.RawMessage
	_, err := st.Read(AppliedFile, &raw)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, state.ErrCorrupt):
		return appliedState{}, nil
	case err != nil:
		return nil, fmt.Errorf("applied state: %w", err)
	}
	out := appliedState{}
	for key, value := range raw {
		if key == "version" {
			continue
		}
		var fields config.Object
		if json.Unmarshal(value, &fields) != nil || fields == nil {
			continue
		}
		a := &applied{extra: config.Object{}}
		var known struct {
			ReleaseID      any             `json:"release_id"`
			Revision       json.Number     `json:"revision"`
			Item           json.RawMessage `json:"item"`
			RolledBackFrom *rolledBack     `json:"rolled_back_from"`
			Reapply        bool            `json:"reapply"`
		}
		_ = json.Unmarshal(value, &known)
		if known.ReleaseID != nil {
			a.ReleaseID = fmt.Sprint(known.ReleaseID)
		}
		a.Revision = -1
		if n, err := known.Revision.Int64(); err == nil {
			a.Revision = n
		}
		if len(known.Item) > 0 && string(known.Item) != "null" {
			a.Item = known.Item
		}
		a.RolledBackFrom, a.Reapply = known.RolledBackFrom, known.Reapply
		for k, v := range fields {
			a.extra[k] = v
		}
		for _, k := range knownKeys {
			delete(a.extra, k)
		}
		out[key] = a
	}
	return out, nil
}

// save writes the whole state (0600: an item can hold the release's env values).
func (s appliedState) save(st *state.Store) error {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]config.Object, len(s))
	for _, k := range keys {
		a := s[k]
		obj := config.Object{}
		for ek, ev := range a.extra {
			obj[ek] = ev
		}
		set := func(name string, v any) {
			data, _ := json.Marshal(v)
			obj[name] = data
		}
		set("release_id", a.ReleaseID)
		set("revision", a.Revision)
		if a.Item != nil {
			obj["item"] = a.Item
		}
		if a.RolledBackFrom != nil {
			set("rolled_back_from", a.RolledBackFrom)
		}
		if a.Reapply {
			set("reapply", true)
		}
		out[k] = obj
	}
	if err := st.Write(AppliedFile, appliedVersion, out); err != nil {
		return fmt.Errorf("applied state: %w", err)
	}
	return nil
}

// record stores a successful apply of (releaseID, revision). The revision is a
// high-water mark unless this records a device-side rollback. item nil keeps
// the stored item. Rollback and reapply marks are cleared unless given.
func (s appliedState) record(key, releaseID string, revision int64, item json.RawMessage, from *rolledBack, reapply bool) {
	prev := s[key]
	next := &applied{ReleaseID: releaseID, Revision: revision, Item: item, RolledBackFrom: from, Reapply: reapply, extra: config.Object{}}
	if prev != nil {
		next.extra = prev.extra
		if from == nil && prev.Revision > revision {
			next.Revision, next.ReleaseID = prev.Revision, prev.ReleaseID
		}
		if item == nil {
			next.Item = prev.Item
		}
	}
	s[key] = next
}
