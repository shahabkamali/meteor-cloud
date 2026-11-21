package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"meteorcloud/meteorcli/internal/agent"
	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/deploy/runtime"
	"meteorcloud/meteorcli/internal/platform"
	"meteorcloud/meteorcli/internal/signing"
	"meteorcloud/meteorcli/internal/state"
)

// errAuth stops a cycle after the server refused the device token; identity
// has been told and decides what happens next.
var errAuth = errors.New("the server refused the device token")

// cycle is one reconcile pass: list desired software, verify, apply what
// changed, check what did not, and leave one report per workload in the outbox.
type cycle struct {
	d       agent.Deps
	log     *slog.Logger
	kinds   map[string]Kind
	tools   platform.Tools
	waiter  *waiter
	token   string
	applied appliedState
	now     func() time.Time
}

// authFailed tells identity about a 401/403 and returns errAuth.
func (c *cycle) authFailed(err error) error {
	c.d.Identity.AuthFailed(c.token)
	c.log.Warn("the server refused the device token; waiting for identity", "err", err)
	return errAuth
}

// run does one pass. It returns errAuth or ctx's error; every other problem
// is reported per workload.
func (c *cycle) run(ctx context.Context) error {
	items, err := c.d.API.Software(ctx, c.token)
	if api.IsAuth(err) {
		return c.authFailed(err)
	}
	if err != nil {
		c.log.Warn("could not list desired software", "err", err)
		return nil
	}
	if c.applied, err = loadApplied(c.d.State); err != nil {
		c.log.Error("read applied state; trying again next cycle", "err", err)
		return nil
	}
	verifier := &signing.Verifier{
		State: c.d.State, DeviceID: c.d.Identity.DeviceID(), Log: c.log,
		CredentialFP: signing.CredentialFingerprint(c.token),
		Fetch: func(ctx context.Context) ([]api.SigningKey, error) {
			return c.d.API.SigningKeys(ctx, c.token)
		},
	}

	var accepted []api.DesiredItem
	for _, item := range items {
		if item.WorkloadKey == "" {
			continue
		}
		if _, ok := c.kinds[item.Kind]; !ok {
			c.put(failed(item.WorkloadKey, fmt.Sprintf("Unsupported release kind: %s", pyRepr(item))))
			continue
		}
		if err := verifier.Check(ctx, item); err != nil {
			if api.IsAuth(err) {
				return c.authFailed(err)
			}
			var refused *signing.Refused
			msg := fmt.Sprintf("Could not check the update signature (%v); will retry.", err)
			if errors.As(err, &refused) {
				msg = refused.Reason
			}
			c.log.Warn("refusing desired software", "workload", item.WorkloadKey, "reason", msg)
			c.put(failed(item.WorkloadKey, msg))
			continue
		}
		if a := c.applied[item.WorkloadKey]; a != nil && a.Revision >= 0 && item.ReleaseID != "" && item.Revision < a.Revision {
			msg := fmt.Sprintf("Desired revision %d is older than applied revision %d; refusing rollback.", item.Revision, a.Revision)
			c.log.Warn("refusing desired software", "workload", item.WorkloadKey, "reason", msg)
			c.put(failed(item.WorkloadKey, msg))
			continue
		}
		accepted = append(accepted, item)
	}

	for _, item := range accepted {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := c.reconcile(ctx, item)
		if errors.Is(err, errAuth) {
			return err
		}
		c.put(r)
	}
	return ctx.Err()
}

// pyRepr formats the kind as the Python agent's {kind!r} did.
func pyRepr(item api.DesiredItem) string {
	raw := item.Field("kind")
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return "None"
	case item.Kind == "":
		return string(raw) // not a string: shown as sent
	}
	return "'" + item.Kind + "'"
}

// put leaves a report for the next heartbeat; only the latest per workload is kept.
func (c *cycle) put(r report) {
	key, _ := r["workload_key"].(string)
	if _, err := c.d.Outbox.Put(state.KindSoftwareReport, key, r); err != nil {
		c.log.Error("store software report", "workload", key, "err", err)
	}
}

// emit leaves a device event for the MQTT bus (only the latest per workload).
func (c *cycle) emit(kind, app string, extra map[string]any) {
	if _, err := c.d.Outbox.Put(state.KindEvent, "app:"+app, event(kind, app, c.now(), extra)); err != nil {
		c.log.Error("store event", "type", kind, "err", err)
	}
}

// progress sends a progress-only heartbeat, best effort, as the Python agent
// did, so the console shows a download moving. Results go through the outbox.
func (c *cycle) progress(ctx context.Context, key string, percent int) {
	raw, _ := json.Marshal(updating(key, percent))
	_, err := c.d.API.Heartbeat(ctx, c.token, api.HeartbeatRequest{SoftwareReport: []json.RawMessage{raw}})
	if err != nil {
		c.log.Warn("could not report progress", "workload", key, "err", err)
	}
}

// releaseOf is (release_id, revision); ok is false without a release id.
func releaseOf(item api.DesiredItem) (string, int64, bool) {
	return item.ReleaseID, item.Revision, item.ReleaseID != ""
}

func (c *cycle) workload(item api.DesiredItem, artifact string) runtime.Workload {
	return runtime.Workload{Key: item.WorkloadKey, ReleaseID: item.ReleaseID, Version: item.ReleaseVersion, Spec: item.Spec, Artifact: artifact}
}

// reconcile handles one verified item and returns its report.
func (c *cycle) reconcile(ctx context.Context, item api.DesiredItem) (report, error) {
	key := item.WorkloadKey
	recorded := c.applied[key]
	if r := c.stillRolledBack(ctx, item, recorded); r != nil {
		return r, nil
	}
	releaseID, revision, hasID := releaseOf(item)
	wasApplied := hasID && recorded != nil && recorded.ReleaseID == releaseID && recorded.Revision == revision
	if wasApplied && !recorded.Reapply {
		if r := c.healthOnly(ctx, item); r != nil {
			return r, nil
		}
	}
	if hasBinding(item.Spec) {
		return failed(key, "MeteorCloud application bindings (spec.meteorcloud) are not supported by this agent yet."), nil
	}

	r, err := c.apply(ctx, item)
	if err != nil {
		return nil, err
	}
	g := gateOf(item.Spec)
	if g != nil && r.status() == syncInSync {
		rt := c.kinds[item.Kind].Runtime
		w := c.workload(item, "")
		reason := c.waiter.wait(ctx, func(ctx context.Context) runtime.Health { return rt.Check(ctx, w) }, *g)
		if reason == "" {
			r = inSync(item, "healthy", "")
			c.emit("app.healthy", key, nil)
		} else {
			r = failed(key, "Health check failed: "+reason)
			c.emit("app.unhealthy", key, map[string]any{"problem": reason})
		}
	}
	if g != nil && g.rollback && r.status() == syncFailed {
		rolled, err := c.rollBack(ctx, item, r, recorded)
		if err != nil {
			return nil, err
		}
		if rolled.status() == syncRolledBack {
			return rolled, nil
		}
		r = rolled
	}
	if r.status() == syncInSync && hasID {
		c.applied.record(key, releaseID, revision, item.Raw, nil, false)
		if err := c.applied.save(c.d.State); err != nil {
			c.log.Error("save applied state", "workload", key, "err", err)
		}
	}
	return r, nil
}

// hasBinding reports a MeteorCloud application binding (spec.meteorcloud).
func hasBinding(spec json.RawMessage) bool {
	var s struct {
		MeteorCloud json.RawMessage `json:"meteorcloud"`
	}
	return json.Unmarshal(spec, &s) == nil && len(s.MeteorCloud) > 0 && string(s.MeteorCloud) != "null"
}

// apply downloads what item needs and installs it. Only errAuth is returned as
// an error; every other failure is the failed report.
func (c *cycle) apply(ctx context.Context, item api.DesiredItem) (report, error) {
	key := item.WorkloadKey
	kind := c.kinds[item.Kind]
	if !kind.Available(c.tools) {
		return failed(key, kind.Missing), nil
	}
	artifact := ""
	if item.ArtifactID != "" {
		path, err := c.ensureArtifact(ctx, item)
		if api.IsAuth(err) {
			return nil, c.authFailed(err)
		}
		if err != nil {
			c.log.Warn("download failed", "workload", key, "err", err)
			return failed(key, message(err)), nil
		}
		artifact = path
	}
	c.progress(ctx, key, 100)
	res, err := kind.Runtime.Apply(ctx, c.workload(item, artifact))
	if err != nil {
		c.log.Warn("apply failed", "workload", key, "kind", item.Kind, "err", err)
		return failed(key, message(err)), nil
	}
	c.log.Info("applied", "workload", key, "kind", item.Kind, "release", item.ReleaseVersion)
	c.emit("app.started", key, nil)
	return inSync(item, healthWord(res.Health.State), res.Health.Problem), nil
}

// message is the text of err for the console: an API or helper error's own
// message without its code.
func message(err error) string {
	var e *api.Error
	if errors.As(err, &e) {
		return e.Message
	}
	return err.Error()
}

// healthOnly reports an applied workload's health without installing it again.
// nil means install it again: the runtime is missing or the workload is gone.
func (c *cycle) healthOnly(ctx context.Context, item api.DesiredItem) report {
	kind, ok := c.kinds[item.Kind]
	if !ok || !kind.Available(c.tools) {
		return nil
	}
	h := kind.Runtime.Check(ctx, c.workload(item, ""))
	if h.State == runtime.Missing {
		return nil
	}
	return inSync(item, healthWord(h.State), h.Problem)
}

// storedItem decodes an applied entry's item.
func storedItem(a *applied) (api.DesiredItem, bool) {
	if a == nil || a.Item == nil {
		return api.DesiredItem{}, false
	}
	var item api.DesiredItem
	if json.Unmarshal(a.Item, &item) != nil || item.WorkloadKey == "" {
		return api.DesiredItem{}, false
	}
	return item, true
}

// rollBack applies the release that ran before item; failure stands when there
// is none or it is the same release.
func (c *cycle) rollBack(ctx context.Context, item api.DesiredItem, failure report, recorded *applied) (report, error) {
	previous, ok := storedItem(recorded)
	releaseID, revision, hasID := releaseOf(item)
	reason := failure.lastError()
	if reason == "" {
		reason = "the update failed"
	}
	prevID, prevRev, prevHasID := releaseOf(previous)
	if !ok || !hasID || !prevHasID || (prevID == releaseID && prevRev == revision) {
		return failure, nil
	}
	c.log.Warn("update failed; rolling back", "workload", item.WorkloadKey, "reason", reason, "to", previous.ReleaseVersion)
	restored, err := c.apply(ctx, previous)
	if err != nil {
		return nil, err
	}
	if restored.status() != syncInSync {
		return failed(item.WorkloadKey, fmt.Sprintf("%s; rolling back to %s also failed: %s", reason, previous.ReleaseVersion, restored.lastError())), nil
	}
	c.applied.record(item.WorkloadKey, prevID, prevRev, previous.Raw, &rolledBack{ReleaseID: releaseID, Revision: revision, Reason: reason}, false)
	if err := c.applied.save(c.d.State); err != nil {
		c.log.Error("save applied state", "workload", item.WorkloadKey, "err", err)
	}
	health, _ := restored["health"].(string)
	return rolledBackReport(item, previous, health, reason), nil
}

// stillRolledBack reports a desired release this device already rolled back
// from (until the desired release changes), or nil to apply it.
func (c *cycle) stillRolledBack(ctx context.Context, item api.DesiredItem, recorded *applied) report {
	if recorded == nil || recorded.RolledBackFrom == nil {
		return nil
	}
	releaseID, revision, ok := releaseOf(item)
	previous, have := storedItem(recorded)
	if !ok || !have {
		return nil
	}
	from := recorded.RolledBackFrom
	if from.ReleaseID != releaseID || from.Revision != revision {
		return nil
	}
	health := "unknown"
	if r := c.healthOnly(ctx, previous); r != nil {
		health, _ = r["health"].(string)
	}
	reason := from.Reason
	if reason == "" {
		reason = "health check failed"
	}
	return rolledBackReport(item, previous, health, reason)
}
