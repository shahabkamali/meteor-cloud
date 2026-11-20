// Package deploy is the module that installs the software the control plane
// wants on this device (contracts/device-agent-v1.md, "Desired software and
// downloads"). Each time the heartbeat says software work waits, it lists the
// desired items, verifies their signatures, downloads and checks artifacts,
// installs changed releases through a runtime (systemd, docker, compose),
// waits for the release's health check, rolls back to the previous release when
// it fails, and leaves one report per workload in the outbox for the heartbeat.
//
// It runs in its own goroutine: a pull that hangs for minutes never delays a
// heartbeat. It is not critical, so a crash loop parks it and leaves the
// device reachable.
package deploy

import (
	"context"
	"errors"
	"time"

	"meteorcloud/meteorcli/internal/agent"
	"meteorcloud/meteorcli/internal/identity"
	"meteorcloud/meteorcli/internal/platform"
	"meteorcloud/meteorcli/internal/telemetry"
)

// name is the module's id.
const name = "deploy"

// tickEvery keeps the module's health fresh while it waits for work.
const tickEvery = 30 * time.Second

// Module reconciles desired software.
type Module struct {
	// Kinds replaces the registry (tests); nil means Runtimes.
	Kinds map[string]Kind
	// Tools replaces the host's tool probe (tests); nil means a cached probe.
	Tools func(ctx context.Context) platform.Tools
	// waiter replaces the real-time health gate (tests).
	waiter *waiter
	// now replaces time.Now (tests).
	now func() time.Time
}

// Name implements agent.Module.
func (m *Module) Name() string { return name }

// Critical implements agent.Module: a failing deploy must never take the device offline.
func (m *Module) Critical() bool { return false }

// Run implements agent.Module: reconcile whenever the heartbeat says software
// work waits (every heartbeat), one pass at a time.
func (m *Module) Run(ctx context.Context, d agent.Deps) error {
	work := d.Signals.Subscribe(agent.Is(agent.WorkWaiting{Kind: "software"}))
	defer work.Close()
	kinds := m.Kinds
	if kinds == nil {
		kinds = Runtimes(d.Helper, d.Paths.ArtifactsDir)
	}
	tools := m.Tools
	if tools == nil {
		cache := &telemetry.Tools{Host: d.Host}
		tools = cache.Get
	}
	w := m.waiter
	if w == nil {
		w = realWaiter(func() { d.Health.Tick(name) })
	}
	now := m.now
	if now == nil {
		now = time.Now
	}
	d.Health.Set(name, agent.StateRunning, nil)
	tick := time.NewTicker(tickEvery)
	defer tick.Stop()
	for {
		d.Health.Tick(name)
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			continue
		case <-work.C():
			work.Take()
		}
		token, err := d.Identity.Token()
		if err != nil {
			if !errors.Is(err, identity.ErrNotEnrolled) {
				d.Log.Info("deploy paused", "reason", err)
			}
			continue
		}
		c := &cycle{d: d, log: d.Log, kinds: kinds, tools: tools(ctx), waiter: w, token: token, now: now}
		if err := c.run(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, errAuth) {
			d.Log.Error("reconcile", "err", err)
		}
	}
}
