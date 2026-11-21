package modules

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"meteorcloud/meteorcli/internal/agent"
	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/config"
	"meteorcloud/meteorcli/internal/deploy"
	"meteorcloud/meteorcli/internal/fakecp"
	"meteorcloud/meteorcli/internal/heartbeat"
	"meteorcloud/meteorcli/internal/helper"
	"meteorcloud/meteorcli/internal/identity"
	"meteorcloud/meteorcli/internal/localrpc"
	"meteorcloud/meteorcli/internal/platform"
	"meteorcloud/meteorcli/internal/state"
)

func TestRegistry(t *testing.T) {
	names := map[string]bool{}
	for _, m := range All() {
		names[m.Name()] = true
		if hb, ok := m.(*heartbeat.Module); ok && len(hb.DeployKinds) != 3 {
			t.Errorf("heartbeat reports deploy kinds %v", hb.DeployKinds)
		}
	}
	if !names["heartbeat"] || !names["deploy"] {
		t.Fatalf("modules %v", names)
	}
}

// TestHungPullDoesNotDelayHeartbeats runs the real heartbeat and deploy modules
// against a helper whose docker.run hangs (a pull that never finishes): the
// heartbeat keeps its interval (the 5 s minimum) while deploy waits.
func TestHungPullDoesNotDelayHeartbeats(t *testing.T) {
	cp := fakecp.New(t)
	cp.On("POST", "/api/v1/agent/heartbeat", fakecp.OK(map[string]any{
		"device_id": "d-1", "status": "online", "heartbeat_interval_seconds": 5,
	}))
	cp.On("GET", "/api/v1/agent/signing-keys", fakecp.Fail(404, "not_found"))
	cp.On("GET", "/api/v1/agent/software", fakecp.OK([]map[string]any{{
		"workload_key": "app", "kind": "docker", "release_id": "r1", "release_name": "app", "release_version": "1",
		"artifact_id": nil, "revision": 1, "spec": map[string]any{"container_name": "app", "image": "slow/image:1"},
	}}))

	root := t.TempDir()
	p := config.DefaultPaths(root)
	_ = os.MkdirAll(p.IdentityDir, 0o700)
	_ = os.MkdirAll(p.RuntimeDir, 0o750)
	if err := (&config.Device{DeviceID: "d-1", HeartbeatIntervalSeconds: 5}).Save(p.DeviceFile(), config.Owner{}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p.DeviceTokenFile(), []byte("dev_1"), 0o600)
	src := identity.NewSource(p)
	if err := src.Load(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })

	// The helper: docker.run blocks until the test ends.
	pulling := make(chan struct{}, 1)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: p.HelperSocket(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	rpc := &localrpc.Server{
		Authorize: func(localrpc.Peer, string) error { return nil },
		Log:       agent.NewLogger(io.Discard, nil),
		Handlers: map[string]localrpc.Handler{
			"docker.run": {Timeout: time.Hour, Run: func(ctx context.Context, _ localrpc.Peer, _ json.RawMessage) (any, error) {
				select {
				case pulling <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}},
		},
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = rpc.Serve(ctx, l) }()

	client, err := api.New(api.Options{BaseURL: cp.URL, Version: "1.2.3", HTTPClient: cp.Client()})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := state.NewStore(p.StateDir)
	outbox, _ := state.NewOutbox(filepath.Join(p.StateDir, "outbox"), 0)
	d := agent.Deps{
		Version: "1.2.3", Paths: p, API: client, Identity: src, State: st, Outbox: outbox,
		Signals: agent.NewSignals(), Health: agent.NewHealth(), Helper: helper.NewClient(p.HelperSocket()),
		Log: agent.NewLogger(io.Discard, nil),
		Host: &platform.Host{
			Root:     t.TempDir(),
			Hostname: func() (string, error) { return "edge", nil },
			Uname:    func() (string, string) { return "6.1", "aarch64" },
			LookPath: func(string) (string, error) { return "", errors.New("no") },
			Run:      func(context.Context, string, ...string) bool { return false },
			IPv4:     func(string) []net.IP { return nil },
			Statfs:   func(string) (uint64, uint64, uint64, bool) { return 0, 0, 0, false },
		},
	}
	dep := &deploy.Module{Tools: func(context.Context) platform.Tools { return platform.Tools{Docker: true} }}
	for _, m := range []agent.Module{dep, &heartbeat.Module{}} {
		wg.Add(1)
		go func(m agent.Module) {
			defer wg.Done()
			if err := m.Run(ctx, d); err != nil {
				t.Errorf("%s: %v", m.Name(), err)
			}
		}(m)
	}

	select {
	case <-pulling:
	case <-time.After(10 * time.Second):
		t.Fatal("deploy never asked the helper for docker.run")
	}
	// Two more full heartbeats (not deploy's progress-only ones) arrive while
	// the pull hangs, at the server's interval.
	full := func() []fakecp.Call {
		var out []fakecp.Call
		for _, c := range cp.Calls("POST", "/api/v1/agent/heartbeat") {
			if c.Body["capabilities"] != nil {
				out = append(out, c)
			}
		}
		return out
	}
	before := len(full())
	deadline := time.Now().Add(14 * time.Second)
	for len(full()) < before+2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	calls := full()
	if len(calls) < before+2 {
		t.Fatalf("%d full heartbeats while the pull hangs, want 2", len(calls)-before)
	}
	for i := 1; i < len(calls); i++ {
		if gap := calls[i].At.Sub(calls[i-1].At); gap > 6500*time.Millisecond {
			t.Errorf("heartbeat %d came %s after the previous one (interval 5 s)", i, gap)
		}
	}
}
