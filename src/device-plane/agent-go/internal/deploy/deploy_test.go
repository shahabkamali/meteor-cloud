package deploy

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"meteorcloud/meteorcli/internal/agent"
	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/config"
	"meteorcloud/meteorcli/internal/deploy/runtime"
	"meteorcloud/meteorcli/internal/deploy/runtime/compose"
	"meteorcloud/meteorcli/internal/deploy/runtime/docker"
	"meteorcloud/meteorcli/internal/deploy/runtime/systemd"
	"meteorcloud/meteorcli/internal/fakecp"
	"meteorcloud/meteorcli/internal/identity"
	"meteorcloud/meteorcli/internal/platform"
	"meteorcloud/meteorcli/internal/signing"
	"meteorcloud/meteorcli/internal/state"
)

const (
	softwareRoute = "/api/v1/agent/software"
	keysRoute     = "/api/v1/agent/signing-keys"
	beatRoute     = "/api/v1/agent/heartbeat"
	deviceID      = "d-1"
	token         = "dev_1"
)

// helperCall is one recorded helper request.
type helperCall struct {
	op     string
	params map[string]any
}

// fakeHelper plays the root helper: it records calls and answers from answer.
type fakeHelper struct {
	mu     sync.Mutex
	calls  []helperCall
	answer func(op string, params map[string]any) (any, error)
}

func (f *fakeHelper) Call(ctx context.Context, op string, params, out any) error {
	raw, _ := json.Marshal(params)
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	f.mu.Lock()
	f.calls = append(f.calls, helperCall{op, p})
	answer := f.answer
	f.mu.Unlock()
	result, err := answer(op, p)
	if err != nil {
		return err
	}
	if out != nil && result != nil {
		data, _ := json.Marshal(result)
		return json.Unmarshal(data, out)
	}
	return nil
}

func (f *fakeHelper) ops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.op)
	}
	return out
}

func (f *fakeHelper) find(op string) []helperCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []helperCall
	for _, c := range f.calls {
		if c.op == op {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeHelper) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// dockerDevice answers docker operations like a device where everything works;
// running decides what docker.inspect says for a container's image.
type dockerDevice struct {
	mu         sync.Mutex
	containers map[string]string // name -> image
	unhealthy  map[string]bool   // image -> exits right away
}

func newDockerDevice() *dockerDevice {
	return &dockerDevice{containers: map[string]string{}, unhealthy: map[string]bool{}}
}

func (dd *dockerDevice) answer(op string, p map[string]any) (any, error) {
	dd.mu.Lock()
	defer dd.mu.Unlock()
	switch op {
	case "docker.load":
		return map[string]string{"image": "demo/app:1.0"}, nil
	case "docker.run":
		dd.containers[p["name"].(string)] = p["image"].(string)
		return map[string]bool{"started": true}, nil
	case "docker.inspect":
		image, ok := dd.containers[p["name"].(string)]
		if !ok {
			return map[string]any{"missing": true}, nil
		}
		if dd.unhealthy[image] {
			return map[string]any{"running": false, "status": "exited", "exit_code": 1}, nil
		}
		return map[string]any{"running": true, "status": "running"}, nil
	case "docker.control":
		delete(dd.containers, p["name"].(string))
		return nil, nil
	case "compose.up", "systemd.install_unit", "compose.control":
		return nil, nil
	case "compose.ps":
		return map[string]any{"services": []map[string]any{{"Service": "web", "State": "running"}}}, nil
	case "systemd.control":
		return map[string]bool{"active": true}, nil
	}
	return nil, errors.New("unexpected op " + op)
}

type fixture struct {
	t      *testing.T
	cp     *fakecp.Server
	d      agent.Deps
	helper *fakeHelper
	device *dockerDevice
	now    time.Time
	key    ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	cp := fakecp.New(t)
	p := config.DefaultPaths(t.TempDir())
	_ = os.MkdirAll(p.IdentityDir, 0o700)
	if err := (&config.Device{DeviceID: deviceID, HeartbeatIntervalSeconds: 60}).Save(p.DeviceFile(), config.Owner{}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p.DeviceTokenFile(), []byte(token), 0o600)
	src := identity.NewSource(p)
	if err := src.Load(); err != nil {
		t.Fatal(err)
	}
	client, err := api.New(api.Options{BaseURL: cp.URL, Version: "1.2.3", HTTPClient: cp.Client()})
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.NewStore(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := state.NewOutbox(filepath.Join(p.StateDir, "outbox"), 0)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, cp: cp, device: newDockerDevice(), now: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}
	f.helper = &fakeHelper{answer: f.device.answer}
	f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	f.d = agent.Deps{
		Version: "1.2.3", Paths: p, API: client, Identity: src, State: st, Outbox: outbox,
		Signals: agent.NewSignals(), Health: agent.NewHealth(), Log: agent.NewLogger(io.Discard, nil),
	}
	cp.On("POST", beatRoute, fakecp.OK(map[string]any{"device_id": deviceID, "heartbeat_interval_seconds": 60}))
	cp.On("GET", keysRoute, fakecp.OK([]map[string]any{{
		"key_id": "k1", "algorithm": "ed25519", "public_key": b64(f.key.Public().(ed25519.PublicKey)), "created_at": "2026-01-01T00:00:00Z",
	}}))
	return f
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// signed returns item signed for this device, the way the control plane does.
func (f *fixture) signed(item map[string]any) map[string]any {
	f.t.Helper()
	payload := map[string]any{"device_id": deviceID}
	for _, k := range []string{"workload_key", "kind", "release_id", "release_version", "artifact_id", "artifact_sha256", "revision", "spec"} {
		payload[k] = item[k]
	}
	raw, _ := json.Marshal(payload)
	c, err := signing.Canonical(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]any{"key_id": "k1", "signature": b64(ed25519.Sign(f.key, append([]byte("meteorcloud-desired-v1\n"), c...)))}
	for k, v := range item {
		out[k] = v
	}
	return out
}

func (f *fixture) kinds() map[string]Kind {
	return map[string]Kind{
		"systemd":        {Runtime: &systemd.Runtime{Helper: f.helper}, Available: func(platform.Tools) bool { return true }},
		"docker":         {Runtime: &docker.Runtime{Helper: f.helper}, Available: func(t platform.Tools) bool { return t.Docker }, Missing: "This device does not support Docker."},
		"docker_compose": {Runtime: &compose.Runtime{Helper: f.helper, ArtifactsDir: f.d.Paths.ArtifactsDir}, Available: func(platform.Tools) bool { return true }},
	}
}

// fakeWaiter runs the health gate on a fake clock.
func (f *fixture) waiter() *waiter {
	return &waiter{
		now:   func() time.Time { return f.now },
		sleep: func(_ context.Context, d time.Duration) bool { f.now = f.now.Add(d); return true },
		probe: func(context.Context, string) string { return "" },
	}
}

// cycle runs one reconcile pass with every tool installed.
func (f *fixture) cycle() error {
	c := &cycle{d: f.d, log: f.d.Log, kinds: f.kinds(), tools: platform.Tools{Docker: true}, waiter: f.waiter(),
		token: token, now: func() time.Time { return f.now }}
	return c.run(context.Background())
}

// desired scripts GET /software with the given items.
func (f *fixture) desired(items ...map[string]any) {
	f.cp.On("GET", softwareRoute, fakecp.OK(items))
}

// reports returns the software reports in the outbox, oldest first.
func (f *fixture) reports() []map[string]any {
	f.t.Helper()
	pending, err := f.d.Outbox.Pending(state.KindSoftwareReport)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []map[string]any
	for _, r := range pending {
		var m map[string]any
		_ = json.Unmarshal(r.Body, &m)
		out = append(out, m)
	}
	return out
}

func (f *fixture) last() map[string]any {
	f.t.Helper()
	r := f.reports()
	if len(r) == 0 {
		f.t.Fatal("no report")
	}
	return r[len(r)-1]
}

func (f *fixture) progress() []float64 {
	var out []float64
	for _, c := range f.cp.Calls("POST", beatRoute) {
		for _, r := range c.Body["software_report"].([]any) {
			out = append(out, r.(map[string]any)["progress_percent"].(float64))
		}
	}
	return out
}

func dockerItem(release, version string, revision int, spec map[string]any) map[string]any {
	if spec == nil {
		spec = map[string]any{"container_name": "demo-app", "image": "demo/app:" + version, "ports": []string{"8080:80"}}
	}
	return map[string]any{
		"workload_key": "demo-app", "kind": "docker", "release_id": release, "release_name": "demo",
		"release_version": version, "artifact_id": nil, "revision": revision, "artifact_sha256": nil, "spec": spec,
	}
}

func TestDockerTarballDeploy(t *testing.T) {
	f := newFixture(t)
	tarball := []byte("docker save tarball")
	artifactID := "0f7a6c1e-1111-4c39-9d1e-2b8f0c7a9e11"
	item := dockerItem("r1", "1.0.0", 1, map[string]any{"container_name": "demo-app", "env": map[string]string{"A": "b"}})
	item["artifact_id"], item["artifact_sha256"] = artifactID, digest(tarball)
	f.desired(f.signed(item))
	f.cp.On("GET", "/api/v1/agent/artifacts/"+artifactID+"/download", fakecp.Reply{
		Status: 200, Body: tarball, Header: map[string]string{api.ChecksumHeader: digest(tarball)},
	})

	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.helper.ops(), ","); got != "docker.load,docker.run,docker.inspect" {
		t.Fatalf("helper ops %s", got)
	}
	run := f.helper.find("docker.run")[0].params
	if run["image"] != "demo/app:1.0" || run["name"] != "demo-app" || run["restart"] != "unless-stopped" {
		t.Fatalf("run params %v", run)
	}
	if load := f.helper.find("docker.load")[0].params; load["artifact"] != artifactID {
		t.Fatalf("load params %v", load)
	}
	r := f.last()
	if r["sync_status"] != "in_sync" || r["health"] != "healthy" || r["installed_version"] != "1.0.0" || r["installed_release_id"] != "r1" {
		t.Fatalf("report %v", r)
	}
	if got := f.progress(); len(got) != 3 || got[0] != 0 || got[1] != 99 || got[2] != 100 {
		t.Fatalf("progress %v", got)
	}
	body, _ := os.ReadFile(filepath.Join(f.d.Paths.ArtifactsDir, artifactID))
	if !bytes.Equal(body, tarball) {
		t.Fatal("artifact not stored")
	}
	events, _ := f.d.Outbox.Pending(state.KindEvent)
	if len(events) != 1 || !strings.Contains(string(events[0].Body), `"type":"app.started"`) {
		t.Fatalf("events %v", events)
	}

	// Next cycle: applied, so only its health is checked; the artifact is not fetched again.
	f.helper.reset()
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.helper.ops(), ","); got != "docker.inspect" {
		t.Fatalf("second cycle ops %s", got)
	}
	if n := len(f.cp.Calls("GET", "/api/v1/agent/artifacts/"+artifactID+"/download")); n != 1 {
		t.Fatalf("downloads %d", n)
	}

	// The container was removed by hand: it is installed again from the cached artifact.
	f.device.containers = map[string]string{}
	f.helper.reset()
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.helper.ops(), ","); got != "docker.inspect,docker.load,docker.run,docker.inspect" {
		t.Fatalf("reinstall ops %s", got)
	}
	if n := len(f.cp.Calls("GET", "/api/v1/agent/artifacts/"+artifactID+"/download")); n != 1 {
		t.Fatalf("cached artifact downloaded again: %d", n)
	}
}

func TestBrokenReleaseRollsBack(t *testing.T) {
	f := newFixture(t)
	f.desired(f.signed(dockerItem("r1", "1.0.0", 1, nil)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if f.last()["sync_status"] != "in_sync" {
		t.Fatalf("v1 %v", f.last())
	}

	// v2 starts but exits right away; its health check fails and v1 comes back.
	f.device.unhealthy["demo/app:2.0.0"] = true
	spec := map[string]any{"container_name": "demo-app", "image": "demo/app:2.0.0", "health_check": map[string]any{"timeout_seconds": 20, "stable_seconds": 5}}
	v2 := f.signed(dockerItem("r2", "2.0.0", 2, spec))
	f.desired(v2)
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	r := f.last()
	if r["sync_status"] != "rolled_back" || r["installed_version"] != "1.0.0" || r["health"] != "healthy" {
		t.Fatalf("report %v", r)
	}
	if msg, _ := r["last_error"].(string); !strings.HasPrefix(msg, "Rolled back to 1.0.0: ") || !strings.Contains(msg, "is not running") {
		t.Fatalf("last_error %q", msg)
	}
	if f.device.containers["demo-app"] != "demo/app:1.0.0" {
		t.Fatalf("running %v", f.device.containers)
	}
	applied, err := loadApplied(f.d.State)
	if err != nil || applied["demo-app"].ReleaseID != "r1" || applied["demo-app"].RolledBackFrom == nil || applied["demo-app"].RolledBackFrom.ReleaseID != "r2" {
		t.Fatalf("applied %+v %v", applied["demo-app"], err)
	}

	// The same broken release is not tried again.
	f.helper.reset()
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.helper.ops(), ","); got != "docker.inspect" {
		t.Fatalf("retried a rolled-back release: %s", got)
	}
	if f.last()["sync_status"] != "rolled_back" {
		t.Fatalf("report %v", f.last())
	}

	// A new release (v3) is applied and clears the rollback mark.
	f.desired(f.signed(dockerItem("r3", "3.0.0", 3, nil)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	applied, _ = loadApplied(f.d.State)
	if f.last()["sync_status"] != "in_sync" || applied["demo-app"].RolledBackFrom != nil || applied["demo-app"].Revision != 3 {
		t.Fatalf("v3 %v %+v", f.last(), applied["demo-app"])
	}
}

func TestRollbackAlsoFails(t *testing.T) {
	f := newFixture(t)
	f.desired(f.signed(dockerItem("r1", "1.0.0", 1, nil)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	f.device.unhealthy["demo/app:1.0.0"] = true
	f.device.unhealthy["demo/app:2.0.0"] = true
	spec := map[string]any{"container_name": "demo-app", "image": "demo/app:2.0.0", "health_check": map[string]any{}}
	f.desired(f.signed(dockerItem("r2", "2.0.0", 2, spec)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	r := f.last()
	if msg, _ := r["last_error"].(string); r["sync_status"] != "failed" || !strings.Contains(msg, "rolling back to 1.0.0 also failed") {
		t.Fatalf("report %v", r)
	}
}

func TestNoRollbackWhenDisabledOrFirstRelease(t *testing.T) {
	f := newFixture(t)
	f.device.unhealthy["demo/app:1.0.0"] = true
	f.desired(f.signed(dockerItem("r1", "1.0.0", 1, map[string]any{"container_name": "demo-app", "image": "demo/app:1.0.0", "health_check": map[string]any{"rollback": true}})))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if r := f.last(); r["sync_status"] != "failed" {
		t.Fatalf("first release with nothing to roll back to: %v", r)
	}
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	unsigned := dockerItem("r1", "1.0.0", 1, nil)
	unsigned["workload_key"] = "unsigned"
	tampered := f.signed(dockerItem("r1", "1.0.0", 1, nil))
	tampered["workload_key"] = "tampered"
	unknown := f.signed(dockerItem("r1", "1.0.0", 1, nil))
	unknown["workload_key"], unknown["kind"] = "unknown", "podman"
	f.desired(unsigned, tampered, unknown, map[string]any{"kind": "docker"})
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range f.reports() {
		got[r["workload_key"].(string)] = r["last_error"].(string)
	}
	want := map[string]string{
		"unsigned": "Desired software is not signed; refusing to install it.",
		"tampered": "Desired software signature does not verify; refusing to install it.",
		"unknown":  "Unsupported release kind: 'podman'",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if len(got) != 3 || len(f.helper.ops()) != 0 {
		t.Fatalf("reports %v, helper %v", got, f.helper.ops())
	}
}

func TestStaleRevisionRefused(t *testing.T) {
	f := newFixture(t)
	f.desired(f.signed(dockerItem("r5", "5.0.0", 5, nil)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	f.desired(f.signed(dockerItem("r4", "4.0.0", 4, nil)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if msg := f.last()["last_error"]; msg != "Desired revision 4 is older than applied revision 5; refusing rollback." {
		t.Fatalf("got %v", msg)
	}
}

func TestChecksumMismatchAndMissingTool(t *testing.T) {
	f := newFixture(t)
	item := dockerItem("r1", "1.0.0", 1, map[string]any{"container_name": "demo-app"})
	item["artifact_id"], item["artifact_sha256"] = "a1", strings.Repeat("0", 64)
	f.desired(f.signed(item))
	f.cp.On("GET", "/api/v1/agent/artifacts/a1/download", fakecp.Reply{Status: 200, Body: []byte("other bytes")})
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if msg := f.last()["last_error"].(string); !strings.Contains(msg, "does not match the signed checksum") {
		t.Fatalf("got %q", msg)
	}
	if _, err := os.Stat(filepath.Join(f.d.Paths.ArtifactsDir, "a1")); !os.IsNotExist(err) {
		t.Fatal("refused artifact kept")
	}

	c := &cycle{d: f.d, log: f.d.Log, kinds: f.kinds(), tools: platform.Tools{}, waiter: f.waiter(), token: token, now: time.Now}
	f.desired(f.signed(dockerItem("r1", "1.0.0", 1, nil)))
	if err := c.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if msg := f.last()["last_error"]; msg != "This device does not support Docker." {
		t.Fatalf("got %v", msg)
	}
}

func zipBundle(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestComposeDeploy(t *testing.T) {
	f := newFixture(t)
	bundle := zipBundle(t, map[string]string{"docker-compose.yml": "services: {web: {image: nginx}}\n", "conf/site.conf": "x"})
	item := map[string]any{
		"workload_key": "shop", "kind": "docker_compose", "release_id": "r1", "release_name": "shop", "release_version": "1.0",
		"artifact_id": "c1", "revision": 1, "artifact_sha256": digest(bundle),
		"spec": map[string]any{"project_name": "shop", "env": map[string]string{"TAG": "1.0"}},
	}
	f.desired(f.signed(item))
	f.cp.On("GET", "/api/v1/agent/artifacts/c1/download", fakecp.Reply{Status: 200, Body: bundle})
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if r := f.last(); r["sync_status"] != "in_sync" || r["health"] != "healthy" {
		t.Fatalf("report %v", r)
	}
	up := f.helper.find("compose.up")[0].params
	if up["project"] != "shop" || up["file"] != "docker-compose.yml" || up["env_file"] != true {
		t.Fatalf("up %v", up)
	}
	dir := filepath.Join(f.d.Paths.ArtifactsDir, "compose", "shop")
	env, _ := os.ReadFile(filepath.Join(dir, ".env.meteorcloud"))
	site, _ := os.ReadFile(filepath.Join(dir, "conf", "site.conf"))
	if string(env) != "TAG=1.0\n" || string(site) != "x" {
		t.Fatalf("project files env=%q site=%q", env, site)
	}
}

func TestComposeZipSlipRefused(t *testing.T) {
	f := newFixture(t)
	bundle := zipBundle(t, map[string]string{"../../evil.yml": "x"})
	item := map[string]any{
		"workload_key": "shop", "kind": "docker_compose", "release_id": "r1", "release_version": "1.0",
		"artifact_id": "c1", "revision": 1, "artifact_sha256": digest(bundle), "spec": map[string]any{"project_name": "shop"},
	}
	f.desired(f.signed(item))
	f.cp.On("GET", "/api/v1/agent/artifacts/c1/download", fakecp.Reply{Status: 200, Body: bundle})
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if msg := f.last()["last_error"].(string); !strings.Contains(msg, "leaves the project directory") {
		t.Fatalf("got %q", msg)
	}
}

func TestSystemdDeploy(t *testing.T) {
	f := newFixture(t)
	unit := []byte("[Unit]\nDescription=demo\n[Service]\nExecStart=/bin/true\n")
	item := map[string]any{
		"workload_key": "demo", "kind": "systemd", "release_id": "r1", "release_version": "1",
		"artifact_id": "u1", "revision": 1, "artifact_sha256": digest(unit), "spec": map[string]any{"unit_name": "demo"},
	}
	f.desired(f.signed(item))
	f.cp.On("GET", "/api/v1/agent/artifacts/u1/download", fakecp.Reply{Status: 200, Body: unit})
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	install := f.helper.find("systemd.install_unit")[0].params
	if install["name"] != "demo.service" || install["content"] != string(unit) || install["no_start"] != false {
		t.Fatalf("install %v", install)
	}
	if r := f.last(); r["sync_status"] != "in_sync" {
		t.Fatalf("report %v", r)
	}
}

func TestBindingNotSupported(t *testing.T) {
	f := newFixture(t)
	spec := map[string]any{"container_name": "demo-app", "image": "x", "meteorcloud": map[string]any{"application": "cam"}}
	f.desired(f.signed(dockerItem("r1", "1", 1, spec)))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if msg := f.last()["last_error"].(string); !strings.Contains(msg, "bindings") || len(f.helper.ops()) != 0 {
		t.Fatalf("got %q %v", msg, f.helper.ops())
	}
}

func TestAuthFailureGoesToIdentity(t *testing.T) {
	f := newFixture(t)
	f.cp.On("GET", softwareRoute, fakecp.Fail(401, "invalid_token"))
	if err := f.cycle(); !errors.Is(err, errAuth) {
		t.Fatalf("got %v", err)
	}
	if _, err := f.d.Identity.Token(); err == nil {
		t.Fatal("identity still hands out the refused token")
	}
}

func TestServerWithoutSigning(t *testing.T) {
	f := newFixture(t)
	f.cp.On("GET", keysRoute, fakecp.Fail(404, "not_found"))
	f.desired(dockerItem("r1", "1.0.0", 1, nil))
	if err := f.cycle(); err != nil {
		t.Fatal(err)
	}
	if r := f.last(); r["sync_status"] != "in_sync" {
		t.Fatalf("unsigned item on an older server: %v", r)
	}
}

func TestModuleRunsOnWorkWaiting(t *testing.T) {
	f := newFixture(t)
	f.desired(f.signed(dockerItem("r1", "1.0.0", 1, nil)))
	m := &Module{Kinds: f.kinds(), Tools: func(context.Context) platform.Tools { return platform.Tools{Docker: true} }, waiter: f.waiter()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, f.d) }()
	// Run subscribes in its own goroutine: publish until the work is picked up.
	deadline := time.Now().Add(5 * time.Second)
	for len(f.reports()) == 0 && time.Now().Before(deadline) {
		f.d.Signals.Publish(agent.WorkWaiting{Kind: "software"})
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h, _ := f.d.Health.Get(name); h.State != string(agent.StateRunning) {
		t.Fatalf("health %+v", h)
	}
	if r := f.last(); r["sync_status"] != "in_sync" {
		t.Fatalf("report %v", r)
	}
	if m.Name() != "deploy" || m.Critical() {
		t.Fatal("deploy must be an optional module named deploy")
	}
}

func TestAppliedStateKeepsUnknownAndReadsPython(t *testing.T) {
	st, _ := state.NewStore(t.TempDir())
	python := `{"demo": {"release_id": "r1", "revision": 2, "item": {"workload_key": "demo"}, "note": "keep"}}`
	if err := os.WriteFile(filepath.Join(st.Dir(), AppliedFile), []byte(python), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadApplied(st)
	if err != nil || s["demo"].Revision != 2 || s["demo"].ReleaseID != "r1" {
		t.Fatalf("%+v %v", s["demo"], err)
	}
	s.record("demo", "r0", 1, nil, nil, false) // lower revision: the high-water mark stays
	if err := s.save(st); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(st.Dir(), AppliedFile))
	for _, want := range []string{`"note": "keep"`, `"version": 1`, `"revision": 2`, `"workload_key": "demo"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("%s missing in %s", want, data)
		}
	}
}

func TestGateSettingsAndWait(t *testing.T) {
	if gateOf(json.RawMessage(`{}`)) != nil {
		t.Fatal("no health_check means no gate")
	}
	g := gateOf(json.RawMessage(`{"health_check":{"timeout_seconds":0,"stable_seconds":0,"http_url":"http://x","rollback":false}}`))
	if g.timeout != 60*time.Second || g.stable != 0 || g.url != "http://x" || g.rollback {
		t.Fatalf("gate %+v", g)
	}
	now := time.Unix(0, 0)
	w := &waiter{
		now:   func() time.Time { return now },
		sleep: func(_ context.Context, d time.Duration) bool { now = now.Add(d); return true },
	}
	// Healthy for the runtime, but the URL fails: the probe's problem is reported.
	w.probe = func(context.Context, string) string { return "http://x answered HTTP 502" }
	healthy := func(context.Context) runtime.Health { return runtime.Health{State: runtime.Healthy} }
	if got := w.wait(context.Background(), healthy, gate{timeout: 10 * time.Second, stable: 4 * time.Second, url: "http://x"}); got != "http://x answered HTTP 502" {
		t.Fatalf("got %q", got)
	}
	// Starting forever: the default message.
	starting := func(context.Context) runtime.Health { return runtime.Health{State: runtime.Starting} }
	if got := w.wait(context.Background(), starting, gate{timeout: 6 * time.Second}); got != "not healthy within 6s" {
		t.Fatalf("got %q", got)
	}
	// Flapping restarts the stable window; healthy long enough passes.
	n := 0
	flaps := func(context.Context) runtime.Health {
		n++
		if n == 2 {
			return runtime.Health{State: runtime.Unhealthy, Problem: "blip"}
		}
		return runtime.Health{State: runtime.Healthy}
	}
	if got := w.wait(context.Background(), flaps, gate{timeout: 30 * time.Second, stable: 4 * time.Second}); got != "" {
		t.Fatalf("got %q", got)
	}
}
