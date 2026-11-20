package helper

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"meteorcloud/meteorcli/internal/localrpc"
)

// dockerHost is a fake host for the docker and compose operations.
func dockerHost(t *testing.T, f *fakeHost) (Host, string) {
	t.Helper()
	dir := t.TempDir()
	h := f.host(filepath.Join(dir, "units"))
	h.ArtifactsDir = filepath.Join(dir, "artifacts")
	h.TempDir = t.TempDir()
	if err := os.MkdirAll(h.ArtifactsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	h.RunStdin = func(ctx context.Context, r io.Reader, name string, args ...string) ([]byte, error) {
		data, _ := io.ReadAll(r)
		return h.Run(ctx, name, append(args, "stdin="+string(data))...)
	}
	return h, h.ArtifactsDir
}

func badRequest(err error) bool { return localrpc.CodeOf(err) == localrpc.CodeBadRequest }

func TestDockerLoad(t *testing.T) {
	f := &fakeHost{output: "Loaded image: demo/app:1.0\n"}
	h, artifacts := dockerHost(t, f)
	if err := os.WriteFile(filepath.Join(artifacts, "a1"), []byte("tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := call(t, h, "docker.load", DockerLoadRequest{Artifact: "a1"})
	if err != nil || string(out) != `{"image":"demo/app:1.0"}` {
		t.Fatalf("load: %s %v", out, err)
	}
	if got := f.calls[0]; !slices.Equal(got, []string{"docker", "load", "stdin=tar"}) {
		t.Fatalf("calls %v", got)
	}
	// A link to a file only root may read is refused.
	if err := os.Symlink("/etc/hostname", filepath.Join(artifacts, "link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link", "../x", "-rf", "missing"} {
		if _, err := call(t, h, "docker.load", DockerLoadRequest{Artifact: name}); !badRequest(err) {
			t.Errorf("artifact %q: %v", name, err)
		}
	}
	f.output = "nothing useful"
	if _, err := call(t, h, "docker.load", DockerLoadRequest{Artifact: "a1"}); err == nil {
		t.Error("load without an image name accepted")
	}
}

func TestDockerRun(t *testing.T) {
	f := &fakeHost{}
	h, _ := dockerHost(t, f)
	var envFile string
	run := h.Run
	h.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if i := slices.Index(args, "--env-file"); i >= 0 {
			data, _ := os.ReadFile(args[i+1])
			envFile = string(data)
		}
		return run(ctx, name, args...)
	}
	req := DockerRunRequest{
		Name: "demo-app", Image: "nginx:1.27", Ports: []string{"8080:80", "127.0.0.1:53:53/udp"},
		Env: map[string]string{"TOKEN": "s3cret"}, Restart: "unless-stopped", Command: []string{"-g", "daemon off;"},
	}
	if _, err := call(t, h, "docker.run", req); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls[0], []string{"docker", "rm", "-f", "--", "demo-app"}) {
		t.Fatalf("first call %v", f.calls[0])
	}
	runArgs := strings.Join(f.calls[1], " ")
	if strings.Contains(runArgs, "s3cret") {
		t.Fatalf("secret on the command line: %s", runArgs)
	}
	want := "docker run -d --name demo-app --restart unless-stopped -p 8080:80 -p 127.0.0.1:53:53/udp --env-file "
	if !strings.HasPrefix(runArgs, want) || !strings.HasSuffix(runArgs, "-- nginx:1.27 -g daemon off;") {
		t.Fatalf("run args %s", runArgs)
	}
	if envFile != "TOKEN=s3cret\n" {
		t.Fatalf("env file %q", envFile)
	}
	if left, _ := os.ReadDir(h.TempDir); len(left) != 0 {
		t.Fatalf("env file left behind: %v", left)
	}

	bads := []func(r *DockerRunRequest){
		func(r *DockerRunRequest) { r.Name = "-x" },
		func(r *DockerRunRequest) { r.Name = "UPPER" },
		func(r *DockerRunRequest) { r.Image = "-v /:/host" },
		func(r *DockerRunRequest) { r.Ports = []string{"--privileged"} },
		func(r *DockerRunRequest) { r.Env = map[string]string{"A B": "x"} },
		func(r *DockerRunRequest) { r.Env = map[string]string{"A": "two\nlines"} },
		func(r *DockerRunRequest) { r.Restart = "sometimes" },
		func(r *DockerRunRequest) { r.Command = []string{"a\x00b"} },
	}
	for i, mutate := range bads {
		r := req
		mutate(&r)
		if _, err := call(t, h, "docker.run", r); !badRequest(err) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// Unknown fields (a volume) are refused by the root process.
	raw := json.RawMessage(`{"name":"a","image":"b","volumes":["/:/host"]}`)
	if _, err := Ops(h)["docker.run"].Run(context.Background(), localrpc.Peer{}, raw); !badRequest(err) {
		t.Errorf("volumes accepted: %v", err)
	}
}

func TestDockerInspectAndControl(t *testing.T) {
	f := &fakeHost{output: "true|running|0|starting\n"}
	h, _ := dockerHost(t, f)
	out, err := call(t, h, "docker.inspect", DockerNameRequest{Name: "web"})
	if err != nil || string(out) != `{"missing":false,"running":true,"status":"running","exit_code":0,"health":"starting"}` {
		t.Fatalf("inspect: %s %v", out, err)
	}
	f.fail = "inspect"
	out, _ = call(t, h, "docker.inspect", DockerNameRequest{Name: "web"})
	if !strings.Contains(string(out), `"missing":true`) {
		t.Fatalf("missing container: %s", out)
	}
	f.fail = ""
	for _, action := range []string{"restart", "remove"} {
		if _, err := call(t, h, "docker.control", DockerNameRequest{Name: "web", Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call(t, h, "docker.control", DockerNameRequest{Name: "web", Action: "exec"}); !badRequest(err) {
		t.Fatalf("exec: %v", err)
	}
	if got := parseInspect("false|exited|137|"); got.Running || got.ExitCode != 137 || got.Status != "exited" {
		t.Fatalf("parseInspect %+v", got)
	}
}

func TestCompose(t *testing.T) {
	f := &fakeHost{}
	h, artifacts := dockerHost(t, f)
	dir := filepath.Join(artifacts, ComposeDirName, "shop")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"compose.yaml", ComposeEnvFile} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call(t, h, "compose.up", ComposeUpRequest{Project: "shop", File: "compose.yaml", EnvFile: true, ForceRecreate: true}); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "compose", "-p", "shop", "-f", filepath.Join(dir, "compose.yaml"),
		"--env-file", filepath.Join(dir, ComposeEnvFile), "up", "-d", "--remove-orphans", "--force-recreate"}
	if !slices.Equal(f.calls[0], want) {
		t.Fatalf("up %v", f.calls[0])
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(dir, "docker-compose.yml")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []ComposeUpRequest{
		{Project: "shop", File: "../../x.yaml"},
		{Project: "shop", File: "docker-compose.yml"},
		{Project: "nope", File: "compose.yaml"},
		{Project: "-p", File: "compose.yaml"},
	} {
		if _, err := call(t, h, "compose.up", r); !badRequest(err) {
			t.Errorf("%+v: %v", r, err)
		}
	}

	f.output = `{"Service":"web","Name":"shop-web-1","State":"running","ExitCode":0,"Health":"healthy"}` + "\n" +
		`{"Service":"init","Name":"shop-init-1","State":"exited","ExitCode":0,"Health":""}` + "\n"
	out, err := call(t, h, "compose.ps", ComposeProjectRequest{Project: "shop"})
	if err != nil || !strings.Contains(string(out), `"Service":"init"`) {
		t.Fatalf("ps: %s %v", out, err)
	}
	if got := parsePS(`[{"Service":"a","State":"running"}]`); len(got) != 1 || got[0].Service != "a" {
		t.Fatalf("array form %+v", got)
	}
	if got := parsePS("garbage"); len(got) != 0 {
		t.Fatalf("garbage %+v", got)
	}
	for _, action := range []string{"restart", "down"} {
		if _, err := call(t, h, "compose.control", ComposeProjectRequest{Project: "shop", Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call(t, h, "compose.control", ComposeProjectRequest{Project: "shop", Action: "rm"}); !badRequest(err) {
		t.Fatal(err)
	}
}

func TestSystemdControl(t *testing.T) {
	f := &fakeHost{}
	h, _ := dockerHost(t, f)
	out, err := call(t, h, "systemd.control", SystemdControlRequest{Unit: "demo.service", Action: "is-active"})
	if err != nil || string(out) != `{"active":true}` {
		t.Fatalf("is-active: %s %v", out, err)
	}
	f.fail = "is-active"
	out, _ = call(t, h, "systemd.control", SystemdControlRequest{Unit: "demo.service", Action: "is-active"})
	if string(out) != `{"active":false}` {
		t.Fatalf("inactive: %s", out)
	}
	f.fail = ""
	if err := os.MkdirAll(h.UnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(h.UnitDir, "demo.service")
	if err := os.WriteFile(unit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"start", "stop", "restart", "remove"} {
		if _, err := call(t, h, "systemd.control", SystemdControlRequest{Unit: "demo.service", Action: action}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatalf("unit file not removed: %v", err)
	}
	for _, r := range []SystemdControlRequest{
		{Unit: "meteorcli.service", Action: "stop"},
		{Unit: "demo.service", Action: "mask"},
		{Unit: "-x.service", Action: "stop"},
		{Unit: "demo.timer", Action: "stop"},
	} {
		if _, err := call(t, h, "systemd.control", r); !badRequest(err) {
			t.Errorf("%+v: %v", r, err)
		}
	}
}

func TestAuditNeverLogsSecrets(t *testing.T) {
	raw, _ := json.Marshal(DockerRunRequest{Name: "a", Image: "b", Env: map[string]string{"K": "s3cret"}, Command: []string{"--token=s3cret"}})
	logged, _ := json.Marshal(auditDocker(raw))
	if strings.Contains(string(logged), "s3cret") {
		t.Fatalf("audit leaks: %s", logged)
	}
}
