package compose

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"meteorcloud/meteorcli/internal/deploy/runtime"
	"meteorcloud/meteorcli/internal/deploy/runtime/runtimetest"
)

func TestCheckStates(t *testing.T) {
	type svc = map[string]any
	cases := []struct {
		services []svc
		state    runtime.State
		problem  string
	}{
		{[]svc{{"Service": "web", "State": "running"}, {"Service": "init", "State": "exited", "ExitCode": 0}}, runtime.Healthy, ""},
		{nil, runtime.Missing, "compose project shop has no services"},
		{[]svc{{"Service": "web", "State": "exited", "ExitCode": 3}}, runtime.Unhealthy, "compose service web is not running (exited, exit 3)"},
		{[]svc{{"Name": "shop-web-1", "State": "running", "Health": "unhealthy"}}, runtime.Unhealthy, "compose service shop-web-1 HEALTHCHECK failed"},
		{[]svc{{"Service": "web", "State": "running", "Health": "starting"}}, runtime.Starting, "compose service web HEALTHCHECK starting"},
		{[]svc{{"Service": "init", "State": "exited", "ExitCode": 0}}, runtime.Unhealthy, "compose project shop has no running services"},
	}
	for _, c := range cases {
		h := &runtimetest.FakeHelper{Answer: func(string, map[string]any) (any, error) {
			return map[string]any{"services": c.services}, nil
		}}
		got := (&Runtime{Helper: h}).Check(context.Background(), runtime.Workload{Key: "shop"})
		if got.State != c.state || got.Problem != c.problem {
			t.Errorf("%v: got %+v", c.services, got)
		}
	}
}

func TestApplyPlainComposeFile(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "a1")
	if err := os.WriteFile(artifact, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &runtimetest.FakeHelper{Answer: func(op string, p map[string]any) (any, error) {
		if op == "compose.ps" {
			return map[string]any{"services": []map[string]any{{"Service": "web", "State": "running"}}}, nil
		}
		return nil, nil
	}}
	r := &Runtime{Helper: h, ArtifactsDir: dir}
	project := filepath.Join(dir, "compose", "web")
	// A stale env file from an earlier release goes when the release has no env.
	_ = os.MkdirAll(project, 0o750)
	_ = os.WriteFile(filepath.Join(project, envFile), []byte("OLD=1\n"), 0o600)
	if _, err := r.Apply(context.Background(), runtime.Workload{Key: "web", Spec: json.RawMessage(`{}`), Artifact: artifact}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(project, "compose.yaml")); string(got) != "services: {}\n" {
		t.Fatalf("compose file %q", got)
	}
	if _, err := os.Stat(filepath.Join(project, envFile)); !os.IsNotExist(err) {
		t.Fatal("stale env file kept")
	}
	if p := h.Calls()[0].Params; p["file"] != "compose.yaml" || p["env_file"] != false {
		t.Fatalf("up %v", p)
	}
	for _, spec := range []string{`{"project_name":"../x"}`, `{"env":{"A":"two\nlines"}}`} {
		if _, err := r.Apply(context.Background(), runtime.Workload{Key: "web", Spec: json.RawMessage(spec), Artifact: artifact}); err == nil {
			t.Errorf("%s accepted", spec)
		}
	}
	if _, err := r.Apply(context.Background(), runtime.Workload{Key: "web"}); err == nil {
		t.Error("missing artifact accepted")
	}
	if err := r.Remove(context.Background(), runtime.Workload{Key: "web"}); err != nil || r.Kind() != "docker_compose" {
		t.Fatal(err)
	}
}
