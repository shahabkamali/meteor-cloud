package systemd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meteorcloud/meteorcli/internal/deploy/runtime"
	"meteorcloud/meteorcli/internal/deploy/runtime/runtimetest"
)

func TestApplyAndCheck(t *testing.T) {
	unit := filepath.Join(t.TempDir(), "u1")
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	active := false
	h := &runtimetest.FakeHelper{Answer: func(op string, p map[string]any) (any, error) {
		if op == "systemd.control" {
			return map[string]bool{"active": active}, nil
		}
		return nil, nil
	}}
	r := &Runtime{Helper: h}
	w := runtime.Workload{Key: "demo", Spec: json.RawMessage(`{"unit_name":"demo.service"}`), Artifact: unit}
	if _, err := r.Apply(context.Background(), w); err == nil || !strings.Contains(err.Error(), "is not active after apply") {
		t.Fatalf("inactive unit: %v", err)
	}
	active = true
	if res, err := r.Apply(context.Background(), w); err != nil || res.Health.State != runtime.Healthy {
		t.Fatalf("apply: %+v %v", res, err)
	}
	// start: false installs without starting and counts as healthy.
	idle := runtime.Workload{Key: "demo", Spec: json.RawMessage(`{"start":false}`), Artifact: unit}
	active = false
	if _, err := r.Apply(context.Background(), idle); err != nil {
		t.Fatal(err)
	}
	if p := h.Calls()[len(h.Calls())-1].Params; p["name"] != "demo.service" || p["no_start"] != true {
		t.Fatalf("install %v", p)
	}
	if got := r.Check(context.Background(), w); got.State != runtime.Unhealthy || got.Problem != "systemd unit demo.service is not active" {
		t.Fatalf("check %+v", got)
	}
	if _, err := r.Apply(context.Background(), runtime.Workload{Key: "demo"}); err == nil {
		t.Fatal("missing artifact accepted")
	}
	big := filepath.Join(t.TempDir(), "big")
	_ = os.WriteFile(big, make([]byte, maxUnit+1), 0o600)
	if _, err := r.Apply(context.Background(), runtime.Workload{Key: "demo", Artifact: big}); err == nil {
		t.Fatal("oversized unit accepted")
	}
	if err := r.Remove(context.Background(), w); err != nil || r.Kind() != "systemd" {
		t.Fatal(err)
	}
}
