// Package systemd installs a release's unit file through the helper
// (systemd.install_unit) and watches it with systemd.control.
package systemd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"meteorcloud/meteorcli/internal/deploy/runtime"
)

// maxUnit matches the helper's limit.
const maxUnit = 256 << 10

// Runtime is the systemd runtime.
type Runtime struct {
	Helper runtime.Helper
}

// spec is the systemd release spec (app/releases/kinds.py SystemdSpec).
type spec struct {
	unit  string
	start bool
}

func parse(w runtime.Workload) spec {
	s := spec{unit: runtime.Name(w.Spec, "unit_name", w.Key), start: true}
	var fields struct {
		Start *bool `json:"start"`
	}
	if json.Unmarshal(w.Spec, &fields) == nil && fields.Start != nil {
		s.start = *fields.Start
	}
	// systemctl treats "demo" as "demo.service"; the file must have the suffix.
	if !strings.Contains(s.unit, ".") {
		s.unit += ".service"
	}
	return s
}

// Kind implements runtime.Runtime.
func (r *Runtime) Kind() string { return "systemd" }

// Apply installs the unit file, enables it and (unless start is false) restarts it.
func (r *Runtime) Apply(ctx context.Context, w runtime.Workload) (runtime.Result, error) {
	s := parse(w)
	if w.Artifact == "" {
		return runtime.Result{}, runtime.Fail("systemd release is missing an artifact_id.")
	}
	content, err := readUnit(w.Artifact)
	if err != nil {
		return runtime.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	params := map[string]any{"name": s.unit, "content": content, "no_start": !s.start}
	if err := r.Helper.Call(ctx, "systemd.install_unit", params, nil); err != nil {
		return runtime.Result{}, err
	}
	h := r.Check(ctx, w)
	if s.start && h.State != runtime.Healthy {
		return runtime.Result{Health: h}, runtime.Fail("Unit %s is not active after apply.", s.unit)
	}
	return runtime.Result{Health: runtime.Health{State: runtime.Healthy}}, nil
}

func readUnit(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("unit file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUnit+1))
	if err != nil {
		return "", fmt.Errorf("unit file: %w", err)
	}
	if len(data) > maxUnit {
		return "", fmt.Errorf("unit file is larger than %d bytes", maxUnit)
	}
	return string(data), nil
}

// Check reports the unit active (healthy) or not; a unit that is not meant to
// run (start: false) is healthy once installed.
func (r *Runtime) Check(ctx context.Context, w runtime.Workload) runtime.Health {
	s := parse(w)
	if !s.start {
		return runtime.Health{State: runtime.Healthy}
	}
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	var out struct {
		Active bool `json:"active"`
	}
	if err := r.Helper.Call(ctx, "systemd.control", map[string]string{"unit": s.unit, "action": "is-active"}, &out); err != nil {
		return runtime.Health{State: runtime.Unhealthy, Problem: fmt.Sprintf("systemd unit %s could not be checked: %v", s.unit, err)}
	}
	if !out.Active {
		return runtime.Health{State: runtime.Unhealthy, Problem: fmt.Sprintf("systemd unit %s is not active", s.unit)}
	}
	return runtime.Health{State: runtime.Healthy}
}

// Remove stops and disables the unit and deletes its file.
func (r *Runtime) Remove(ctx context.Context, w runtime.Workload) error {
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	return r.Helper.Call(ctx, "systemd.control", map[string]string{"unit": parse(w).unit, "action": "remove"}, nil)
}
