// Package compose runs a docker_compose release: it prepares the project
// directory (<artifacts>/compose/<project>/) from the artifact, a compose file
// or a zip bundle, and asks the helper to bring it up (compose.up) and to list
// its containers (compose.ps).
package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"meteorcloud/meteorcli/internal/config"
	"meteorcloud/meteorcli/internal/deploy/runtime"
)

// Names shared with the helper (internal/helper/compose.go).
const (
	dirName = "compose"
	envFile = ".env.meteorcloud"
)

// candidates are the compose file names looked for in a zip bundle, in order.
var candidates = []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

// Runtime is the docker_compose runtime.
type Runtime struct {
	Helper runtime.Helper
	// ArtifactsDir holds the compose project directories.
	ArtifactsDir string
}

// spec is the compose release spec (app/releases/kinds.py DockerComposeSpec).
type spec struct {
	Env map[string]string `json:"env"`
}

func project(w runtime.Workload) string { return runtime.Name(w.Spec, "project_name", w.Key) }

// Kind implements runtime.Runtime.
func (r *Runtime) Kind() string { return "docker_compose" }

// Apply writes the project files and brings the project up.
func (r *Runtime) Apply(ctx context.Context, w runtime.Workload) (runtime.Result, error) {
	name := project(w)
	if w.Artifact == "" {
		return runtime.Result{}, runtime.Fail("docker_compose release is missing an artifact_id.")
	}
	if strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return runtime.Result{}, runtime.Fail("Invalid project_name: %s", name)
	}
	var s spec
	_ = json.Unmarshal(w.Spec, &s)

	dir := filepath.Join(r.ArtifactsDir, dirName, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return runtime.Result{}, fmt.Errorf("compose project %s: %w", name, err)
	}
	file, err := materialize(w.Artifact, dir)
	if err != nil {
		return runtime.Result{}, err
	}
	envPath := filepath.Join(dir, envFile)
	if len(s.Env) > 0 {
		if err := writeEnv(envPath, s.Env); err != nil {
			return runtime.Result{}, err
		}
	} else if err := os.Remove(envPath); err != nil && !os.IsNotExist(err) {
		return runtime.Result{}, fmt.Errorf("compose env file: %w", err)
	}

	upCtx, cancel := context.WithTimeout(ctx, runtime.Slow)
	err = r.Helper.Call(upCtx, "compose.up", map[string]any{"project": name, "file": file, "env_file": len(s.Env) > 0}, nil)
	cancel()
	if err != nil {
		return runtime.Result{}, err
	}
	h := r.Check(ctx, w)
	if h.State == runtime.Unhealthy || h.State == runtime.Missing {
		return runtime.Result{Health: h}, runtime.Fail("%s after apply.", h.Problem)
	}
	return runtime.Result{Health: h}, nil
}

// writeEnv writes the substitution variables (KEY=value lines). Values can be
// secrets: the file is 0640 (the root helper reads it).
func writeEnv(path string, env map[string]string) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if strings.ContainsAny(k+env[k], "\n\r\x00") || strings.Contains(k, "=") {
			return fmt.Errorf("compose env %q must be one line", k)
		}
		b.WriteString(k + "=" + env[k] + "\n")
	}
	if err := config.WriteFileAtomic(path, []byte(b.String()), 0o640); err != nil {
		return fmt.Errorf("compose env file: %w", err)
	}
	return nil
}

// Check is healthy when every service container runs (and passes its
// HEALTHCHECK, if any); one-shot jobs that exited 0 are fine.
func (r *Runtime) Check(ctx context.Context, w runtime.Workload) runtime.Health {
	name := project(w)
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	var ps struct {
		Services []struct {
			Service, Name, State, Health string
			ExitCode                     int
		} `json:"services"`
	}
	if err := r.Helper.Call(ctx, "compose.ps", map[string]string{"project": name}, &ps); err != nil {
		return runtime.Health{State: runtime.Unhealthy, Problem: fmt.Sprintf("compose project %s could not be listed", name)}
	}
	if len(ps.Services) == 0 {
		return runtime.Health{State: runtime.Missing, Problem: fmt.Sprintf("compose project %s has no services", name)}
	}
	var starting *runtime.Health
	running := 0
	for _, s := range ps.Services {
		label := s.Service
		if label == "" {
			label = s.Name
		}
		subject := "compose service " + label
		if s.State == "exited" && s.ExitCode == 0 {
			continue // a one-shot job (migration, init) that finished
		}
		if s.State != "running" {
			return runtime.Health{State: runtime.Unhealthy, Problem: fmt.Sprintf("%s is not running (%s, exit %d)", subject, s.State, s.ExitCode)}
		}
		running++
		if s.Health == "unhealthy" {
			return runtime.Health{State: runtime.Unhealthy, Problem: subject + " HEALTHCHECK failed"}
		}
		if s.Health == "starting" && starting == nil {
			starting = &runtime.Health{State: runtime.Starting, Problem: subject + " HEALTHCHECK starting"}
		}
	}
	if running == 0 {
		return runtime.Health{State: runtime.Unhealthy, Problem: fmt.Sprintf("compose project %s has no running services", name)}
	}
	if starting != nil {
		return *starting
	}
	return runtime.Health{State: runtime.Healthy}
}

// Remove stops the project and removes its containers.
func (r *Runtime) Remove(ctx context.Context, w runtime.Workload) error {
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	return r.Helper.Call(ctx, "compose.control", map[string]string{"project": project(w), "action": "down"}, nil)
}
