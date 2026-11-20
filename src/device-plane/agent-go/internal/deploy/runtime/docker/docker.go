// Package docker runs one container for a docker release through the helper:
// docker.load for a tarball artifact, docker.run, docker.inspect.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"meteorcloud/meteorcli/internal/deploy/runtime"
)

// Runtime is the docker runtime.
type Runtime struct {
	Helper runtime.Helper
}

// digestRe is a release's image_digest.
var digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// spec is the docker release spec (app/releases/kinds.py DockerSpec).
type spec struct {
	ContainerName string            `json:"container_name"`
	Image         string            `json:"image"`
	ImageDigest   string            `json:"image_digest"`
	Ports         []string          `json:"ports"`
	Env           map[string]string `json:"env"`
	Restart       json.RawMessage   `json:"restart"`
	Command       string            `json:"command"`
}

func parse(w runtime.Workload) (spec, string) {
	var s spec
	_ = json.Unmarshal(w.Spec, &s)
	return s, runtime.Name(w.Spec, "container_name", w.Key)
}

// restart is the --restart policy: unless-stopped when the spec has none, no
// flag when it is null or empty (as the Python agent did).
func (s spec) restart() string {
	if len(s.Restart) == 0 {
		return "unless-stopped"
	}
	var r string
	_ = json.Unmarshal(s.Restart, &r)
	return r
}

// Kind implements runtime.Runtime.
func (r *Runtime) Kind() string { return "docker" }

// Apply loads the tarball (when the release has one) or pulls the image, and
// replaces the container.
func (r *Runtime) Apply(ctx context.Context, w runtime.Workload) (runtime.Result, error) {
	s, name := parse(w)
	image := strings.TrimSpace(s.Image)
	if image != "" && w.Artifact == "" {
		pinned, err := pinnedImage(image, s.ImageDigest)
		if err != nil {
			return runtime.Result{}, err
		}
		image = pinned
	}
	if w.Artifact != "" {
		var loaded struct {
			Image string `json:"image"`
		}
		ctx, cancel := context.WithTimeout(ctx, runtime.Slow)
		err := r.Helper.Call(ctx, "docker.load", map[string]string{"artifact": filepath.Base(w.Artifact)}, &loaded)
		cancel()
		if err != nil {
			return runtime.Result{}, err
		}
		if image == "" {
			image = loaded.Image
		}
	}
	if image == "" {
		return runtime.Result{}, runtime.Fail("A docker release needs an image name or a loadable tarball.")
	}
	command, err := Split(s.Command)
	if err != nil {
		return runtime.Result{}, fmt.Errorf("command: %w", err)
	}
	params := map[string]any{
		"name": name, "image": image, "ports": nonNil(s.Ports), "env": s.Env,
		"restart": s.restart(), "command": nonNil(command),
	}
	runCtx, cancel := context.WithTimeout(ctx, runtime.Slow)
	err = r.Helper.Call(runCtx, "docker.run", params, nil)
	cancel()
	if err != nil {
		return runtime.Result{}, err
	}
	h := r.Check(ctx, w)
	// Not up after install: the install failed. A HEALTHCHECK still starting is fine.
	if h.State == runtime.Unhealthy || h.State == runtime.Missing {
		return runtime.Result{Health: h}, runtime.Fail("%s after apply.", h.Problem)
	}
	return runtime.Result{Health: h}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// pinnedImage turns repo:tag plus a release's image_digest into repo@sha256:…
// so Docker checks the content it pulls.
func pinnedImage(image, digest string) (string, error) {
	if digest == "" {
		return image, nil
	}
	if !digestRe.MatchString(digest) {
		return "", runtime.Fail("Invalid image digest %q.", digest)
	}
	name, _, _ := strings.Cut(image, "@")
	slash := strings.LastIndex(name, "/")
	if colon := strings.LastIndex(name, ":"); colon > slash {
		name = name[:colon]
	}
	return name + "@" + digest, nil
}

// Check reads the container's state (and HEALTHCHECK) with one inspect.
func (r *Runtime) Check(ctx context.Context, w runtime.Workload) runtime.Health {
	_, name := parse(w)
	subject := "container " + name
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	var st struct {
		Missing  bool   `json:"missing"`
		Running  bool   `json:"running"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
		Health   string `json:"health"`
	}
	if err := r.Helper.Call(ctx, "docker.inspect", map[string]string{"name": name}, &st); err != nil {
		return runtime.Health{State: runtime.Unhealthy, Problem: subject + " could not be inspected"}
	}
	switch {
	case st.Missing:
		return runtime.Health{State: runtime.Missing, Problem: subject + " not found"}
	// Docker reports a crash-looping container as running with status "restarting".
	case !st.Running || st.Status == "restarting":
		detail := fmt.Sprintf("exit %d", st.ExitCode)
		if st.Status != "" {
			detail = st.Status + ", " + detail
		}
		return runtime.Health{State: runtime.Unhealthy, Problem: fmt.Sprintf("%s is not running (%s)", subject, detail)}
	case st.Health == "unhealthy":
		return runtime.Health{State: runtime.Unhealthy, Problem: subject + " HEALTHCHECK failed"}
	case st.Health == "starting":
		return runtime.Health{State: runtime.Starting, Problem: subject + " HEALTHCHECK starting"}
	}
	return runtime.Health{State: runtime.Healthy}
}

// Remove removes the container.
func (r *Runtime) Remove(ctx context.Context, w runtime.Workload) error {
	_, name := parse(w)
	ctx, cancel := context.WithTimeout(ctx, runtime.Quick)
	defer cancel()
	return r.Helper.Call(ctx, "docker.control", map[string]string{"name": name, "action": "remove"}, nil)
}
