// Package runtime is what the deploy module and its runtimes share: the Runtime
// interface, the Workload a runtime installs, and the Health it reports. Each
// runtime (systemd, docker, compose) lives in its own sub-package, does its work
// through the root helper, and is listed once in deploy/runtimes.go.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Helper is the part of the root helper client a runtime uses.
type Helper interface {
	Call(ctx context.Context, op string, params, out any) error
}

// Timeouts of helper calls. The helper bounds the work too; these bound the
// wait so a hung helper never holds the deploy module forever.
const (
	// Slow covers pulls, loads and compose up (the helper allows 10 minutes).
	Slow = 11 * time.Minute
	// Quick covers state queries and restarts.
	Quick = 3 * time.Minute
)

// Workload is one release of one workload, ready to install.
type Workload struct {
	// Key is the workload_key; the default unit, container or project name.
	Key string
	// ReleaseID and Version name the release (logs and errors).
	ReleaseID, Version string
	// Spec is the release's kind-specific settings as the server sent them.
	Spec json.RawMessage
	// Artifact is the path of the downloaded, verified artifact ("" when the
	// release has none, such as a docker release that pulls an image).
	Artifact string
}

// State is how a workload is doing.
type State string

// States a runtime reports.
const (
	// Healthy: running (and its HEALTHCHECK, if any, passes).
	Healthy State = "healthy"
	// Unhealthy: installed but not running, or failing its HEALTHCHECK.
	Unhealthy State = "unhealthy"
	// Starting: coming up; neither healthy nor failed yet.
	Starting State = "unknown"
	// Missing: gone (for example `docker rm`); the deploy module installs it again.
	Missing State = "missing"
)

// Health is a runtime's view of one workload. Problem says why it is not healthy.
type Health struct {
	State   State
	Problem string
}

// Result is what Apply did.
type Result struct {
	// Health right after the install.
	Health Health
}

// Runtime installs and watches one kind of workload. Implementations are
// stateless: everything they need is in the Workload.
type Runtime interface {
	// Kind is the release kind this runtime handles ("systemd", "docker", "docker_compose").
	Kind() string
	// Apply installs w and starts it. An error means the install failed.
	Apply(ctx context.Context, w Workload) (Result, error)
	// Check reports w's health now without changing anything.
	Check(ctx context.Context, w Workload) Health
	// Remove stops w and removes it.
	Remove(ctx context.Context, w Workload) error
}

// Name returns the string field of spec named field, or fallback when it is
// missing or blank.
func Name(spec json.RawMessage, field, fallback string) string {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(spec, &fields)
	var s string
	if json.Unmarshal(fields[field], &s) == nil {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			return trimmed
		}
	}
	return fallback
}

// Failure is an install problem worded for the console, in the same words the
// Python agent used (sentences, so not a Go-style error string).
type Failure struct{ Message string }

func (f *Failure) Error() string { return f.Message }

// Fail returns a *Failure with a formatted message.
func Fail(format string, args ...any) error {
	return &Failure{Message: fmt.Sprintf(format, args...)}
}
