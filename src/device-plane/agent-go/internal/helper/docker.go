package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"meteorcloud/meteorcli/internal/localrpc"
)

// Docker operations run one container for a docker release. Like a systemd unit,
// a container is root-equivalent by design; the helper checks names and the
// shape of every argument, never mounts host paths, and the agent asks only for
// releases whose signature it verified.

// Timeouts of docker work. A pull or load of a large image on a slow board can
// take minutes; the agent's heartbeat never waits for it (deploy runs alone).
const (
	slowDocker  = 10 * time.Minute
	quickDocker = 30 * time.Second
	maxEnv      = 256
	maxPorts    = 64
	maxArgs     = 128
	maxArgBytes = 4096
)

var (
	// imageRe is a docker image reference: repository, optional tag and digest.
	imageRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,511}$`)
	// portRe is a -p value such as 8080:80, 127.0.0.1:53:53/udp or [::1]:80:80.
	portRe    = regexp.MustCompile(`^[0-9A-Fa-f.:\[\]]{1,60}(/(tcp|udp|sctp))?$`)
	envKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	restartRe = regexp.MustCompile(`^(no|always|unless-stopped|on-failure(:[0-9]{1,4})?)$`)
	// loadedRe finds the image name in docker load's output.
	loadedRe = regexp.MustCompile(`(?i)Loaded image(?: ID)?:?\s*(\S+)`)
)

// DockerLoadRequest is the params of docker.load.
type DockerLoadRequest struct {
	// Artifact is the file name of a downloaded artifact in the artifacts directory.
	Artifact string `json:"artifact"`
}

// DockerLoadReply is the answer of docker.load.
type DockerLoadReply struct {
	Image string `json:"image"`
}

// DockerRunRequest is the params of docker.run: replace container Name with a
// new one from Image.
type DockerRunRequest struct {
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Ports   []string          `json:"ports"`
	Env     map[string]string `json:"env"`
	Restart string            `json:"restart"`
	// Command is the container's command, already split into arguments.
	Command []string `json:"command"`
}

// DockerNameRequest is the params of operations on one container.
type DockerNameRequest struct {
	Name string `json:"name"`
	// Action, for docker.control: "restart" or "remove".
	Action string `json:"action,omitempty"`
}

// DockerInspectReply is the state of one container. Only these fields are read:
// never its env, labels or logs (they can hold secrets).
type DockerInspectReply struct {
	Missing  bool   `json:"missing"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	// Health is the HEALTHCHECK status ("" when the image has none).
	Health string `json:"health"`
}

// inspectTemplate reads only the state fields of DockerInspectReply.
const inspectTemplate = "{{.State.Running}}|{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}"

func bad(format string, args ...any) error {
	return localrpc.Errorf(localrpc.CodeBadRequest, format, args...)
}

func checkName(what, name string) error {
	if !validName.MatchString(name) {
		return bad("%s %q must be 1-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit", what, name)
	}
	return nil
}

// auditDocker logs the container and image, never env or command.
func auditDocker(raw json.RawMessage) []any {
	var r struct {
		Name, Image, Artifact, Action string
	}
	_ = json.Unmarshal(raw, &r)
	return []any{"container", r.Name, "image", r.Image, "artifact", r.Artifact, "action", r.Action}
}

func (h Host) dockerLoad(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req DockerLoadRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := checkName("artifact", req.Artifact); err != nil {
		return nil, err
	}
	// O_NOFOLLOW: the agent owns the directory, so the file must not be a link
	// to something only root may read. docker load reads it from stdin.
	f, err := os.OpenFile(filepath.Join(h.ArtifactsDir, req.Artifact), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, bad("artifact %s: %v", req.Artifact, err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, bad("artifact %s is not a regular file", req.Artifact)
	}
	out, err := h.RunStdin(ctx, f, "docker", "load")
	if err != nil {
		return nil, err
	}
	if m := loadedRe.FindStringSubmatch(string(out)); m != nil {
		return DockerLoadReply{Image: m[1]}, nil
	}
	return nil, localrpc.Errorf(localrpc.CodeFailed, "docker load succeeded but no image name was reported")
}

func (r *DockerRunRequest) validate() error {
	if err := checkName("container_name", r.Name); err != nil {
		return err
	}
	if !imageRe.MatchString(r.Image) {
		return bad("image %q is not a docker image reference", r.Image)
	}
	if len(r.Ports) > maxPorts {
		return bad("at most %d ports", maxPorts)
	}
	for _, p := range r.Ports {
		if !portRe.MatchString(p) {
			return bad("port %q must look like 8080:80 or 127.0.0.1:53:53/udp", p)
		}
	}
	if len(r.Env) > maxEnv {
		return bad("at most %d env variables", maxEnv)
	}
	for k, v := range r.Env {
		if !envKeyRe.MatchString(k) {
			return bad("env name %q must be letters, digits and '_'", k)
		}
		if strings.ContainsAny(v, "\x00\n\r") || len(v) > 64<<10 {
			return bad("env %s must be one line without NUL, at most 64 KiB", k)
		}
	}
	if r.Restart != "" && !restartRe.MatchString(r.Restart) {
		return bad("restart %q must be no, always, unless-stopped or on-failure[:N]", r.Restart)
	}
	if len(r.Command) > maxArgs {
		return bad("command has more than %d arguments", maxArgs)
	}
	for _, a := range r.Command {
		if strings.ContainsRune(a, 0) || len(a) > maxArgBytes {
			return bad("command arguments must be text without NUL, at most %d bytes", maxArgBytes)
		}
	}
	return nil
}

func (h Host) dockerRun(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req DockerRunRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	args := []string{"run", "-d", "--name", req.Name}
	if req.Restart != "" {
		args = append(args, "--restart", req.Restart)
	}
	for _, p := range req.Ports {
		args = append(args, "-p", p)
	}
	if len(req.Env) > 0 {
		// An env file keeps values (often secrets) out of the argument list,
		// the process table and error messages.
		file, err := h.writeEnvFile(req.Env)
		if err != nil {
			return nil, err
		}
		defer os.Remove(file)
		args = append(args, "--env-file", file)
	}
	// "--" ends docker's options: the image and the command are positional.
	args = append(args, "--", req.Image)
	args = append(args, req.Command...)

	// Replace the old container; a missing one is not an error.
	_, _ = h.Run(ctx, "docker", "rm", "-f", "--", req.Name)
	if _, err := h.Run(ctx, "docker", args...); err != nil {
		return nil, err
	}
	return Started{Started: true}, nil
}

// writeEnvFile writes env as a docker --env-file (KEY=VALUE lines, mode 0600).
func (h Host) writeEnvFile(env map[string]string) (string, error) {
	f, err := os.CreateTemp(h.TempDir, "meteorcli-env-")
	if err != nil {
		return "", fmt.Errorf("env file: %w", err)
	}
	var b strings.Builder
	for k, v := range env {
		b.WriteString(k + "=" + v + "\n")
	}
	_, werr := f.WriteString(b.String())
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("env file: %v %v", werr, cerr)
	}
	return f.Name(), nil
}

func (h Host) dockerInspect(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req DockerNameRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := checkName("container_name", req.Name); err != nil {
		return nil, err
	}
	out, err := h.Run(ctx, "docker", "inspect", "-f", inspectTemplate, "--", req.Name)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return DockerInspectReply{Missing: true}, nil
	}
	return parseInspect(string(out)), nil
}

func parseInspect(out string) DockerInspectReply {
	parts := append(strings.Split(strings.TrimSpace(out), "|"), "", "", "", "")
	code, _ := strconv.Atoi(parts[2])
	return DockerInspectReply{
		Running: strings.EqualFold(parts[0], "true"), Status: parts[1], ExitCode: code, Health: parts[3],
	}
}

func (h Host) dockerControl(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req DockerNameRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := checkName("container_name", req.Name); err != nil {
		return nil, err
	}
	var args []string
	switch req.Action {
	case "restart":
		args = []string{"restart", "--", req.Name}
	case "remove":
		args = []string{"rm", "-f", "--", req.Name}
	default:
		return nil, bad("action must be restart or remove")
	}
	if _, err := h.Run(ctx, "docker", args...); err != nil {
		return nil, err
	}
	return Started{Started: true}, nil
}
