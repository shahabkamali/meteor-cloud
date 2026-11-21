package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"meteorcloud/meteorcli/internal/localrpc"
)

// Compose operations bring up a project the agent prepared in
// <artifacts>/compose/<project>/ from a verified release. A compose file is
// root-equivalent by design (it can mount host paths), like a systemd unit.

// ComposeDirName is the directory under the artifacts directory that holds one
// directory per compose project.
const ComposeDirName = "compose"

// ComposeEnvFile is the env file (variable substitution) the agent may write
// next to the compose file.
const ComposeEnvFile = ".env.meteorcloud"

// composeFiles are the compose file names a project may use.
var composeFiles = map[string]bool{
	"compose.yaml": true, "compose.yml": true, "docker-compose.yml": true, "docker-compose.yaml": true,
}

// ComposeUpRequest is the params of compose.up.
type ComposeUpRequest struct {
	Project string `json:"project"`
	// File is the compose file name in the project directory.
	File string `json:"file"`
	// EnvFile uses ComposeEnvFile from the project directory.
	EnvFile bool `json:"env_file"`
	// ForceRecreate creates the containers again even when nothing changed.
	ForceRecreate bool `json:"force_recreate"`
}

// ComposeProjectRequest is the params of compose.ps and compose.control.
type ComposeProjectRequest struct {
	Project string `json:"project"`
	// Action, for compose.control: "restart" or "down".
	Action string `json:"action,omitempty"`
}

// ComposeService is one container of `docker compose ps`.
type ComposeService struct {
	Service  string `json:"Service"`
	Name     string `json:"Name"`
	State    string `json:"State"`
	ExitCode int    `json:"ExitCode"`
	Health   string `json:"Health"`
}

// ComposePSReply is the answer of compose.ps.
type ComposePSReply struct {
	Services []ComposeService `json:"services"`
}

func auditCompose(raw json.RawMessage) []any {
	var r struct{ Project, File, Action string }
	_ = json.Unmarshal(raw, &r)
	return []any{"project", r.Project, "file", r.File, "action", r.Action}
}

// projectDir returns the project's directory after checking it is a real
// directory (not a link) under the compose directory.
func (h Host) projectDir(project string) (string, error) {
	if err := checkName("project_name", project); err != nil {
		return "", err
	}
	root := filepath.Join(h.ArtifactsDir, ComposeDirName)
	dir := filepath.Join(root, project)
	for _, d := range []string{root, dir} {
		if st, err := os.Lstat(d); err != nil || !st.IsDir() {
			return "", bad("compose project %s has no directory", project)
		}
	}
	return dir, nil
}

// regularFile refuses a link or anything but a plain file: the agent owns the
// directory and must not make root read another file.
func regularFile(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return bad("%s does not exist", filepath.Base(path))
	}
	if err != nil || !st.Mode().IsRegular() {
		return bad("%s is not a regular file", filepath.Base(path))
	}
	return nil
}

func (h Host) composeUp(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req ComposeUpRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	dir, err := h.projectDir(req.Project)
	if err != nil {
		return nil, err
	}
	if !composeFiles[req.File] {
		return nil, bad("file must be compose.yaml, compose.yml, docker-compose.yml or docker-compose.yaml")
	}
	file := filepath.Join(dir, req.File)
	if err := regularFile(file); err != nil {
		return nil, err
	}
	args := []string{"compose", "-p", req.Project, "-f", file}
	if req.EnvFile {
		env := filepath.Join(dir, ComposeEnvFile)
		if err := regularFile(env); err != nil {
			return nil, err
		}
		args = append(args, "--env-file", env)
	}
	args = append(args, "up", "-d", "--remove-orphans")
	if req.ForceRecreate {
		args = append(args, "--force-recreate")
	}
	if _, err := h.Run(ctx, "docker", args...); err != nil {
		return nil, err
	}
	return Started{Started: true}, nil
}

func (h Host) composePS(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req ComposeProjectRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := checkName("project_name", req.Project); err != nil {
		return nil, err
	}
	out, err := h.Run(ctx, "docker", "compose", "-p", req.Project, "ps", "-a", "--format", "json")
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return ComposePSReply{Services: []ComposeService{}}, nil
	}
	return ComposePSReply{Services: parsePS(string(out))}, nil
}

// parsePS reads `docker compose ps --format json`: a JSON array (older Compose)
// or one object per line. Anything else gives no services.
func parsePS(out string) []ComposeService {
	text := strings.TrimSpace(out)
	rows := []ComposeService{}
	if strings.HasPrefix(text, "[") {
		if json.Unmarshal([]byte(text), &rows) != nil {
			return []ComposeService{}
		}
		return rows
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row ComposeService
		if json.Unmarshal([]byte(line), &row) != nil {
			return []ComposeService{}
		}
		rows = append(rows, row)
	}
	return rows
}

func (h Host) composeControl(ctx context.Context, _ localrpc.Peer, raw json.RawMessage) (any, error) {
	var req ComposeProjectRequest
	if err := decode(raw, &req); err != nil {
		return nil, err
	}
	if err := checkName("project_name", req.Project); err != nil {
		return nil, err
	}
	var args []string
	switch req.Action {
	case "restart":
		args = []string{"compose", "-p", req.Project, "restart"}
	case "down":
		args = []string{"compose", "-p", req.Project, "down", "--remove-orphans"}
	default:
		return nil, bad("action must be restart or down")
	}
	if _, err := h.Run(ctx, "docker", args...); err != nil {
		return nil, err
	}
	return Started{Started: true}, nil
}
