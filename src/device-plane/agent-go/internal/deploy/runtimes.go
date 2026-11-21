package deploy

import (
	"meteorcloud/meteorcli/internal/deploy/runtime"
	"meteorcloud/meteorcli/internal/deploy/runtime/compose"
	"meteorcloud/meteorcli/internal/deploy/runtime/docker"
	"meteorcloud/meteorcli/internal/deploy/runtime/systemd"
	"meteorcloud/meteorcli/internal/platform"
)

// Kind is one deploy kind this agent can apply.
type Kind struct {
	// Runtime installs and watches workloads of this kind.
	Runtime runtime.Runtime
	// Available reports whether this device has the tool the runtime needs.
	Available func(platform.Tools) bool
	// Missing is the error reported when the tool is not installed.
	Missing string
}

// Runtimes is the registry of deploy kinds. Add a kind: a package under
// runtime/ and one entry here. Kinds lists the names in this order.
func Runtimes(h runtime.Helper, artifactsDir string) map[string]Kind {
	return map[string]Kind{
		"systemd": {
			Runtime:   &systemd.Runtime{Helper: h},
			Available: func(t platform.Tools) bool { return t.Systemd },
			Missing:   "This device does not support systemd.",
		},
		"docker": {
			Runtime:   &docker.Runtime{Helper: h},
			Available: func(t platform.Tools) bool { return t.Docker },
			Missing:   "This device does not support Docker.",
		},
		"docker_compose": {
			Runtime:   &compose.Runtime{Helper: h, ArtifactsDir: artifactsDir},
			Available: func(t platform.Tools) bool { return t.DockerCompose },
			Missing:   "This device does not support Docker Compose.",
		},
	}
}

// Kinds is capabilities.deploy_kinds: what this agent's code can apply.
func Kinds() []string { return []string{"systemd", "docker", "docker_compose"} }
