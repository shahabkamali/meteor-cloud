package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/config"
)

// artifactIDRe keeps an artifact id a plain file name (the server sends UUIDs).
var artifactIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// sidecar is the file next to an artifact holding its verified SHA-256.
func sidecar(path string) string { return path + ".sha256" }

// fileSHA256 hashes a file in a streaming way.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cached reports whether path holds a verified copy. With an expected checksum
// (from the signed item) the file is hashed again; without one the sidecar
// written after the last verified download is enough, as in the Python agent.
func cached(path, expected string) bool {
	if st, err := os.Lstat(path); err != nil || !st.Mode().IsRegular() {
		return false
	}
	stored, err := os.ReadFile(sidecar(path))
	if err != nil {
		return false
	}
	if expected == "" {
		return true
	}
	if strings.ToLower(strings.TrimSpace(string(stored))) != expected {
		return false
	}
	sum, err := fileSHA256(path)
	return err == nil && sum == expected
}

// ensureArtifact downloads artifact id (or reuses a verified copy) and returns
// its path. Progress goes to the console through progress-only heartbeats.
func (c *cycle) ensureArtifact(ctx context.Context, item api.DesiredItem) (string, error) {
	id := item.ArtifactID
	if !artifactIDRe.MatchString(id) {
		return "", fmt.Errorf("artifact id %q is not a plain name", id)
	}
	expected := strings.ToLower(strings.TrimSpace(item.ArtifactSHA256))
	dir := c.d.Paths.ArtifactsDir
	dest := filepath.Join(dir, id)
	if cached(dest, expected) {
		return dest, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("artifacts: %w", err)
	}
	c.progress(ctx, item.WorkloadKey, 0)
	bucket := 0
	onProgress := func(received, total int64) {
		percent := 0
		if total > 0 {
			percent = int(min(99, received*100/total))
		}
		if percent/10 != bucket {
			bucket = percent / 10
			c.progress(ctx, item.WorkloadKey, percent)
		}
	}

	partial := dest + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return "", fmt.Errorf("artifact %s: %w", id, err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(partial)
		}
	}()
	sum, err := c.d.API.Download(ctx, c.token, id, f, onProgress)
	if err != nil {
		return "", err
	}
	if expected != "" && sum != expected {
		return "", &api.Error{Code: "checksum_mismatch", Message: fmt.Sprintf("Artifact %s does not match the signed checksum; refusing to install it.", id)}
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return "", fmt.Errorf("artifact %s: %w", id, err)
	}
	if err := os.Rename(partial, dest); err != nil {
		return "", fmt.Errorf("artifact %s: %w", id, err)
	}
	ok = true
	if err := config.WriteFileAtomic(sidecar(dest), []byte(sum+"\n"), 0o640); err != nil {
		return "", fmt.Errorf("artifact %s: %w", id, err)
	}
	c.log.Info("downloaded artifact", "artifact", id, "workload", item.WorkloadKey)
	return dest, nil
}
