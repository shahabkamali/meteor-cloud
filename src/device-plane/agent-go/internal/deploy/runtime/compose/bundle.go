package compose

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"meteorcloud/meteorcli/internal/deploy/runtime"
)

// Limits of a zip bundle, so a hostile or broken archive cannot fill the disk.
const (
	maxEntries   = 10000
	maxUnzipped  = 1 << 30
	maxComposeIn = 16 << 20
)

// materialize puts the compose file of artifact into dir and returns its name.
// A zip bundle is unpacked (its compose file is one of candidates); any other
// file is the compose file itself and is copied to compose.yaml. Existing files
// in dir stay, as the Python agent left them (a project may keep data there).
func materialize(artifact, dir string) (string, error) {
	zr, err := zip.OpenReader(artifact)
	if err == nil {
		defer zr.Close()
		if err := unzip(&zr.Reader, dir); err != nil {
			return "", err
		}
		for _, name := range candidates {
			if st, err := os.Lstat(filepath.Join(dir, name)); err == nil && st.Mode().IsRegular() {
				return name, nil
			}
		}
		return "", runtime.Fail("Compose zip must contain docker-compose.yml, docker-compose.yaml, compose.yml, or compose.yaml.")
	}
	src, err := os.Open(artifact)
	if err != nil {
		return "", fmt.Errorf("compose artifact: %w", err)
	}
	defer src.Close()
	if err := writeFile(filepath.Join(dir, "compose.yaml"), io.LimitReader(src, maxComposeIn), 0o640); err != nil {
		return "", err
	}
	return "compose.yaml", nil
}

// unzip extracts regular files and directories only, refusing names that leave dir.
func unzip(zr *zip.Reader, dir string) error {
	if len(zr.File) > maxEntries {
		return fmt.Errorf("compose zip has more than %d entries", maxEntries)
	}
	var total int64
	for _, f := range zr.File {
		name := filepath.FromSlash(f.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("compose zip entry %q leaves the project directory", f.Name)
		}
		dest := filepath.Join(dir, name)
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(dest, 0o750); err != nil {
				return fmt.Errorf("compose zip: %w", err)
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("compose zip entry %q is not a regular file", f.Name)
		}
		total += int64(f.UncompressedSize64)
		if total > maxUnzipped || f.UncompressedSize64 > maxUnzipped {
			return fmt.Errorf("compose zip unpacks to more than %d bytes", maxUnzipped)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return fmt.Errorf("compose zip: %w", err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("compose zip %s: %w", f.Name, err)
		}
		err = writeFile(dest, io.LimitReader(rc, int64(f.UncompressedSize64)+1), 0o640)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// writeFile replaces path with r's content, never following a link at path.
func writeFile(path string, r io.Reader, perm os.FileMode) error {
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return fmt.Errorf("compose: %w", err)
	}
	_, werr := io.Copy(f, r)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("compose %s: %w", strings.TrimPrefix(path, filepath.Dir(filepath.Dir(path))+"/"), err)
	}
	return os.Chmod(path, perm)
}
