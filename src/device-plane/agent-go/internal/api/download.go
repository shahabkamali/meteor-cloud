package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Download limits. A release artifact (a docker save tarball) can be large and a
// board's network slow, so a download is bounded by how long it may stall, not
// by one short timeout; MaxDownload still ends one that never finishes.
const (
	// RedirectHeader tells the server this agent follows a redirect to storage.
	RedirectHeader = "X-Meteorcli-Redirect"
	// ChecksumHeader carries the artifact's SHA-256 (hex).
	ChecksumHeader = "X-Checksum-SHA256"
	// DownloadStall fails a download that received nothing for this long (the
	// Python agent's socket timeout).
	DownloadStall = 5 * time.Minute
	// MaxDownload bounds one download in total.
	MaxDownload = 2 * time.Hour
)

// Progress is told how many bytes arrived so far and the total (0 when unknown).
type Progress func(received, total int64)

// Download fetches artifact id into w and returns its SHA-256 (hex), checked
// against the X-Checksum-SHA256 the server sent. A 302 is followed to the
// storage URL without the Authorization header, and never from https to http;
// the checksum then comes from the redirect and must be present.
func (c *Client) Download(ctx context.Context, deviceToken, artifactID string, w io.Writer, progress Progress) (string, error) {
	base, hc := c.target()
	if base == "" {
		return "", ErrNoServer
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDownload)
	defer cancel()

	apiURL := base + "/api/v1/agent/artifacts/" + url.PathEscape(artifactID) + "/download"
	req, err := c.downloadRequest(ctx, apiURL)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	req.Header.Set(RedirectHeader, "1")
	resp, err := hc.Do(req)
	if err != nil {
		return "", &Error{Code: "network_error", Message: redactURLError(err, base)}
	}
	expected := ""
	if isRedirect(resp.StatusCode) {
		resp, expected, err = c.followStorage(ctx, hc, apiURL, resp)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		return "", decodeError(resp, data)
	}
	if expected == "" {
		expected = strings.ToLower(strings.TrimSpace(resp.Header.Get(ChecksumHeader)))
	}

	total, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	digest := sha256.New()
	stall := time.AfterFunc(DownloadStall, cancel)
	defer stall.Stop()
	buf := make([]byte, 64<<10)
	var received int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			stall.Reset(DownloadStall)
			digest.Write(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				return "", fmt.Errorf("download %s: %w", artifactID, werr)
			}
			received += int64(n)
			if progress != nil {
				progress(received, max(total, 0))
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			if ctx.Err() != nil {
				return "", &Error{Code: "network_error", Message: fmt.Sprintf("download %s stalled or took too long", artifactID)}
			}
			return "", &Error{Code: "network_error", Message: rerr.Error()}
		}
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if expected != "" && actual != expected {
		return "", &Error{Code: "checksum_mismatch", Message: "Downloaded artifact failed SHA-256 verification."}
	}
	return actual, nil
}

func (c *Client) downloadRequest(ctx context.Context, target string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set(ProtocolHeader, ProtocolVersion)
	return req, nil
}

// followStorage opens the storage URL a download redirected to, without the
// device token, and returns the answer and the checksum sent with the redirect.
func (c *Client) followStorage(ctx context.Context, hc *http.Client, apiURL string, redirect *http.Response) (*http.Response, string, error) {
	location := redirect.Header.Get("Location")
	checksum := strings.ToLower(strings.TrimSpace(redirect.Header.Get(ChecksumHeader)))
	_, _ = io.Copy(io.Discard, io.LimitReader(redirect.Body, maxBody))
	redirect.Body.Close()
	if location == "" {
		return nil, "", &Error{Status: redirect.StatusCode, Code: "download_redirect_invalid", Message: "The download redirect has no location."}
	}
	if len(checksum) != 64 {
		// Without the server's checksum the storage copy cannot be checked.
		return nil, "", &Error{Code: "checksum_missing", Message: "The download redirect did not include a SHA-256 checksum."}
	}
	from, err := url.Parse(apiURL)
	if err != nil {
		return nil, "", fmt.Errorf("download: %w", err)
	}
	to, err := from.Parse(location)
	if err != nil || (to.Scheme != "https" && to.Scheme != "http") || (to.Scheme == "http" && from.Scheme == "https") {
		return nil, "", &Error{Code: "download_redirect_insecure", Message: "Refusing to download over an insecure redirect."}
	}
	req, err := c.downloadRequest(ctx, to.String())
	if err != nil {
		return nil, "", err
	}
	// Storage is not the control plane: no agent headers beyond the basics.
	req.Header.Del(ProtocolHeader)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, "", &Error{Code: "network_error", Message: "storage download failed: " + redactQuery(err.Error(), to)}
	}
	if isRedirect(resp.StatusCode) {
		resp.Body.Close()
		return nil, "", &Error{Status: resp.StatusCode, Code: "download_redirect_invalid", Message: "Storage answered with another redirect."}
	}
	return resp, checksum, nil
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// redactQuery removes a presigned URL's query (it is a credential) from msg.
func redactQuery(msg string, u *url.URL) string {
	if u.RawQuery == "" {
		return msg
	}
	return strings.ReplaceAll(msg, "?"+u.RawQuery, "?<redacted>")
}
