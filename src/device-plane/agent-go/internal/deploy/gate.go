package deploy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"meteorcloud/meteorcli/internal/deploy/runtime"
)

// Health gate defaults (app/releases/kinds.py HealthCheck).
const (
	defaultGateTimeout = 60
	defaultGateStable  = 10
	gatePoll           = 2 * time.Second
	probeTimeout       = 5 * time.Second
)

// gate is a release's health_check with defaults filled in.
type gate struct {
	timeout, stable time.Duration
	url             string
	rollback        bool
}

// gateOf returns the release's health_check, or nil when it has none.
func gateOf(spec json.RawMessage) *gate {
	var s struct {
		HealthCheck *struct {
			TimeoutSeconds *float64 `json:"timeout_seconds"`
			StableSeconds  *float64 `json:"stable_seconds"`
			HTTPURL        *string  `json:"http_url"`
			Rollback       *bool    `json:"rollback"`
		} `json:"health_check"`
	}
	if json.Unmarshal(spec, &s) != nil || s.HealthCheck == nil {
		return nil
	}
	h := s.HealthCheck
	g := &gate{timeout: defaultGateTimeout * time.Second, stable: defaultGateStable * time.Second, rollback: true}
	if h.TimeoutSeconds != nil && *h.TimeoutSeconds > 0 {
		g.timeout = time.Duration(*h.TimeoutSeconds) * time.Second
	}
	if h.StableSeconds != nil && *h.StableSeconds >= 0 {
		g.stable = time.Duration(*h.StableSeconds) * time.Second
	}
	if h.HTTPURL != nil {
		g.url = *h.HTTPURL
	}
	if h.Rollback != nil && !*h.Rollback {
		g.rollback = false
	}
	return g
}

// waiter runs the health gate. Its clock and probe are fields so tests need
// not wait in real time.
type waiter struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) bool
	probe func(ctx context.Context, url string) string
	// tick is called on every poll (the module's health registry).
	tick func()
}

func realWaiter(tick func()) *waiter {
	return &waiter{now: time.Now, sleep: sleepCtx, probe: httpProbe, tick: tick}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// wait returns "" once the workload stayed healthy for g.stable, else the last
// problem. It has g.timeout to become healthy; turning unhealthy again starts
// the stable window over.
func (w *waiter) wait(ctx context.Context, check func(context.Context) runtime.Health, g gate) string {
	started := w.now()
	deadline := started.Add(g.timeout + g.stable)
	var healthySince time.Time
	problem := ""
	notWithin := fmt.Sprintf("not healthy within %ds", int(g.timeout/time.Second))
	for {
		if w.tick != nil {
			w.tick()
		}
		now := w.now()
		h := check(ctx)
		healthy, why := h.State == runtime.Healthy, h.Problem
		if healthy && g.url != "" {
			why = w.probe(ctx, g.url)
			healthy = why == ""
		}
		if healthy {
			if healthySince.IsZero() {
				healthySince = now
			}
			if now.Sub(healthySince) >= g.stable {
				return ""
			}
		} else {
			healthySince = time.Time{}
			if why != "" {
				problem = why
			}
			if now.Sub(started) >= g.timeout {
				return orDefault(problem, notWithin)
			}
		}
		if !now.Before(deadline) {
			return orDefault(problem, notWithin)
		}
		if !w.sleep(ctx, gatePoll) {
			return orDefault(problem, "stopped while waiting for the health check")
		}
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// probeClient follows no redirects: 3xx counts as an answer.
var probeClient = &http.Client{
	Timeout:       probeTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		Proxy:           nil, // the URL is on the device or its network
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	},
}

// httpProbe returns "" when url answers 2xx or 3xx, else why not.
func httpProbe(ctx context.Context, url string) string {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Sprintf("%s did not answer (%v)", url, err)
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return fmt.Sprintf("%s did not answer (%v)", url, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return ""
	}
	return fmt.Sprintf("%s answered HTTP %d", url, resp.StatusCode)
}
