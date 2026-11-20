package deploy

import (
	"time"

	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/deploy/runtime"
)

// maxError bounds last_error (the console shows it; the API takes 2000).
const maxError = 500

// report is one software_report entry (common.json#/$defs/software_report_item).
// A map keeps the exact key set the Python agent sent.
type report map[string]any

// Sync states.
const (
	syncInSync     = "in_sync"
	syncFailed     = "failed"
	syncUpdating   = "updating"
	syncRolledBack = "rolled_back"
)

func short(s string) any {
	if s == "" {
		return nil
	}
	if r := []rune(s); len(r) > maxError {
		return string(r[:maxError])
	}
	return s
}

func (r report) status() string {
	s, _ := r["sync_status"].(string)
	return s
}

func (r report) lastError() string {
	s, _ := r["last_error"].(string)
	return s
}

func failed(key, message string) report {
	return report{"workload_key": key, "sync_status": syncFailed, "progress_percent": 0, "health": "unhealthy", "last_error": short(message)}
}

func updating(key string, percent int) report {
	return report{"workload_key": key, "sync_status": syncUpdating, "progress_percent": percent, "health": "unknown"}
}

// healthWord maps a runtime state to the report's health.
func healthWord(s runtime.State) string {
	switch s {
	case runtime.Healthy:
		return "healthy"
	case runtime.Unhealthy, runtime.Missing:
		return "unhealthy"
	}
	return "unknown"
}

// nullable sends "" as null, as the Python agent sent a missing field.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func inSync(item api.DesiredItem, health, problem string) report {
	return report{
		"workload_key": item.WorkloadKey, "installed_release_id": nullable(item.ReleaseID),
		"installed_version": nullable(item.ReleaseVersion), "sync_status": syncInSync,
		"progress_percent": 100, "health": health, "last_error": short(problem),
	}
}

// rolledBackReport says the previous release runs again because item failed.
func rolledBackReport(item, previous api.DesiredItem, health, reason string) report {
	version := previous.ReleaseVersion
	if version == "" {
		version = previous.ReleaseID
	}
	return report{
		"workload_key": item.WorkloadKey, "installed_release_id": nullable(previous.ReleaseID),
		"installed_version": nullable(previous.ReleaseVersion), "sync_status": syncRolledBack,
		"progress_percent": 100, "health": health,
		"last_error": short("Rolled back to " + version + ": " + reason),
	}
}

// event is one devices/{id}/events message (mqtt/events.json).
func event(kind, app string, now time.Time, extra map[string]any) map[string]any {
	e := map[string]any{"type": kind, "app": app, "timestamp": now.UTC().Format(time.RFC3339)}
	for k, v := range extra {
		e[k] = v
	}
	return e
}
