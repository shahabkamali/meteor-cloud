// Package runtimetest has a fake root helper for the runtime tests. Only tests import it.
package runtimetest

import (
	"context"
	"encoding/json"
	"sync"
)

// FakeHelper answers helper calls from Answer and records them. Tests of the
// runtimes and of the deploy module use it instead of the root helper.
type FakeHelper struct {
	// Answer returns the result of op (marshalled into out) or an error.
	Answer func(op string, params map[string]any) (any, error)

	mu    sync.Mutex
	calls []FakeCall
}

// FakeCall is one recorded call.
type FakeCall struct {
	Op     string
	Params map[string]any
}

// Call implements runtime.Helper.
func (f *FakeHelper) Call(_ context.Context, op string, params, out any) error {
	raw, _ := json.Marshal(params)
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	f.mu.Lock()
	f.calls = append(f.calls, FakeCall{op, p})
	f.mu.Unlock()
	result, err := f.Answer(op, p)
	if err != nil {
		return err
	}
	if out != nil && result != nil {
		data, _ := json.Marshal(result)
		return json.Unmarshal(data, out)
	}
	return nil
}

// Calls returns the recorded calls.
func (f *FakeHelper) Calls() []FakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeCall(nil), f.calls...)
}
