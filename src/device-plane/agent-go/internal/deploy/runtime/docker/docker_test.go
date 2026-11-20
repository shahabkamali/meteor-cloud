package docker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"meteorcloud/meteorcli/internal/deploy/runtime"
	"meteorcloud/meteorcli/internal/deploy/runtime/runtimetest"
)

func TestSplitMatchesPythonShlex(t *testing.T) {
	// Outputs of Python's shlex.split for the same inputs.
	cases := map[string][]string{
		"a b":                 {"a", "b"},
		`a "b c" d`:           {"a", "b c", "d"},
		"'x y'z":              {"x yz"},
		"a\\\nb":              {"a\nb"},
		`"a\$b"`:              {`a\$b`},
		`"q\"q"`:              {`q"q`},
		`x\ y`:                {"x y"},
		`"" e`:                {"", "e"},
		"''":                  {""},
		`a\\b`:                {`a\b`},
		"  -g 'daemon off;' ": {"-g", "daemon off;"},
		"":                    nil,
	}
	for in, want := range cases {
		got, err := Split(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("Split(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`"open`, `'open`, `end\`} {
		if _, err := Split(bad); err == nil {
			t.Errorf("Split(%q) accepted", bad)
		}
	}
}

func TestPinnedImage(t *testing.T) {
	d := "sha256:" + string(make([]byte, 0)) + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]string{
		"nginx:1.27":                 "nginx@" + d,
		"registry:5000/team/app:1.0": "registry:5000/team/app@" + d,
		"registry:5000/team/app":     "registry:5000/team/app@" + d,
		"app@sha256:old":             "app@" + d,
	}
	for in, want := range cases {
		if got, err := pinnedImage(in, d); err != nil || got != want {
			t.Errorf("pinnedImage(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if got, _ := pinnedImage("nginx", ""); got != "nginx" {
		t.Errorf("no digest: %q", got)
	}
	if _, err := pinnedImage("nginx", "md5:x"); err == nil {
		t.Error("bad digest accepted")
	}
}

func TestCheckStates(t *testing.T) {
	cases := []struct {
		answer  any
		err     error
		state   runtime.State
		problem string
	}{
		{map[string]any{"running": true, "status": "running"}, nil, runtime.Healthy, ""},
		{map[string]any{"missing": true}, nil, runtime.Missing, "container web not found"},
		{map[string]any{"running": false, "status": "exited", "exit_code": 2}, nil, runtime.Unhealthy, "container web is not running (exited, exit 2)"},
		{map[string]any{"running": true, "status": "restarting", "exit_code": 1}, nil, runtime.Unhealthy, "container web is not running (restarting, exit 1)"},
		{map[string]any{"running": true, "status": "running", "health": "unhealthy"}, nil, runtime.Unhealthy, "container web HEALTHCHECK failed"},
		{map[string]any{"running": true, "status": "running", "health": "starting"}, nil, runtime.Starting, "container web HEALTHCHECK starting"},
		{nil, errors.New("helper down"), runtime.Unhealthy, "container web could not be inspected"},
	}
	for _, c := range cases {
		h := &runtimetest.FakeHelper{Answer: func(string, map[string]any) (any, error) { return c.answer, c.err }}
		r := &Runtime{Helper: h}
		got := r.Check(context.Background(), runtime.Workload{Key: "x", Spec: json.RawMessage(`{"container_name":" web "}`)})
		if got.State != c.state || got.Problem != c.problem {
			t.Errorf("%v: got %+v", c.answer, got)
		}
	}
}

func TestApplyPullsPinnedImage(t *testing.T) {
	running := false
	h := &runtimetest.FakeHelper{Answer: func(op string, p map[string]any) (any, error) {
		switch op {
		case "docker.run":
			running = true
		case "docker.inspect":
			return map[string]any{"running": running, "status": "running"}, nil
		}
		return nil, nil
	}}
	r := &Runtime{Helper: h}
	spec := `{"image":"nginx:1.27","image_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","restart":null,"command":"nginx -g 'daemon off;'"}`
	res, err := r.Apply(context.Background(), runtime.Workload{Key: "web", Spec: json.RawMessage(spec)})
	if err != nil || res.Health.State != runtime.Healthy {
		t.Fatalf("apply: %+v %v", res, err)
	}
	p := h.Calls()[0].Params
	if p["image"] != "nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" || p["restart"] != "" || p["name"] != "web" {
		t.Fatalf("params %v", p)
	}
	if !reflect.DeepEqual(p["command"], []any{"nginx", "-g", "daemon off;"}) {
		t.Fatalf("command %v", p["command"])
	}
	if _, err := r.Apply(context.Background(), runtime.Workload{Key: "web", Spec: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("no image and no tarball accepted")
	}
	if err := r.Remove(context.Background(), runtime.Workload{Key: "web"}); err != nil || r.Kind() != "docker" {
		t.Fatal(err)
	}
}
