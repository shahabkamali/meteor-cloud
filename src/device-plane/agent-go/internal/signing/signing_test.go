package signing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/state"
)

// Vectors produced by the Python agent (edge_agent.signing) and the contract
// harness signer with seed bytes 0..31: the Go code must agree byte for byte.
const (
	pyItem      = `{"workload_key": "demo-app", "kind": "docker", "release_id": "7b1c3c1e-5a0e-4c39-9d1e-2b8f0c7a9e11", "release_name": "demo", "release_version": "1.0.0", "artifact_id": null, "revision": 3, "artifact_sha256": null, "spec": {"image": "nginx:1.27", "env": {"GREETING": "h\u00e9llo \"w\"\n<&>\u2028\u0001", "Z": 1.5, "A": [1, true, null]}, "ports": ["8080:80"]}}`
	pyCanonical = "{\"artifact_id\":null,\"artifact_sha256\":null,\"device_id\":\"dev-1\",\"kind\":\"docker\",\"release_id\":\"7b1c3c1e-5a0e-4c39-9d1e-2b8f0c7a9e11\",\"release_version\":\"1.0.0\",\"revision\":3,\"spec\":{\"env\":{\"A\":[1,true,null],\"GREETING\":\"héllo \\\"w\\\"\\n<&>\u2028\\u0001\",\"Z\":1.5},\"image\":\"nginx:1.27\",\"ports\":[\"8080:80\"]},\"workload_key\":\"demo-app\"}"
	pyPublic    = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
	pySignature = "78uxm32hJBDc8mOkufI1CCq16KvDvXRBJBPaagTSRIW1IakSuZ2Ee2DUKvu-FI6P7b72sULBmpkKkg8kkjAGBg"
)

func item(t *testing.T, raw string) api.DesiredItem {
	t.Helper()
	var it api.DesiredItem
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatal(err)
	}
	return it
}

func TestCanonicalMatchesPython(t *testing.T) {
	v := &Verifier{DeviceID: "dev-1"}
	msg, err := v.payload(item(t, pyItem))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimPrefix(string(msg), desiredContext); got != pyCanonical {
		t.Fatalf("canonical differs:\n got %s\nwant %s", got, pyCanonical)
	}
	if !verify(pyPublic, msg, pySignature) {
		t.Fatal("python signature does not verify")
	}
}

func TestCanonicalValues(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":{"d":[],"c":{}}}`: `{"a":{"c":{},"d":[]},"b":1}`,
		`"tab\tq\\"`:                  `"tab\tq\\"`,
		`1e+20`:                       `1e+20`,
		`false`:                       `false`,
		`{"é":1,"z":2,"a":3}`:         `{"a":3,"z":2,"é":1}`,
	}
	for in, want := range cases {
		got, err := Canonical(json.RawMessage(in))
		if err != nil || string(got) != want {
			t.Errorf("Canonical(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
	if _, err := Canonical(json.RawMessage(`{`)); err == nil {
		t.Error("broken JSON accepted")
	}
}

type keyPair struct {
	id   string
	pub  string
	priv ed25519.PrivateKey
}

func newKey(id string, seed byte) keyPair {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	return keyPair{id: id, pub: enc(priv.Public().(ed25519.PublicKey)), priv: priv}
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k keyPair) sign(t *testing.T, deviceID string, it map[string]any) api.DesiredItem {
	t.Helper()
	raw, _ := json.Marshal(it)
	v := &Verifier{DeviceID: deviceID}
	msg, err := v.payload(item(t, string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	it["key_id"], it["signature"] = k.id, enc(ed25519.Sign(k.priv, msg))
	raw, _ = json.Marshal(it)
	return item(t, string(raw))
}

func (k keyPair) endorse(next keyPair) api.SigningKey {
	body, _ := json.Marshal(map[string]string{"key_id": next.id, "public_key": next.pub})
	c, _ := Canonical(body)
	return api.SigningKey{KeyID: next.id, PublicKey: next.pub, EndorsedBy: k.id,
		Endorsement: enc(ed25519.Sign(k.priv, append([]byte(endorsementContext), c...)))}
}

func desired() map[string]any {
	return map[string]any{"workload_key": "w", "kind": "docker", "release_id": "r", "release_version": "1",
		"artifact_id": nil, "revision": 1, "spec": map[string]any{"image": "x"}}
}

type fetcher struct {
	keys  []api.SigningKey
	err   error
	calls int
}

func (f *fetcher) fetch(context.Context) ([]api.SigningKey, error) {
	f.calls++
	return f.keys, f.err
}

func newVerifier(t *testing.T, st *state.Store, f *fetcher) *Verifier {
	return &Verifier{State: st, DeviceID: "dev", CredentialFP: CredentialFingerprint("tok"), Fetch: f.fetch}
}

func store(t *testing.T) *state.Store {
	st, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func refused(err error) bool {
	var r *Refused
	return errors.As(err, &r)
}

func TestVerifierPinsAndChecks(t *testing.T) {
	ctx := context.Background()
	k1, k2, rogue := newKey("k1", 1), newKey("k2", 50), newKey("rogue", 99)
	st := store(t)
	f := &fetcher{keys: []api.SigningKey{{KeyID: k1.id, PublicKey: k1.pub}}}

	good := k1.sign(t, "dev", desired())
	if err := newVerifier(t, st, f).Check(ctx, good); err != nil {
		t.Fatalf("good item: %v", err)
	}
	// Pinned: the next cycle does not fetch again.
	f.calls = 0
	if err := newVerifier(t, st, f).Check(ctx, good); err != nil || f.calls != 0 {
		t.Fatalf("pinned check: %v, fetches %d", err, f.calls)
	}

	tampered := desired()
	tampered["spec"] = map[string]any{"image": "evil"}
	tampered["key_id"], tampered["signature"] = "k1", good.Signature
	raw, _ := json.Marshal(tampered)
	bad := item(t, string(raw))
	if err := newVerifier(t, st, f).Check(ctx, bad); !refused(err) {
		t.Fatalf("tampered item: %v", err)
	}
	if err := newVerifier(t, st, f).Check(ctx, item(t, `{"workload_key":"w"}`)); !refused(err) {
		t.Fatalf("unsigned item: %v", err)
	}
	// Another device's signature does not verify here.
	if err := newVerifier(t, st, f).Check(ctx, k1.sign(t, "other", desired())); !refused(err) {
		t.Fatalf("other device: %v", err)
	}

	// A rogue key the server now lists is not trusted without an endorsement.
	f.keys = append(f.keys, api.SigningKey{KeyID: rogue.id, PublicKey: rogue.pub})
	if err := newVerifier(t, st, f).Check(ctx, rogue.sign(t, "dev", desired())); !refused(err) {
		t.Fatalf("rogue key: %v", err)
	}
	// k2 endorsed by k1 is pinned on rotation.
	f.keys = append(f.keys, k1.endorse(k2))
	if err := newVerifier(t, st, f).Check(ctx, k2.sign(t, "dev", desired())); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	var p pins
	if _, err := st.Read(PinFile, &p); err != nil || p.Keys["k2"] != k2.pub || p.Keys["rogue"] != "" {
		t.Fatalf("pins %+v, %v", p, err)
	}
}

func TestVerifierServerDoesNotSign(t *testing.T) {
	f := &fetcher{err: api.ErrNotSigning}
	if err := newVerifier(t, store(t), f).Check(context.Background(), item(t, `{"workload_key":"w"}`)); err != nil {
		t.Fatalf("unsigned item on a server without keys: %v", err)
	}
}

func TestVerifierFetchFailure(t *testing.T) {
	f := &fetcher{err: &api.Error{Status: 503, Code: "down"}}
	err := newVerifier(t, store(t), f).Check(context.Background(), item(t, `{"workload_key":"w","key_id":"k","signature":"s"}`))
	if err == nil || refused(err) || !strings.Contains(err.Error(), "fetch signing keys") {
		t.Fatalf("fetch failure: %v", err)
	}
	f.err = &api.Error{Status: 401, Code: "unauthorized"}
	err = newVerifier(t, store(t), f).Check(context.Background(), item(t, `{"workload_key":"w"}`))
	if !api.IsAuth(err) {
		t.Fatalf("401 lost: %v", err)
	}
}

func TestVerifierIgnoresOtherCredentialPins(t *testing.T) {
	ctx := context.Background()
	k1, k2 := newKey("k1", 1), newKey("k2", 50)
	st := store(t)
	f := &fetcher{keys: []api.SigningKey{{KeyID: k1.id, PublicKey: k1.pub}}}
	if err := newVerifier(t, st, f).Check(ctx, k1.sign(t, "dev", desired())); err != nil {
		t.Fatal(err)
	}
	// Re-enrolled (new token): old pins are not used, the new org key is pinned.
	f.keys = []api.SigningKey{{KeyID: k2.id, PublicKey: k2.pub}}
	v := newVerifier(t, st, f)
	v.CredentialFP = CredentialFingerprint("new-token")
	if err := v.Check(ctx, k2.sign(t, "dev", desired())); err != nil {
		t.Fatalf("after re-enrollment: %v", err)
	}
}

func TestVerifierDamagedPinFile(t *testing.T) {
	st := store(t)
	if err := os.WriteFile(filepath.Join(st.Dir(), PinFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	k1 := newKey("k1", 1)
	f := &fetcher{keys: []api.SigningKey{{KeyID: k1.id, PublicKey: k1.pub}}}
	if err := newVerifier(t, st, f).Check(context.Background(), k1.sign(t, "dev", desired())); err != nil {
		t.Fatalf("damaged pin file should start clean: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(st.Dir(), PinFile+".corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("damaged file not moved aside: %v", matches)
	}
}
