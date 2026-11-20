package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	"meteorcloud/meteorcli/internal/api"
	"meteorcloud/meteorcli/internal/state"
)

// Signature contexts; they must match the control plane (app/signing/service.py).
const (
	desiredContext     = "meteorcloud-desired-v1\n"
	endorsementContext = "meteorcloud-key-endorsement-v1\n"
)

// PinFile is the state file with the pinned organization keys. The Python agent
// wrote the same shape (without a version), so an imported file keeps working.
const PinFile = "signing-keys.json"

// pinVersion is the format of PinFile.
const pinVersion = 1

// signedFields are the item fields a signature covers, in sorted order, plus
// device_id. They must match signed_desired_payload on the server.
var signedFields = []string{
	"artifact_id", "artifact_sha256", "device_id", "kind", "release_id",
	"release_version", "revision", "spec", "workload_key",
}

// Refused is an item the device must not install; Reason goes to the console.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return r.Reason }

// pins is PinFile.
type pins struct {
	Keys         map[string]string `json:"keys"`
	DeviceID     string            `json:"device_id"`
	CredentialFP string            `json:"credential_fp"`
}

// Verifier checks desired-software items against the keys this device pinned.
// Make one per reconcile cycle: it remembers within the cycle whether the
// server signs at all.
type Verifier struct {
	// State holds PinFile.
	State *state.Store
	// DeviceID is part of every signed payload.
	DeviceID string
	// CredentialFP ties the pins to the device token that fetched them, so pins
	// of an earlier enrollment are never used (see CredentialFingerprint).
	CredentialFP string
	// Fetch returns the server's keys, or api.ErrNotSigning (404).
	Fetch func(ctx context.Context) ([]api.SigningKey, error)
	// Log may be nil.
	Log *slog.Logger

	// serverSigns is nil until Fetch ran in this cycle.
	serverSigns *bool
}

// CredentialFingerprint is a short hash of the device token; pins are dropped
// when it changes (as the Python agent did).
func CredentialFingerprint(deviceToken string) string {
	sum := sha256.Sum256([]byte(deviceToken))
	return hex.EncodeToString(sum[:])[:32]
}

// Check returns nil when item may be installed, a *Refused when it must not
// be, and another error when the keys could not be fetched (the caller reports
// it and tries again on the next cycle; a 401 is reported to identity).
func (v *Verifier) Check(ctx context.Context, item api.DesiredItem) error {
	pinned, err := v.load()
	if err != nil {
		return err
	}
	if len(pinned) == 0 {
		if pinned, err = v.refresh(ctx, pinned); err != nil {
			return err
		}
	}
	if item.Signature == "" || item.KeyID == "" {
		if len(pinned) == 0 && v.serverSigns != nil && !*v.serverSigns {
			return nil // an older control plane that does not sign yet
		}
		return &Refused{"Desired software is not signed; refusing to install it."}
	}
	if _, ok := pinned[item.KeyID]; !ok {
		if pinned, err = v.refresh(ctx, pinned); err != nil {
			return err
		}
	}
	public, ok := pinned[item.KeyID]
	if !ok {
		return &Refused{fmt.Sprintf("Desired software is signed by an untrusted key (%s); refusing to install it.", item.KeyID)}
	}
	message, err := v.payload(item)
	if err != nil {
		return &Refused{"Desired software signature does not verify; refusing to install it."}
	}
	if !verify(public, message, item.Signature) {
		return &Refused{"Desired software signature does not verify; refusing to install it."}
	}
	return nil
}

// payload is the signed message of item for this device.
func (v *Verifier) payload(item api.DesiredItem) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item.Raw, &fields); err != nil || fields == nil {
		return nil, errors.New("item is not an object")
	}
	id, err := json.Marshal(v.DeviceID)
	if err != nil {
		return nil, err
	}
	fields["device_id"] = id
	body, err := canonicalObject(fields, signedFields...)
	if err != nil {
		return nil, err
	}
	return append([]byte(desiredContext), body...), nil
}

// load returns the pinned keys, or none when the file is missing, damaged, or
// belongs to another device or credential.
func (v *Verifier) load() (map[string]string, error) {
	var p pins
	_, err := v.State.Read(PinFile, &p)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, state.ErrCorrupt):
		return map[string]string{}, nil
	case err != nil:
		return nil, fmt.Errorf("signing: %w", err)
	}
	if p.DeviceID != "" && p.DeviceID != v.DeviceID {
		return map[string]string{}, nil
	}
	// An exact credential match: a late save of an earlier enrollment must not
	// bring that enrollment's pins back.
	if v.CredentialFP != "" && p.CredentialFP != v.CredentialFP {
		return map[string]string{}, nil
	}
	if p.Keys == nil {
		p.Keys = map[string]string{}
	}
	return p.Keys, nil
}

func (v *Verifier) save(keys map[string]string) error {
	if err := v.State.Write(PinFile, pinVersion, pins{Keys: keys, DeviceID: v.DeviceID, CredentialFP: v.CredentialFP}); err != nil {
		return fmt.Errorf("signing: %w", err)
	}
	return nil
}

// refresh pins every key on first use, later only keys a pinned key endorsed
// (a rotation, possibly a chain of them).
func (v *Verifier) refresh(ctx context.Context, pinned map[string]string) (map[string]string, error) {
	fetched, err := v.Fetch(ctx)
	if errors.Is(err, api.ErrNotSigning) {
		no := false
		v.serverSigns = &no
		return pinned, nil
	}
	if err != nil {
		return pinned, fmt.Errorf("fetch signing keys: %w", err)
	}
	yes := true
	v.serverSigns = &yes
	if len(pinned) == 0 {
		pinned = map[string]string{}
		for _, k := range fetched {
			if k.KeyID != "" && k.PublicKey != "" {
				pinned[k.KeyID] = k.PublicKey
			}
		}
		if len(pinned) > 0 {
			ids := make([]string, 0, len(pinned))
			for id := range pinned {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			v.logger().Warn("pinned organization signing keys on first use", "keys", strings.Join(ids, ","))
			if err := v.save(pinned); err != nil {
				return pinned, err
			}
		}
		return pinned, nil
	}
	added := false
	for changed := true; changed; {
		changed = false
		for _, k := range fetched {
			endorser, ok := pinned[k.EndorsedBy]
			if k.KeyID == "" || !ok || k.Endorsement == "" {
				continue
			}
			if _, have := pinned[k.KeyID]; have {
				continue
			}
			body, err := json.Marshal(map[string]string{"key_id": k.KeyID, "public_key": k.PublicKey})
			if err != nil {
				continue
			}
			c, err := Canonical(body)
			if err != nil {
				continue
			}
			if verify(endorser, append([]byte(endorsementContext), c...), k.Endorsement) {
				pinned[k.KeyID] = k.PublicKey
				v.logger().Info("pinned rotated signing key", "key", k.KeyID, "endorsed_by", k.EndorsedBy)
				changed, added = true, true
			}
		}
	}
	if added {
		if err := v.save(pinned); err != nil {
			return pinned, err
		}
	}
	return pinned, nil
}

func (v *Verifier) logger() *slog.Logger {
	if v.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return v.Log
}

// verify checks an Ed25519 signature; key and signature are base64url (padding optional).
func verify(publicKey string, message []byte, signature string) bool {
	pub, err := b64url(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := b64url(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
