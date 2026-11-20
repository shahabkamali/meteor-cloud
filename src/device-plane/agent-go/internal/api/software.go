package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// DesiredItem is one entry of GET /software (common.json#/$defs/desired_software_item).
// Raw keeps the item exactly as the server sent it: the signature covers some of
// its fields byte for byte, and the applied state stores it for a rollback.
type DesiredItem struct {
	WorkloadKey    string          `json:"workload_key"`
	Kind           string          `json:"kind"`
	ReleaseID      string          `json:"release_id"`
	ReleaseName    string          `json:"release_name"`
	ReleaseVersion string          `json:"release_version"`
	ArtifactID     string          `json:"artifact_id"`
	Revision       int64           `json:"revision"`
	Spec           json.RawMessage `json:"spec"`
	ArtifactSHA256 string          `json:"artifact_sha256"`
	KeyID          string          `json:"key_id"`
	Signature      string          `json:"signature"`

	// Raw is the whole item as received.
	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON reads the known fields leniently (null, a missing field or a
// value of the wrong type leaves the zero value, as the Python agent's
// item.get() did) and keeps the raw item.
func (d *DesiredItem) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("desired item is not an object")
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(fields[k], &s)
		return s
	}
	*d = DesiredItem{
		WorkloadKey: str("workload_key"), Kind: str("kind"), ReleaseID: str("release_id"),
		ReleaseName: str("release_name"), ReleaseVersion: str("release_version"),
		ArtifactID: str("artifact_id"), ArtifactSHA256: str("artifact_sha256"),
		KeyID: str("key_id"), Signature: str("signature"),
		Spec: fields["spec"], Raw: bytes.Clone(data),
	}
	var rev json.Number
	if json.Unmarshal(fields["revision"], &rev) == nil {
		if n, err := rev.Int64(); err == nil {
			d.Revision = n
		}
	}
	if string(bytes.TrimSpace(d.Spec)) == "null" {
		d.Spec = nil
	}
	return nil
}

// MarshalJSON writes the item back as it was received, so a stored item still
// verifies and keeps fields this version does not know.
func (d DesiredItem) MarshalJSON() ([]byte, error) {
	if len(d.Raw) > 0 {
		return d.Raw, nil
	}
	type plain DesiredItem
	return json.Marshal(plain(d))
}

// Field returns the raw value of one field of the item, or nil.
func (d DesiredItem) Field(name string) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(d.Raw, &fields) != nil {
		return nil
	}
	return fields[name]
}

// SigningKey is one organization key of GET /signing-keys.
type SigningKey struct {
	KeyID       string `json:"key_id"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	EndorsedBy  string `json:"endorsed_by"`
	Endorsement string `json:"endorsement"`
}

// ErrNotSigning is returned by SigningKeys when the server answers 404: it does
// not sign desired software (an older control plane).
var ErrNotSigning = errors.New("the server does not sign desired software")

// Software lists the desired software for this device. Items that are not
// JSON objects are skipped.
func (c *Client) Software(ctx context.Context, deviceToken string) ([]DesiredItem, error) {
	var raw []json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/v1/agent/software", deviceToken, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]DesiredItem, 0, len(raw))
	for _, r := range raw {
		var item DesiredItem
		if err := json.Unmarshal(r, &item); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

// SigningKeys returns the organization's public keys, or ErrNotSigning.
func (c *Client) SigningKeys(ctx context.Context, deviceToken string) ([]SigningKey, error) {
	var keys []SigningKey
	err := c.do(ctx, http.MethodGet, "/api/v1/agent/signing-keys", deviceToken, nil, &keys)
	if StatusOf(err) == http.StatusNotFound {
		return nil, ErrNotSigning
	}
	if err != nil {
		return nil, fmt.Errorf("signing keys: %w", err)
	}
	return keys, nil
}
