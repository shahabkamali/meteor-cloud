// Package signing checks signed desired software before anything is downloaded
// or applied (docs/fleet/signed-updates.md). The control plane signs each item
// with the organization's Ed25519 key; the agent pins the organization's public
// keys the first time it fetches them and afterwards trusts a new key only when
// a pinned key endorsed it. A tampered artifact store, database or network
// answer therefore cannot make the device install something the organization
// did not sign.
package signing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Canonical returns the canonical JSON of a JSON value exactly as the control
// plane computes it (Python json.dumps with sort_keys=True, separators=(",", ":")
// and ensure_ascii=False): keys sorted, no spaces, non-ASCII kept, numbers as
// the server wrote them.
func Canonical(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		writeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Byte order of UTF-8 is code point order, which is what Python sorts by.
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unexpected %T", v)
	}
	return nil
}

// writeString escapes like Python's json with ensure_ascii=False: only the
// quote, the backslash and control characters below 0x20.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// canonicalObject is the canonical JSON of an object built from raw values;
// a missing value is null, as Python's item.get() gives None. keys must be
// sorted already.
func canonicalObject(fields map[string]json.RawMessage, keys ...string) ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		v := fields[k]
		if len(bytes.TrimSpace(v)) == 0 {
			v = json.RawMessage("null")
		}
		b.WriteString(`"` + k + `":`)
		c, err := Canonical(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		b.Write(c)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}
