package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestDownload(t *testing.T) {
	body := []byte("artifact bytes")
	var storageAuth, apiAuth, redirectFlag string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/api/v1/agent/artifacts/direct/download", func(w http.ResponseWriter, r *http.Request) {
		apiAuth, redirectFlag = r.Header.Get("Authorization"), r.Header.Get(RedirectHeader)
		w.Header().Set(ChecksumHeader, sum(body))
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/v1/agent/artifacts/redirect/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/storage/x?X-Amz-Signature=secret")
		w.Header().Set(ChecksumHeader, sum(body))
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/api/v1/agent/artifacts/nosum/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/storage/x")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/api/v1/agent/artifacts/bad/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ChecksumHeader, strings.Repeat("0", 64))
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/v1/agent/artifacts/gone/download", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"artifact_not_found","message":"no"}}`))
	})
	mux.HandleFunc("/storage/x", func(w http.ResponseWriter, r *http.Request) {
		storageAuth = r.Header.Get("Authorization")
		_, _ = w.Write(body)
	})

	c, err := New(Options{BaseURL: srv.URL, Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var buf bytes.Buffer
	var lastProgress int64
	got, err := c.Download(ctx, "tok", "direct", &buf, func(n, _ int64) { lastProgress = n })
	if err != nil || got != sum(body) || buf.String() != string(body) || lastProgress != int64(len(body)) {
		t.Fatalf("direct: %q %v %q %d", got, err, buf.String(), lastProgress)
	}
	if apiAuth != "Bearer tok" || redirectFlag != "1" {
		t.Fatalf("api headers: %q %q", apiAuth, redirectFlag)
	}

	buf.Reset()
	if got, err := c.Download(ctx, "tok", "redirect", &buf, nil); err != nil || got != sum(body) {
		t.Fatalf("redirect: %q %v", got, err)
	}
	if storageAuth != "" {
		t.Fatalf("the device token followed the redirect: %q", storageAuth)
	}

	cases := map[string]string{"nosum": "checksum_missing", "bad": "checksum_mismatch", "gone": "artifact_not_found"}
	for id, code := range cases {
		_, err := c.Download(ctx, "tok", id, &bytes.Buffer{}, nil)
		if e, ok := err.(*Error); !ok || e.Code != code {
			t.Errorf("%s: %v, want %s", id, err, code)
		}
	}
}

func TestDownloadRefusesHTTPAfterHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://storage.example/x")
		w.Header().Set(ChecksumHeader, strings.Repeat("a", 64))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c, err := New(Options{BaseURL: srv.URL, HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Download(context.Background(), "tok", "a", &bytes.Buffer{}, nil)
	if e, ok := err.(*Error); !ok || e.Code != "download_redirect_insecure" {
		t.Fatalf("got %v", err)
	}
}

func TestSoftwareAndSigningKeys(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/software", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"workload_key":"a","kind":"docker","revision":"x","spec":null,"extra":1}, 7,
			{"workload_key":"b","revision":4,"artifact_id":null,"spec":{"image":"i"}}]`))
	})
	mux.HandleFunc("/api/v1/agent/signing-keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL})
	items, err := c.Software(context.Background(), "tok")
	if err != nil || len(items) != 2 {
		t.Fatalf("software: %v %v", items, err)
	}
	if items[0].Revision != 0 || items[0].Spec != nil || items[1].Revision != 4 || items[1].ArtifactID != "" {
		t.Fatalf("lenient fields: %+v", items)
	}
	if string(items[0].Field("extra")) != "1" {
		t.Fatalf("raw item lost: %s", items[0].Raw)
	}
	out, _ := items[0].MarshalJSON()
	if !strings.Contains(string(out), `"extra":1`) {
		t.Fatalf("marshal does not keep the raw item: %s", out)
	}
	if _, err := c.SigningKeys(context.Background(), "tok"); err != ErrNotSigning {
		t.Fatalf("404 signing keys: %v", err)
	}
}
