package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixListener(t *testing.T) {
	for in, want := range map[string]string{"unix:/run/x.sock": "/run/x.sock", "unix:///run/x.sock": "/run/x.sock", ":8000": "", "0.0.0.0:1": ""} {
		if got := unixPath(in); got != want {
			t.Errorf("unixPath(%q) = %q, want %q", in, got, want)
		}
	}
	p := filepath.Join(t.TempDir(), "sub", "api.sock")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, nil, 0o600) // stale file from a crash is replaced
	ln, err := listen("unix:" + p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, err := os.Stat(p); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Setenv("PUBLIC_ADDR", "unix:"+p)
	if healthcheck() != 0 {
		t.Fatal("healthcheck over unix socket failed")
	}
}
