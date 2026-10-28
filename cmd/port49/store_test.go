package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serveStatus serves GET /store/status with code and body on a listener of
// the test's own, and returns its host:port.
func serveStatus(t *testing.T, code int, body string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /store/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func TestStoreStatusExitsByWhatItFound(t *testing.T) {
	ok := "directory  etcd    3/3 members  reachable  cache 0.4s\nsession    shares the directory store\n"
	var out, errb bytes.Buffer
	if code := run([]string{"store", "status", "--metrics", serveStatus(t, 200, ok)}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "3/3 members  reachable") {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errb.String())
	}
	// A store that does not answer: the lines are still printed, exit 3.
	out.Reset()
	if code := run([]string{"store", "status", "--metrics",
		serveStatus(t, 503, "directory  etcd    ?/3 members  unreachable\n           timed out\n")}, &out, &errb); code != 3 ||
		!strings.Contains(out.String(), "unreachable") || !strings.Contains(out.String(), "timed out") {
		t.Fatalf("a store that does not answer exits %d, out %q, want 3", code, out.String())
	}
	// A status already running is not a store that failed: exit 1.
	out.Reset()
	errb.Reset()
	if code := run([]string{"store", "status", "--metrics", serveStatus(t, 429, "busy\n")}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "already running") || out.Len() != 0 {
		t.Fatalf("429 exits %d, out %q, err %q", code, out.String(), errb.String())
	}
	// Nothing listening.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	if code := run([]string{"store", "status", "--metrics", addr}, &out, &errb); code != 1 {
		t.Fatalf("no listener exits %d, want 1", code)
	}
}

// The answer is printed through printsafe: a control sequence in a body from
// an endpoint that is not port49 never reaches the terminal.
func TestStoreStatusPrintsOnlySafeText(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"store", "status", "--metrics", serveStatus(t, 200, "directory  \x1b[31mred\n")}, &out, &errb); code != 0 ||
		strings.Contains(out.String(), "\x1b") {
		t.Fatalf("exit %d, out %q", code, out.String())
	}
}

// A process that accepts and never answers is named, with the wait, and the
// command exits 1.
func TestStoreStatusNamesAProcessThatDoesNotAnswer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	e := storeStatusWait
	t.Cleanup(func() { storeStatusWait = e })
	storeStatusWait = 200 * time.Millisecond
	var out, errb bytes.Buffer
	code := run([]string{"store", "status", "--metrics", l.Addr().String()}, &out, &errb)
	want := "port49 store status: " + l.Addr().String() + " did not answer within 200ms (is the process wedged?)\n"
	if code != 1 || errb.String() != want || out.Len() != 0 {
		t.Fatalf("exit %d, out %q, err %q, want %q", code, out.String(), errb.String(), want)
	}
}

// keys diagnose is gone with the socket and says where it went.
func TestKeysDiagnoseIsRefusedNamingPort49dKeysDiagnose(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"keys", "diagnose", "leaf-19"}, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "port49d keys-diagnose") || out.Len() != 0 {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errb.String())
	}
}
