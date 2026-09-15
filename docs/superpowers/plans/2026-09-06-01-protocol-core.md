# Plan 1: TACACS+ Protocol Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `port49d` daemon that speaks RFC 8907 on port 49 to real devices: header validation, MD5-pad obfuscation, all three exchanges, key trial with a version set, admission from a file inventory, per-source listener limits, an in-memory store, an accounting spool, and a JSON-lines decision log — with a containerlab harness that closes lab register entries L1, L2, L5, L6, L8, L10.

**Architecture:** One Go module, one binary for this plan (`cmd/port49d`). The wire layer (`internal/tacacs/wire`) is pure encode/decode with no I/O. Key trial (`internal/keyring`) and admission (`internal/admission`) decide whether a packet is readable and who sent it. Handlers (`internal/daemon/authen`, `author`, `acct`) run one exchange each against a narrow `store.Store` interface whose only implementation here is in-memory. Everything the device sees is produced by `internal/daemon/server`, which owns the listener limits. The decision log (`internal/decision`) is the single emitter for every record.

**Tech Stack:** Go 1.22 is the module's language target (toolchain installed 2026-09-07: 1.27.1 at `/usr/local/go`; the older apt `go1.22.2` at `/usr/bin/go` is shadowed, so confirm `go version` before blaming a build). Standard library only for the wire and handlers; `github.com/prometheus/client_golang` for metrics; `gopkg.in/yaml.v3` for config; `golang.org/x/crypto/ssh` in the lab harness only. containerlab + Docker for the lab (containerlab **0.79.0 on both PCs** as of 2026-09-15; device images **arrived 2026-09-15**, all VM disks built with vrnetlab; see Task 15's prerequisites. Lab tasks are behind the `lab` build tag and are the last tasks).

**Spec:** `docs/design/2026-08-21-port49-design.md` (§5, §8, §11, §12, §14, §15, §16, §19 step 1) and `docs/design/2026-08-23-policy-engine-spec.md` (§5.7, §5.8, §10 "Admission and keys" through "Devices presenting a key that does not validate", §15 lab register). This plan is design §19 **step 1** plus the store-record slice of step 2 that step 1 cannot run without. Later plans: 2 (token model), 3 (vertical slice), 4 (policy engine), 5 (adapters), 6 (inventory), 7 (broker), 8–12.

## Global Constraints

- Go `1.22` module `github.com/rhwendt/port49`; `gofmt` clean; `go vet ./...` clean; no `cgo`.
- **Config keys, YAML keys, JSON log keys, and metric names are `snake_case`.** Never camelCase.
- **Header validation before anything else** (spec §10): version major `0xc`, `type` in `{1,2,3}`, client `seq_no` odd, `length ≤ 4096`. A failing packet is never parsed further and its body is never logged.
- **`TAC_PLUS_UNENCRYPTED_FLAG` (0x01) is refused** without parsing the body; `TAC_PLUS_SINGLE_CONNECT_FLAG` (0x04) is honored.
- **The reply is obfuscated with the key that validated the request**, and the resolved key is cached for the life of the TCP connection.
- **A retired key version may identify a device; it MUST NOT admit one and MUST NOT construct a reply.**
- **An unvalidated body is never logged.** Record cleartext header fields, source, and a SHA-256 of the body.
- **Limits are per source before they are global** (design §11). Every limit is configurable and has a metric.
- **Accounting replies `SUCCESS` after a durable spool hand-off; `ERROR` only when the spool cannot take it.** Never `ERROR` for a malformed or unwelcome record.
- **Device identity never appears in a metric label.** Labels are bounded: `exchange`, `outcome`, `reason`, `diagnosis`, `key_ref`, `version`, `flags`.
- **Reason codes are the closed vocabulary of spec §5.7.** No handler invents one.
- **The log MUST NOT contain a token, a password, a CHAP challenge or response.** Credentials appear only as `credential_sha256`.
- Conventional Commits; branch `feature/protocol-core`; never commit to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

---

## File Structure

```
go.mod                                  module github.com/rhwendt/port49, go 1.22
Makefile                                test, vet, fuzz, lab targets
cmd/port49d/main.go                     flag/config load, wire everything, run
internal/tacacs/wire/header.go          Header struct, Encode/Decode, Validate
internal/tacacs/wire/pad.go             MD5 pad, Obfuscate (symmetric)
internal/tacacs/wire/authen.go          AuthenStart, AuthenReply, AuthenContinue codecs
internal/tacacs/wire/author.go          AuthorRequest, AuthorResponse codecs
internal/tacacs/wire/acct.go            AcctRequest, AcctReply codecs
internal/tacacs/wire/consts.go          every RFC 8907 enum, as typed constants
internal/tacacs/wire/errors.go          typed decode errors
internal/keyring/keyring.go             KeyRef, Version, Set; Resolve by length identity; Diagnosis
internal/admission/admission.go         file inventory + key groups → trie; Lookup(addr) → Device, key_ref
internal/store/store.go                 Store interface, record types, errors
internal/store/memory/memory.go         in-memory implementation with TTL
internal/decision/log.go                Emitter, Record envelope, Reason constants, redaction of credentials
internal/daemon/limits/limits.go        per-NAS connection cap, idle timeout, backoff, failure counters
internal/daemon/metrics/metrics.go      every metric in one place
internal/daemon/authen/authen.go        ASCII/PAP/CHAP against the store's token set
internal/daemon/author/author.go        session + command authorization via an Authorizer interface; lab Authorizer
internal/daemon/acct/acct.go            record parsing, <cr> strip, spool hand-off, account event
internal/daemon/acct/spool.go           bounded spool with disk overflow, drain to sink
internal/daemon/server/conn.go          one TCP connection: key resolution, dispatch, single-connect
internal/daemon/server/server.go        listener, accept shedding, wiring
internal/config/config.go               port49d.yaml schema (snake_case), load, validate
tests/fuzz/                             fuzz corpora
tests/lab/                              containerlab topologies, startup configs, lab tests (//go:build lab)
tests/lab/results/                      L<N>-<platform>.md, written by the lab tests
```

---

### Task 1: Module scaffold

**Files:**
- Create: `go.mod`, `Makefile`, `cmd/port49d/main.go`, `internal/tacacs/wire/doc.go`
- Modify: `.gitignore` (add `/tests/lab/captures/`)

**Interfaces:**
- Produces: the module path `github.com/rhwendt/port49` every later import uses; `make test`, `make vet`, `make fuzz`, `make lab`.

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feature/protocol-core
```

- [ ] **Step 2: Write `go.mod`**

```
module github.com/rhwendt/port49

go 1.22
```

- [ ] **Step 3: Write the Makefile**

```makefile
.PHONY: test vet fuzz lab build

build:
	go build -o bin/port49d ./cmd/port49d

test:
	go test ./... -count=1

vet:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...

# Short fuzz pass for every FuzzXxx in the wire package; CI-sized.
fuzz:
	@for f in $$(go test -list 'Fuzz.*' ./internal/tacacs/wire | grep '^Fuzz'); do \
	  go test ./internal/tacacs/wire -run '^$$' -fuzz "^$$f$$" -fuzztime 20s || exit 1; \
	done

# Requires containerlab and device images; see tests/lab/README.md.
lab:
	go test -tags lab ./tests/lab/... -count=1 -v -timeout 30m
```

- [ ] **Step 4: Write a placeholder main and package doc so the module builds**

`cmd/port49d/main.go`:
```go
// Command port49d is the TACACS+ daemon.
package main

import "fmt"

func main() {
	fmt.Println("port49d: not yet wired")
}
```

`internal/tacacs/wire/doc.go`:
```go
// Package wire encodes and decodes RFC 8907 TACACS+ packets. It performs no I/O.
package wire
```

- [ ] **Step 5: Verify it builds and vets**

Run: `make build && make vet`
Expected: `bin/port49d` exists; no gofmt or vet output.

- [ ] **Step 6: Commit**

```bash
git add go.mod Makefile cmd internal .gitignore
git commit -m "chore: scaffold Go module and Makefile"
```

---

### Task 2: Wire constants and header codec

**Files:**
- Create: `internal/tacacs/wire/consts.go`, `internal/tacacs/wire/errors.go`, `internal/tacacs/wire/header.go`
- Test: `internal/tacacs/wire/header_test.go`

**Interfaces:**
- Produces:
  ```go
  const HeaderLen = 12
  const MaxBodyLen = 4096
  type Type uint8       // TypeAuthen=1, TypeAuthor=2, TypeAcct=3
  type Header struct { MajorVersion, MinorVersion uint8; Type Type; SeqNo uint8; Flags uint8; SessionID uint32; Length uint32 }
  func (h Header) Version() byte                  // the version octet, major<<4 | minor
  func DecodeHeader(b []byte) (Header, error)     // exactly 12 bytes
  func (h Header) Encode() []byte
  func (h Header) Validate() error                // the four spec §10 checks + unencrypted flag
  var ErrShort, ErrBadVersion, ErrBadType, ErrSeqNotOdd, ErrTooLong, ErrUnencrypted error
  ```

- [ ] **Step 1: Write the constants**

`internal/tacacs/wire/consts.go`:
```go
package wire

const (
	HeaderLen  = 12
	MaxBodyLen = 4096 // port49's own ceiling; RFC 8907 sets none (spec §10, L10)

	MajorVersion     = 0xc
	MinorVersionZero = 0x0
	MinorVersionOne  = 0x1

	FlagUnencrypted   = 0x01
	FlagSingleConnect = 0x04
)

type Type uint8

const (
	TypeAuthen Type = 1
	TypeAuthor Type = 2
	TypeAcct   Type = 3
)

// Authentication.
const (
	AuthenActionLogin    = 0x01
	AuthenActionChPass   = 0x02
	AuthenActionSendAuth = 0x04

	AuthenTypeASCII    = 0x01
	AuthenTypePAP      = 0x02
	AuthenTypeCHAP     = 0x03
	AuthenTypeMSCHAP   = 0x05
	AuthenTypeMSCHAPv2 = 0x06

	AuthenServiceNone   = 0x00
	AuthenServiceLogin  = 0x01
	AuthenServiceEnable = 0x02
	AuthenServicePPP    = 0x03

	AuthenStatusPass    = 0x01
	AuthenStatusFail    = 0x02
	AuthenStatusGetData = 0x03
	AuthenStatusGetUser = 0x04
	AuthenStatusGetPass = 0x05
	AuthenStatusRestart = 0x06
	AuthenStatusError   = 0x07
	AuthenStatusFollow  = 0x21

	AuthenReplyFlagNoEcho    = 0x01
	AuthenContinueFlagAbort  = 0x01
)

// Authorization.
const (
	AuthenMethodNotSet     = 0x00
	AuthenMethodNone       = 0x01
	AuthenMethodKRB5       = 0x02
	AuthenMethodLine       = 0x03
	AuthenMethodEnable     = 0x04
	AuthenMethodLocal      = 0x05
	AuthenMethodTACACSPlus = 0x06
	AuthenMethodGuest      = 0x08
	AuthenMethodRADIUS     = 0x10
	AuthenMethodKRB4       = 0x11
	AuthenMethodRCMD       = 0x20

	AuthorStatusPassAdd  = 0x01
	AuthorStatusPassRepl = 0x02
	AuthorStatusFail     = 0x10
	AuthorStatusError    = 0x11
	AuthorStatusFollow   = 0x21
)

// Accounting.
const (
	AcctFlagStart    = 0x02
	AcctFlagStop     = 0x04
	AcctFlagWatchdog = 0x08

	AcctStatusSuccess = 0x01
	AcctStatusError   = 0x02
	AcctStatusFollow  = 0x21
)
```

- [ ] **Step 2: Write the errors**

`internal/tacacs/wire/errors.go`:
```go
package wire

import "errors"

var (
	ErrShort         = errors.New("wire: buffer shorter than declared")
	ErrBadVersion    = errors.New("wire: major version is not 0xc")
	ErrBadType       = errors.New("wire: type not in {authen, author, acct}")
	ErrSeqNotOdd     = errors.New("wire: client seq_no must be odd")
	ErrTooLong       = errors.New("wire: body exceeds 4096-byte ceiling")
	ErrUnencrypted   = errors.New("wire: unencrypted flag set; refused")
	ErrLengthMismatch = errors.New("wire: field lengths do not sum to body length")
	ErrBadEnum       = errors.New("wire: enum value out of range")
	ErrTooManyArgs   = errors.New("wire: arg_cnt exceeds 255")
)
```

- [ ] **Step 3: Write the failing header tests**

`internal/tacacs/wire/header_test.go`:
```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

// A well-formed authentication START header: version c0, type 1, seq 1, flags 0,
// session 0x01020304, length 20.
var goodHeader = []byte{0xc0, 0x01, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x14}

func TestDecodeHeaderRoundTrip(t *testing.T) {
	h, err := DecodeHeader(goodHeader)
	if err != nil {
		t.Fatal(err)
	}
	if h.MajorVersion != 0xc || h.MinorVersion != 0 || h.Type != TypeAuthen ||
		h.SeqNo != 1 || h.Flags != 0 || h.SessionID != 0x01020304 || h.Length != 20 {
		t.Fatalf("decoded %+v", h)
	}
	if !bytes.Equal(h.Encode(), goodHeader) {
		t.Fatalf("encode mismatch: %x", h.Encode())
	}
	if h.Version() != 0xc0 {
		t.Fatalf("version octet %x", h.Version())
	}
}

func TestDecodeHeaderShort(t *testing.T) {
	if _, err := DecodeHeader(goodHeader[:11]); !errors.Is(err, ErrShort) {
		t.Fatalf("want ErrShort, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	mut := func(i int, v byte) []byte { b := append([]byte(nil), goodHeader...); b[i] = v; return b }
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"good", goodHeader, nil},
		{"minor version 1 is fine", mut(0, 0xc1), nil},
		{"bad major", mut(0, 0xb0), ErrBadVersion},
		{"bad type", mut(1, 0x04), ErrBadType},
		{"even seq", mut(2, 0x02), ErrSeqNotOdd},
		{"unencrypted", mut(3, FlagUnencrypted), ErrUnencrypted},
		{"single-connect is honored", mut(3, FlagSingleConnect), nil},
		{"too long", append(goodHeader[:8:8], 0x00, 0x00, 0x10, 0x01), ErrTooLong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := DecodeHeader(c.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.Validate(); !errors.Is(got, c.want) {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}
```

- [ ] **Step 4: Run to verify failure**

Run: `go test ./internal/tacacs/wire -run 'TestDecodeHeader|TestValidate' -v`
Expected: FAIL, `undefined: DecodeHeader`.

- [ ] **Step 5: Implement the header**

`internal/tacacs/wire/header.go`:
```go
package wire

import "encoding/binary"

// Header is the 12-byte cleartext RFC 8907 header.
type Header struct {
	MajorVersion uint8
	MinorVersion uint8
	Type         Type
	SeqNo        uint8
	Flags        uint8
	SessionID    uint32
	Length       uint32
}

// Version returns the version octet as carried on the wire and used in the pad.
func (h Header) Version() byte { return h.MajorVersion<<4 | h.MinorVersion&0x0f }

func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrShort
	}
	return Header{
		MajorVersion: b[0] >> 4,
		MinorVersion: b[0] & 0x0f,
		Type:         Type(b[1]),
		SeqNo:        b[2],
		Flags:        b[3],
		SessionID:    binary.BigEndian.Uint32(b[4:8]),
		Length:       binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

func (h Header) Encode() []byte {
	b := make([]byte, HeaderLen)
	b[0] = h.Version()
	b[1] = byte(h.Type)
	b[2] = h.SeqNo
	b[3] = h.Flags
	binary.BigEndian.PutUint32(b[4:8], h.SessionID)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
	return b
}

// Validate applies the spec §10 header checks to a packet received from a client.
// Order matters: the unencrypted check comes before anything that would read the body.
func (h Header) Validate() error {
	switch {
	case h.MajorVersion != MajorVersion:
		return ErrBadVersion
	case h.Type < TypeAuthen || h.Type > TypeAcct:
		return ErrBadType
	case h.SeqNo%2 == 0:
		return ErrSeqNotOdd
	case h.Flags&FlagUnencrypted != 0:
		return ErrUnencrypted
	case h.Length > MaxBodyLen:
		return ErrTooLong
	}
	return nil
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/tacacs/wire -run 'TestDecodeHeader|TestValidate' -v`
Expected: PASS, all subtests.

- [ ] **Step 7: Commit**

```bash
git add internal/tacacs/wire
git commit -m "feat(wire): RFC 8907 header codec and validation"
```

---

### Task 3: MD5 pad obfuscation

**Files:**
- Create: `internal/tacacs/wire/pad.go`
- Test: `internal/tacacs/wire/pad_test.go`

**Interfaces:**
- Produces:
  ```go
  func Pad(h Header, key []byte, n int) []byte          // n bytes of keystream per RFC 8907 §4.5
  func Obfuscate(h Header, key []byte, body []byte) []byte  // XOR with Pad; symmetric; returns a new slice
  ```

- [ ] **Step 1: Write the failing tests**

`internal/tacacs/wire/pad_test.go`:
```go
package wire

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"testing"
)

func padHeader() Header {
	return Header{MajorVersion: 0xc, MinorVersion: 0, Type: TypeAuthen, SeqNo: 1, SessionID: 0xdeadbeef}
}

// Reference pad computed inline from the RFC text so the implementation is checked
// against the definition, not against itself:
//   MD5_1 = MD5(session_id ‖ key ‖ version ‖ seq_no)
//   MD5_n = MD5(session_id ‖ key ‖ version ‖ seq_no ‖ MD5_{n-1})
func referencePad(h Header, key []byte, n int) []byte {
	var out, prev []byte
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, h.SessionID)
	for len(out) < n {
		m := md5.New()
		m.Write(sid)
		m.Write(key)
		m.Write([]byte{h.Version()})
		m.Write([]byte{h.SeqNo})
		m.Write(prev)
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func TestPadMatchesReference(t *testing.T) {
	h := padHeader()
	key := []byte("s3cret")
	for _, n := range []int{0, 1, 15, 16, 17, 33, 100} {
		if got, want := Pad(h, key, n), referencePad(h, key, n); !bytes.Equal(got, want) {
			t.Fatalf("n=%d: got %x want %x", n, got, want)
		}
	}
}

func TestObfuscateIsSymmetric(t *testing.T) {
	h := padHeader()
	key := []byte("s3cret")
	body := []byte("the quick brown fox jumps over the lazy dog")
	enc := Obfuscate(h, key, body)
	if bytes.Equal(enc, body) {
		t.Fatal("obfuscation changed nothing")
	}
	if got := Obfuscate(h, key, enc); !bytes.Equal(got, body) {
		t.Fatalf("round trip: %q", got)
	}
	if &enc[0] == &body[0] {
		t.Fatal("Obfuscate must not alias its input")
	}
}

func TestObfuscateDependsOnSeqNo(t *testing.T) {
	h := padHeader()
	body := []byte("same body")
	h2 := h
	h2.SeqNo = 3
	if bytes.Equal(Obfuscate(h, []byte("k"), body), Obfuscate(h2, []byte("k"), body)) {
		t.Fatal("pad must vary with seq_no")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tacacs/wire -run 'TestPad|TestObfuscate' -v`
Expected: FAIL, `undefined: Pad`.

- [ ] **Step 3: Implement**

`internal/tacacs/wire/pad.go`:
```go
package wire

import (
	"crypto/md5"
	"encoding/binary"
)

// Pad returns n bytes of RFC 8907 §4.5 keystream for the header and key.
func Pad(h Header, key []byte, n int) []byte {
	out := make([]byte, 0, n+md5.Size)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], h.SessionID)
	var prev []byte
	for len(out) < n {
		m := md5.New()
		m.Write(sid[:])
		m.Write(key)
		m.Write([]byte{h.Version(), h.SeqNo})
		m.Write(prev)
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// Obfuscate XORs body with the pad. The operation is its own inverse. It never
// modifies its input.
func Obfuscate(h Header, key []byte, body []byte) []byte {
	pad := Pad(h, key, len(body))
	out := make([]byte, len(body))
	for i := range body {
		out[i] = body[i] ^ pad[i]
	}
	return out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tacacs/wire -run 'TestPad|TestObfuscate' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tacacs/wire/pad.go internal/tacacs/wire/pad_test.go
git commit -m "feat(wire): MD5 pad obfuscation"
```

---

### Task 4: Authentication body codecs

**Files:**
- Create: `internal/tacacs/wire/authen.go`
- Test: `internal/tacacs/wire/authen_test.go`

**Interfaces:**
- Produces:
  ```go
  type AuthenStart struct { Action, PrivLvl, AuthenType, Service uint8; User, Port, RemAddr, Data []byte }
  type AuthenReply struct { Status, Flags uint8; ServerMsg, Data []byte }
  type AuthenContinue struct { Flags uint8; UserMsg, Data []byte }
  func DecodeAuthenStart(b []byte) (AuthenStart, error)     // enforces the length identity and enum ranges
  func (p AuthenStart) Encode() []byte
  func DecodeAuthenReply(b []byte) (AuthenReply, error)
  func (p AuthenReply) Encode() []byte
  func DecodeAuthenContinue(b []byte) (AuthenContinue, error)
  func (p AuthenContinue) Encode() []byte
  ```
- The length identity `8 + user_len + port_len + rem_addr_len + data_len == len(body)` is what key trial (Task 6) relies on to tell a right key from a wrong one; **it MUST be strict**, no trailing bytes tolerated.

- [ ] **Step 1: Write the failing tests**

`internal/tacacs/wire/authen_test.go`:
```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthenStartRoundTrip(t *testing.T) {
	in := AuthenStart{
		Action: AuthenActionLogin, PrivLvl: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_token"),
	}
	b := in.Encode()
	if len(b) != 8+5+4+12+9 {
		t.Fatalf("encoded length %d", len(b))
	}
	out, err := DecodeAuthenStart(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.User, in.User) || !bytes.Equal(out.Data, in.Data) || out.AuthenType != AuthenTypePAP {
		t.Fatalf("decoded %+v", out)
	}
}

func TestAuthenStartLengthIdentityIsStrict(t *testing.T) {
	b := AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin, User: []byte("a")}.Encode()
	if _, err := DecodeAuthenStart(append(b, 0x00)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing byte: want ErrLengthMismatch, got %v", err)
	}
	if _, err := DecodeAuthenStart(b[:len(b)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("truncated: want ErrShort, got %v", err)
	}
	if _, err := DecodeAuthenStart(b[:5]); !errors.Is(err, ErrShort) {
		t.Fatalf("no fixed part: want ErrShort, got %v", err)
	}
}

func TestAuthenStartEnumRanges(t *testing.T) {
	good := AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin}.Encode()
	bad := append([]byte(nil), good...)
	bad[0] = 0x09 // action
	if _, err := DecodeAuthenStart(bad); !errors.Is(err, ErrBadEnum) {
		t.Fatalf("action: %v", err)
	}
	bad = append([]byte(nil), good...)
	bad[2] = 0x00 // authen_type 0 is not defined
	if _, err := DecodeAuthenStart(bad); !errors.Is(err, ErrBadEnum) {
		t.Fatalf("authen_type: %v", err)
	}
	bad = append([]byte(nil), good...)
	bad[1] = 16 // priv_lvl 0..15
	if _, err := DecodeAuthenStart(bad); !errors.Is(err, ErrBadEnum) {
		t.Fatalf("priv_lvl: %v", err)
	}
}

func TestAuthenReplyRoundTrip(t *testing.T) {
	in := AuthenReply{Status: AuthenStatusGetPass, Flags: AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}
	out, err := DecodeAuthenReply(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != AuthenStatusGetPass || out.Flags != AuthenReplyFlagNoEcho || string(out.ServerMsg) != "Password: " || len(out.Data) != 0 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestAuthenContinueRoundTrip(t *testing.T) {
	in := AuthenContinue{UserMsg: []byte("p49_token")}
	out, err := DecodeAuthenContinue(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if string(out.UserMsg) != "p49_token" || out.Flags != 0 {
		t.Fatalf("decoded %+v", out)
	}
	if _, err := DecodeAuthenContinue(append(in.Encode(), 1)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tacacs/wire -run 'TestAuthen' -v`
Expected: FAIL, `undefined: AuthenStart`.

- [ ] **Step 3: Implement**

`internal/tacacs/wire/authen.go`:
```go
package wire

import "encoding/binary"

type AuthenStart struct {
	Action, PrivLvl, AuthenType, Service uint8
	User, Port, RemAddr, Data           []byte
}

type AuthenReply struct {
	Status, Flags   uint8
	ServerMsg, Data []byte
}

type AuthenContinue struct {
	Flags         uint8
	UserMsg, Data []byte
}

func validAuthenAction(a uint8) bool {
	return a == AuthenActionLogin || a == AuthenActionChPass || a == AuthenActionSendAuth
}

func validAuthenType(t uint8) bool {
	switch t {
	case AuthenTypeASCII, AuthenTypePAP, AuthenTypeCHAP, AuthenTypeMSCHAP, AuthenTypeMSCHAPv2:
		return true
	}
	return false
}

func DecodeAuthenStart(b []byte) (AuthenStart, error) {
	if len(b) < 8 {
		return AuthenStart{}, ErrShort
	}
	p := AuthenStart{Action: b[0], PrivLvl: b[1], AuthenType: b[2], Service: b[3]}
	ul, pl, rl, dl := int(b[4]), int(b[5]), int(b[6]), int(b[7])
	want := 8 + ul + pl + rl + dl
	if len(b) < want {
		return AuthenStart{}, ErrShort
	}
	if len(b) != want {
		return AuthenStart{}, ErrLengthMismatch
	}
	if !validAuthenAction(p.Action) || !validAuthenType(p.AuthenType) || p.PrivLvl > 15 || p.Service > 0x09 {
		return AuthenStart{}, ErrBadEnum
	}
	off := 8
	p.User = cut(b, &off, ul)
	p.Port = cut(b, &off, pl)
	p.RemAddr = cut(b, &off, rl)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AuthenStart) Encode() []byte {
	b := make([]byte, 8, 8+len(p.User)+len(p.Port)+len(p.RemAddr)+len(p.Data))
	b[0], b[1], b[2], b[3] = p.Action, p.PrivLvl, p.AuthenType, p.Service
	b[4], b[5], b[6], b[7] = byte(len(p.User)), byte(len(p.Port)), byte(len(p.RemAddr)), byte(len(p.Data))
	b = append(b, p.User...)
	b = append(b, p.Port...)
	b = append(b, p.RemAddr...)
	b = append(b, p.Data...)
	return b
}

func DecodeAuthenReply(b []byte) (AuthenReply, error) {
	if len(b) < 6 {
		return AuthenReply{}, ErrShort
	}
	p := AuthenReply{Status: b[0], Flags: b[1]}
	sl, dl := int(binary.BigEndian.Uint16(b[2:4])), int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 6+sl+dl {
		return AuthenReply{}, ErrShort
	}
	if len(b) != 6+sl+dl {
		return AuthenReply{}, ErrLengthMismatch
	}
	off := 6
	p.ServerMsg = cut(b, &off, sl)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AuthenReply) Encode() []byte {
	b := make([]byte, 6, 6+len(p.ServerMsg)+len(p.Data))
	b[0], b[1] = p.Status, p.Flags
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.ServerMsg)))
	binary.BigEndian.PutUint16(b[4:6], uint16(len(p.Data)))
	b = append(b, p.ServerMsg...)
	b = append(b, p.Data...)
	return b
}

func DecodeAuthenContinue(b []byte) (AuthenContinue, error) {
	if len(b) < 5 {
		return AuthenContinue{}, ErrShort
	}
	ul, dl := int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4]))
	p := AuthenContinue{Flags: b[4]}
	if len(b) < 5+ul+dl {
		return AuthenContinue{}, ErrShort
	}
	if len(b) != 5+ul+dl {
		return AuthenContinue{}, ErrLengthMismatch
	}
	off := 5
	p.UserMsg = cut(b, &off, ul)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AuthenContinue) Encode() []byte {
	b := make([]byte, 5, 5+len(p.UserMsg)+len(p.Data))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(p.UserMsg)))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.Data)))
	b[4] = p.Flags
	b = append(b, p.UserMsg...)
	b = append(b, p.Data...)
	return b
}

// cut returns a copy of the next n bytes and advances off. Callers have already
// checked the total length, so this cannot run past the buffer.
func cut(b []byte, off *int, n int) []byte {
	out := append([]byte(nil), b[*off:*off+n]...)
	*off += n
	return out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tacacs/wire -run 'TestAuthen' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tacacs/wire/authen.go internal/tacacs/wire/authen_test.go
git commit -m "feat(wire): authentication START/REPLY/CONTINUE codecs"
```

---

### Task 5: Authorization and accounting body codecs, plus fuzz targets

**Files:**
- Create: `internal/tacacs/wire/author.go`, `internal/tacacs/wire/acct.go`, `internal/tacacs/wire/fuzz_test.go`
- Test: `internal/tacacs/wire/author_test.go`, `internal/tacacs/wire/acct_test.go`

**Interfaces:**
- Produces:
  ```go
  type AuthorRequest struct { AuthenMethod, PrivLvl, AuthenType, Service uint8; User, Port, RemAddr []byte; Args [][]byte }
  type AuthorResponse struct { Status uint8; ServerMsg, Data []byte; Args [][]byte }
  type AcctRequest struct { Flags, AuthenMethod, PrivLvl, AuthenType, Service uint8; User, Port, RemAddr []byte; Args [][]byte }
  type AcctReply struct { Status uint8; ServerMsg, Data []byte }
  func DecodeAuthorRequest([]byte) (AuthorRequest, error); func (AuthorRequest) Encode() []byte
  func DecodeAuthorResponse([]byte) (AuthorResponse, error); func (AuthorResponse) Encode() []byte
  func DecodeAcctRequest([]byte) (AcctRequest, error); func (AcctRequest) Encode() []byte
  func DecodeAcctReply([]byte) (AcctReply, error); func (AcctReply) Encode() []byte
  ```
- Args are kept as raw byte strings (`service=shell`, `cmd=show`). Splitting on `=`/`*` is the handlers' job (Tasks 11–12).

- [ ] **Step 1: Write the failing authorization tests**

`internal/tacacs/wire/author_test.go`:
```go
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthorRequestRoundTrip(t *testing.T) {
	in := AuthorRequest{
		AuthenMethod: AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version")},
	}
	b := in.Encode()
	// 8 fixed + 3 arg_len octets + 5 + 4 + 12 + (13 + 8 + 15)
	if len(b) != 8+3+5+4+12+13+8+15 {
		t.Fatalf("encoded length %d", len(b))
	}
	out, err := DecodeAuthorRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Args) != 3 || !bytes.Equal(out.Args[2], []byte("cmd-arg=version")) || out.PrivLvl != 15 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestAuthorRequestLengthIdentity(t *testing.T) {
	b := AuthorRequest{AuthenMethod: AuthenMethodTACACSPlus, AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin,
		Args: [][]byte{[]byte("service=shell")}}.Encode()
	if _, err := DecodeAuthorRequest(append(b, 0)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing: %v", err)
	}
	if _, err := DecodeAuthorRequest(b[:len(b)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("truncated: %v", err)
	}
	// arg_cnt claims 2 args but only one arg_len octet is present.
	bad := append([]byte(nil), b...)
	bad[7] = 2
	if _, err := DecodeAuthorRequest(bad); !errors.Is(err, ErrShort) && !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("arg_cnt lie: %v", err)
	}
}

func TestAuthorResponseRoundTrip(t *testing.T) {
	in := AuthorResponse{Status: AuthorStatusFail, ServerMsg: []byte("port49: denied by no-exfil"),
		Args: [][]byte{[]byte("priv-lvl=15")}}
	out, err := DecodeAuthorResponse(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != AuthorStatusFail || string(out.ServerMsg) != "port49: denied by no-exfil" || len(out.Args) != 1 {
		t.Fatalf("decoded %+v", out)
	}
}
```

- [ ] **Step 2: Write the failing accounting tests**

`internal/tacacs/wire/acct_test.go`:
```go
package wire

import (
	"errors"
	"testing"
)

func TestAcctRequestRoundTrip(t *testing.T) {
	in := AcctRequest{Flags: AcctFlagStop, AuthenMethod: AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"),
		Args: [][]byte{[]byte("task_id=43"), []byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=running-config"), []byte("cmd-arg=<cr>")}}
	out, err := DecodeAcctRequest(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.Flags != AcctFlagStop || len(out.Args) != 5 || string(out.Args[4]) != "cmd-arg=<cr>" {
		t.Fatalf("decoded %+v", out)
	}
	if _, err := DecodeAcctRequest(append(in.Encode(), 0)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing: %v", err)
	}
}

func TestAcctReplyRoundTrip(t *testing.T) {
	in := AcctReply{Status: AcctStatusSuccess}
	b := in.Encode()
	if len(b) != 5 {
		t.Fatalf("encoded %x", b)
	}
	out, err := DecodeAcctReply(b)
	if err != nil || out.Status != AcctStatusSuccess {
		t.Fatalf("decoded %+v err %v", out, err)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/tacacs/wire -run 'TestAuthor|TestAcct' -v`
Expected: FAIL, `undefined: AuthorRequest`.

- [ ] **Step 4: Implement authorization**

`internal/tacacs/wire/author.go`:
```go
package wire

import "encoding/binary"

type AuthorRequest struct {
	AuthenMethod, PrivLvl, AuthenType, Service uint8
	User, Port, RemAddr                       []byte
	Args                                      [][]byte
}

type AuthorResponse struct {
	Status          uint8
	ServerMsg, Data []byte
	Args            [][]byte
}

// decodeArgs reads cnt one-octet lengths starting at *off, then the args
// themselves starting at argsOff. It is shared by author and acct requests.
func argsTotal(lens []byte) int {
	n := 0
	for _, l := range lens {
		n += int(l)
	}
	return n
}

func DecodeAuthorRequest(b []byte) (AuthorRequest, error) {
	if len(b) < 8 {
		return AuthorRequest{}, ErrShort
	}
	p := AuthorRequest{AuthenMethod: b[0], PrivLvl: b[1], AuthenType: b[2], Service: b[3]}
	ul, pl, rl, cnt := int(b[4]), int(b[5]), int(b[6]), int(b[7])
	if len(b) < 8+cnt {
		return AuthorRequest{}, ErrShort
	}
	lens := b[8 : 8+cnt]
	want := 8 + cnt + ul + pl + rl + argsTotal(lens)
	if len(b) < want {
		return AuthorRequest{}, ErrShort
	}
	if len(b) != want {
		return AuthorRequest{}, ErrLengthMismatch
	}
	if p.PrivLvl > 15 || (p.AuthenType != 0 && !validAuthenType(p.AuthenType)) {
		return AuthorRequest{}, ErrBadEnum
	}
	off := 8 + cnt
	p.User = cut(b, &off, ul)
	p.Port = cut(b, &off, pl)
	p.RemAddr = cut(b, &off, rl)
	p.Args = make([][]byte, cnt)
	for i, l := range lens {
		p.Args[i] = cut(b, &off, int(l))
	}
	return p, nil
}

func (p AuthorRequest) Encode() []byte {
	b := []byte{p.AuthenMethod, p.PrivLvl, p.AuthenType, p.Service,
		byte(len(p.User)), byte(len(p.Port)), byte(len(p.RemAddr)), byte(len(p.Args))}
	for _, a := range p.Args {
		b = append(b, byte(len(a)))
	}
	b = append(b, p.User...)
	b = append(b, p.Port...)
	b = append(b, p.RemAddr...)
	for _, a := range p.Args {
		b = append(b, a...)
	}
	return b
}

func DecodeAuthorResponse(b []byte) (AuthorResponse, error) {
	if len(b) < 6 {
		return AuthorResponse{}, ErrShort
	}
	p := AuthorResponse{Status: b[0]}
	cnt := int(b[1])
	sl, dl := int(binary.BigEndian.Uint16(b[2:4])), int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 6+cnt {
		return AuthorResponse{}, ErrShort
	}
	lens := b[6 : 6+cnt]
	want := 6 + cnt + sl + dl + argsTotal(lens)
	if len(b) < want {
		return AuthorResponse{}, ErrShort
	}
	if len(b) != want {
		return AuthorResponse{}, ErrLengthMismatch
	}
	off := 6 + cnt
	p.ServerMsg = cut(b, &off, sl)
	p.Data = cut(b, &off, dl)
	p.Args = make([][]byte, cnt)
	for i, l := range lens {
		p.Args[i] = cut(b, &off, int(l))
	}
	return p, nil
}

func (p AuthorResponse) Encode() []byte {
	b := make([]byte, 6)
	b[0], b[1] = p.Status, byte(len(p.Args))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.ServerMsg)))
	binary.BigEndian.PutUint16(b[4:6], uint16(len(p.Data)))
	for _, a := range p.Args {
		b = append(b, byte(len(a)))
	}
	b = append(b, p.ServerMsg...)
	b = append(b, p.Data...)
	for _, a := range p.Args {
		b = append(b, a...)
	}
	return b
}
```

- [ ] **Step 5: Implement accounting**

`internal/tacacs/wire/acct.go`:
```go
package wire

import "encoding/binary"

type AcctRequest struct {
	Flags, AuthenMethod, PrivLvl, AuthenType, Service uint8
	User, Port, RemAddr                              []byte
	Args                                             [][]byte
}

type AcctReply struct {
	Status          uint8
	ServerMsg, Data []byte
}

func DecodeAcctRequest(b []byte) (AcctRequest, error) {
	if len(b) < 9 {
		return AcctRequest{}, ErrShort
	}
	p := AcctRequest{Flags: b[0], AuthenMethod: b[1], PrivLvl: b[2], AuthenType: b[3], Service: b[4]}
	ul, pl, rl, cnt := int(b[5]), int(b[6]), int(b[7]), int(b[8])
	if len(b) < 9+cnt {
		return AcctRequest{}, ErrShort
	}
	lens := b[9 : 9+cnt]
	want := 9 + cnt + ul + pl + rl + argsTotal(lens)
	if len(b) < want {
		return AcctRequest{}, ErrShort
	}
	if len(b) != want {
		return AcctRequest{}, ErrLengthMismatch
	}
	if p.PrivLvl > 15 || p.Flags&^(AcctFlagStart|AcctFlagStop|AcctFlagWatchdog) != 0 {
		return AcctRequest{}, ErrBadEnum
	}
	off := 9 + cnt
	p.User = cut(b, &off, ul)
	p.Port = cut(b, &off, pl)
	p.RemAddr = cut(b, &off, rl)
	p.Args = make([][]byte, cnt)
	for i, l := range lens {
		p.Args[i] = cut(b, &off, int(l))
	}
	return p, nil
}

func (p AcctRequest) Encode() []byte {
	b := []byte{p.Flags, p.AuthenMethod, p.PrivLvl, p.AuthenType, p.Service,
		byte(len(p.User)), byte(len(p.Port)), byte(len(p.RemAddr)), byte(len(p.Args))}
	for _, a := range p.Args {
		b = append(b, byte(len(a)))
	}
	b = append(b, p.User...)
	b = append(b, p.Port...)
	b = append(b, p.RemAddr...)
	for _, a := range p.Args {
		b = append(b, a...)
	}
	return b
}

func DecodeAcctReply(b []byte) (AcctReply, error) {
	if len(b) < 5 {
		return AcctReply{}, ErrShort
	}
	sl, dl := int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4]))
	p := AcctReply{Status: b[4]}
	if len(b) < 5+sl+dl {
		return AcctReply{}, ErrShort
	}
	if len(b) != 5+sl+dl {
		return AcctReply{}, ErrLengthMismatch
	}
	off := 5
	p.ServerMsg = cut(b, &off, sl)
	p.Data = cut(b, &off, dl)
	return p, nil
}

func (p AcctReply) Encode() []byte {
	b := make([]byte, 5, 5+len(p.ServerMsg)+len(p.Data))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(p.ServerMsg)))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(p.Data)))
	b[4] = p.Status
	b = append(b, p.ServerMsg...)
	b = append(b, p.Data...)
	return b
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/tacacs/wire -v`
Expected: PASS, every test in the package.

- [ ] **Step 7: Add fuzz targets**

`internal/tacacs/wire/fuzz_test.go`:
```go
package wire

import "testing"

// Every decoder must reject or accept without panicking, and anything it accepts
// must re-encode to the identical bytes (the codecs are canonical).

func FuzzDecodeHeader(f *testing.F) {
	f.Add(goodHeader)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHeader(b)
		if err != nil {
			return
		}
		_ = h.Validate()
		if got := h.Encode(); string(got) != string(b[:HeaderLen]) {
			t.Fatalf("not canonical: %x vs %x", got, b[:HeaderLen])
		}
	})
}

func FuzzDecodeAuthenStart(f *testing.F) {
	f.Add(AuthenStart{Action: 1, AuthenType: 2, Service: 1, User: []byte("u"), Data: []byte("d")}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodeAuthenStart(b)
		if err != nil {
			return
		}
		if string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzDecodeAuthenContinue(f *testing.F) {
	f.Add(AuthenContinue{UserMsg: []byte("x")}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DecodeAuthenContinue(b); err == nil && string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzDecodeAuthorRequest(f *testing.F) {
	f.Add(AuthorRequest{AuthenMethod: 6, AuthenType: 1, Service: 1, Args: [][]byte{[]byte("service=shell")}}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DecodeAuthorRequest(b); err == nil && string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzDecodeAcctRequest(f *testing.F) {
	f.Add(AcctRequest{Flags: AcctFlagStart, AuthenMethod: 6, AuthenType: 1, Service: 1, Args: [][]byte{[]byte("task_id=1")}}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DecodeAcctRequest(b); err == nil && string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzObfuscate(f *testing.F) {
	f.Add([]byte("k"), []byte("body"), uint32(7), uint8(1))
	f.Fuzz(func(t *testing.T, key, body []byte, sid uint32, seq uint8) {
		h := Header{MajorVersion: 0xc, Type: TypeAuthen, SeqNo: seq, SessionID: sid}
		if got := Obfuscate(h, key, Obfuscate(h, key, body)); string(got) != string(body) {
			t.Fatalf("not symmetric")
		}
	})
}
```

- [ ] **Step 8: Run the fuzz targets briefly**

Run: `make fuzz`
Expected: each target runs 20s and reports no failures. If a crasher is found, `testdata/fuzz/` holds it; fix the decoder and re-run before committing.

- [ ] **Step 9: Commit**

```bash
git add internal/tacacs/wire
git commit -m "feat(wire): authorization and accounting codecs with fuzz targets"
```

---

### Task 6: Keyring — versions, length-identity trial, and diagnosis

**Files:**
- Create: `internal/keyring/keyring.go`
- Test: `internal/keyring/keyring_test.go`

**Interfaces:**
- Consumes: `wire.Header`, `wire.Obfuscate`, the four `wire.Decode*Request` functions.
- Produces:
  ```go
  type Version struct { Number int; Secret []byte; Retired bool }   // Retired: diagnosis only
  type Set struct { Ref string; Versions []Version }                // ordered: current first, then accept, then retired
  type Diagnosis string
  const (
      DiagValidated        Diagnosis = "validated"
      DiagMatchesRetired   Diagnosis = "matches_retired"
      DiagNoKnownKey       Diagnosis = "no_known_key_matches"
      DiagUnencrypted      Diagnosis = "unencrypted_refused"
      DiagNotTACACS        Diagnosis = "not_tacacs"
  )
  type Result struct { Diagnosis Diagnosis; Version int; Body []byte }  // Body is the de-obfuscated body when validated
  func (s Set) Resolve(h wire.Header, obfuscated []byte) Result
  func Validates(h wire.Header, body []byte) bool   // the length identity + enum ranges, per packet type
  ```
- The connection layer (Task 13) caches `Result.Version` per TCP connection and re-obfuscates replies with that version's secret. It never uses a `Retired` version for a reply, and `Resolve` never returns `DiagValidated` for one.

- [ ] **Step 1: Write the failing tests**

`internal/keyring/keyring_test.go`:
```go
package keyring

import (
	"testing"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

func start(t *testing.T) (wire.Header, []byte) {
	t.Helper()
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("tok")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 0x11223344, Length: uint32(len(body))}
	return h, body
}

func set() Set {
	return Set{Ref: "prod_key", Versions: []Version{
		{Number: 3, Secret: []byte("v3-secret")},
		{Number: 2, Secret: []byte("v2-secret")},
		{Number: 1, Secret: []byte("v1-secret"), Retired: true},
	}}
}

func TestResolveCurrentAndAccepted(t *testing.T) {
	h, body := start(t)
	for _, v := range []struct {
		secret []byte
		want   int
	}{{[]byte("v3-secret"), 3}, {[]byte("v2-secret"), 2}} {
		r := set().Resolve(h, wire.Obfuscate(h, v.secret, body))
		if r.Diagnosis != DiagValidated || r.Version != v.want || string(r.Body) != string(body) {
			t.Fatalf("secret %s: %+v", v.secret, r)
		}
	}
}

func TestResolveRetiredIdentifiesButNeverAdmits(t *testing.T) {
	h, body := start(t)
	r := set().Resolve(h, wire.Obfuscate(h, []byte("v1-secret"), body))
	if r.Diagnosis != DiagMatchesRetired || r.Version != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Body != nil {
		t.Fatal("a retired match must not hand the body to anyone")
	}
}

func TestResolveUnknownKey(t *testing.T) {
	h, body := start(t)
	r := set().Resolve(h, wire.Obfuscate(h, []byte("nope"), body))
	if r.Diagnosis != DiagNoKnownKey || r.Body != nil {
		t.Fatalf("%+v", r)
	}
}

func TestResolveNeverParsesUnencrypted(t *testing.T) {
	h, body := start(t)
	h.Flags = wire.FlagUnencrypted
	if r := set().Resolve(h, body); r.Diagnosis != DiagUnencrypted || r.Body != nil {
		t.Fatalf("%+v", r)
	}
}

func TestResolveNotTACACS(t *testing.T) {
	h, body := start(t)
	h.MajorVersion = 0x4
	if r := set().Resolve(h, body); r.Diagnosis != DiagNotTACACS {
		t.Fatalf("%+v", r)
	}
}

func TestValidatesEveryType(t *testing.T) {
	h, body := start(t)
	if !Validates(h, body) {
		t.Fatal("authen start")
	}
	ab := wire.AuthorRequest{AuthenMethod: 6, AuthenType: 1, Service: 1, Args: [][]byte{[]byte("service=shell")}}.Encode()
	if !Validates(wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthor, SeqNo: 1, Length: uint32(len(ab))}, ab) {
		t.Fatal("author")
	}
	cb := wire.AcctRequest{Flags: wire.AcctFlagStart, AuthenMethod: 6, AuthenType: 1, Service: 1}.Encode()
	if !Validates(wire.Header{MajorVersion: 0xc, Type: wire.TypeAcct, SeqNo: 1, Length: uint32(len(cb))}, cb) {
		t.Fatal("acct")
	}
	// seq_no 3 on an authentication session is a CONTINUE, whose identity differs.
	cont := wire.AuthenContinue{UserMsg: []byte("tok")}.Encode()
	if !Validates(wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 3, Length: uint32(len(cont))}, cont) {
		t.Fatal("continue")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/keyring -v`
Expected: FAIL, package does not exist.

- [ ] **Step 3: Implement**

`internal/keyring/keyring.go`:
```go
// Package keyring resolves which shared-key version, if any, obfuscated a packet.
// RFC 8907 carries no key identifier, so the daemon tries candidates and accepts
// the one under which the body is self-consistent (spec §10).
package keyring

import (
	"errors"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Version struct {
	Number  int
	Secret  []byte
	Retired bool // kept for diagnosis; never admits, never builds a reply
}

// Set is one key_ref's versions, ordered current, accepted..., retired...
type Set struct {
	Ref      string
	Versions []Version
}

type Diagnosis string

const (
	DiagValidated      Diagnosis = "validated"
	DiagMatchesRetired Diagnosis = "matches_retired"
	DiagNoKnownKey     Diagnosis = "no_known_key_matches"
	DiagUnencrypted    Diagnosis = "unencrypted_refused"
	DiagNotTACACS      Diagnosis = "not_tacacs"
)

type Result struct {
	Diagnosis Diagnosis
	Version   int
	Body      []byte // de-obfuscated; nil unless Diagnosis == DiagValidated
}

// Resolve tries every version in order and returns the first that validates.
// Header validation happens first so an unencrypted or non-TACACS packet never
// costs a pad computation or reaches a decoder.
func (s Set) Resolve(h wire.Header, obfuscated []byte) Result {
	if err := h.Validate(); err != nil {
		if errors.Is(err, wire.ErrUnencrypted) {
			return Result{Diagnosis: DiagUnencrypted}
		}
		return Result{Diagnosis: DiagNotTACACS}
	}
	for _, v := range s.Versions {
		body := wire.Obfuscate(h, v.Secret, obfuscated)
		if !Validates(h, body) {
			continue
		}
		if v.Retired {
			return Result{Diagnosis: DiagMatchesRetired, Version: v.Number}
		}
		return Result{Diagnosis: DiagValidated, Version: v.Number, Body: body}
	}
	return Result{Diagnosis: DiagNoKnownKey}
}

// Secret returns the secret for a version number, or nil if it is absent or retired.
func (s Set) Secret(version int) []byte {
	for _, v := range s.Versions {
		if v.Number == version && !v.Retired {
			return v.Secret
		}
	}
	return nil
}

// Validates reports whether body is self-consistent for the packet type the
// header announces. Every decoder enforces its length identity strictly, so a
// wrong key's pseudorandom bytes fail here with overwhelming probability.
func Validates(h wire.Header, body []byte) bool {
	var err error
	switch h.Type {
	case wire.TypeAuthen:
		if h.SeqNo == 1 {
			_, err = wire.DecodeAuthenStart(body)
		} else {
			_, err = wire.DecodeAuthenContinue(body)
		}
	case wire.TypeAuthor:
		_, err = wire.DecodeAuthorRequest(body)
	case wire.TypeAcct:
		_, err = wire.DecodeAcctRequest(body)
	default:
		return false
	}
	return err == nil
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/keyring -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/keyring
git commit -m "feat(keyring): key version trial by length identity, retired versions diagnose only"
```

---

### Task 7: Admission — file inventory and key groups

**Files:**
- Create: `internal/admission/admission.go`
- Test: `internal/admission/admission_test.go`
- Create: `internal/admission/testdata/inventory.yaml`

**Interfaces:**
- Produces:
  ```go
  type Device struct { Name, Platform string; Addresses []netip.Addr; Attributes map[string]string; KeyRef string /* pinned, optional */ }
  type KeyGroup struct { CIDR netip.Prefix /* zero if attribute group */; Attributes map[string]string; KeyRef string }
  type Inventory struct { Devices []Device; KeyGroups []KeyGroup }
  type Resolved struct { Device Device; KeyRef string }
  type Trie struct { /* opaque */ }
  func Build(inv Inventory) (*Trie, error)          // errors: address collision (names both devices), same-tier overlap (names both groups)
  func (t *Trie) Lookup(a netip.Addr) (Resolved, bool)
  func LoadFile(path string) (Inventory, error)     // YAML, snake_case keys
  ```
- Tier order (spec §10): 1 device-pinned `key_ref`; 2 attribute match; 3 longest CIDR prefix. Two matches in one tier at build time is an error naming both.

- [ ] **Step 1: Write the test fixture**

`internal/admission/testdata/inventory.yaml`:
```yaml
devices:
  - name: leaf-01
    platform: arista_eos
    addresses: [10.20.0.7, 10.20.255.7]
    attributes: {site: dc1, role: leaf}
  - name: lab-sw-1
    platform: arista_eos
    addresses: [10.99.0.5]
    attributes: {env: lab}
  - name: pinned-1
    platform: generic
    addresses: [10.20.0.9]
    key_ref: special_key

key_groups:
  - {match: {cidr: 10.0.0.0/8},        key_ref: prod_key}
  - {match: {cidr: 10.99.0.0/16},      key_ref: lab_cidr_key}
  - {match: {attributes: {env: lab}},  key_ref: lab_key}
```

- [ ] **Step 2: Write the failing tests**

`internal/admission/admission_test.go`:
```go
package admission

import (
	"net/netip"
	"strings"
	"testing"
)

func load(t *testing.T) *Trie {
	t.Helper()
	inv, err := LoadFile("testdata/inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestLookupTiers(t *testing.T) {
	tr := load(t)
	cases := []struct{ addr, device, keyRef string }{
		{"10.20.0.7", "leaf-01", "prod_key"},       // tier 3, longest prefix is /8
		{"10.20.255.7", "leaf-01", "prod_key"},     // second address, same device
		{"10.99.0.5", "lab-sw-1", "lab_key"},       // tier 2 attribute beats the /16 CIDR
		{"10.20.0.9", "pinned-1", "special_key"},   // tier 1 pin beats everything
	}
	for _, c := range cases {
		r, ok := tr.Lookup(netip.MustParseAddr(c.addr))
		if !ok || r.Device.Name != c.device || r.KeyRef != c.keyRef {
			t.Fatalf("%s: ok=%v %+v", c.addr, ok, r)
		}
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("unknown address admitted")
	}
}

func TestBuildRefusesAddressCollision(t *testing.T) {
	inv := Inventory{Devices: []Device{
		{Name: "a", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{Name: "b", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
	}}
	_, err := Build(inv)
	if err == nil || !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), "b") {
		t.Fatalf("want error naming both devices, got %v", err)
	}
}

func TestBuildRefusesSameTierOverlap(t *testing.T) {
	inv := Inventory{
		Devices: []Device{{Name: "d", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Attributes: map[string]string{"env": "lab", "site": "x"}}},
		KeyGroups: []KeyGroup{
			{Attributes: map[string]string{"env": "lab"}, KeyRef: "k1"},
			{Attributes: map[string]string{"site": "x"}, KeyRef: "k2"},
		},
	}
	_, err := Build(inv)
	if err == nil || !strings.Contains(err.Error(), "k1") || !strings.Contains(err.Error(), "k2") {
		t.Fatalf("want error naming both groups, got %v", err)
	}
}

func TestDeviceMatchingNoGroupIsNotAdmitted(t *testing.T) {
	inv := Inventory{Devices: []Device{{Name: "d", Addresses: []netip.Addr{netip.MustParseAddr("172.16.0.1")}}},
		KeyGroups: []KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "k"}}}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("172.16.0.1")); ok {
		t.Fatal("device with no key group must be refused")
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/admission -v`
Expected: FAIL, package does not exist.

- [ ] **Step 4: Add the YAML dependency**

Run: `go get gopkg.in/yaml.v3@v3.0.1`

- [ ] **Step 5: Implement**

`internal/admission/admission.go`:
```go
// Package admission answers "which device is this address, and which key_ref
// admits it" from a file inventory and reviewed key groups (spec §10).
package admission

import (
	"fmt"
	"net/netip"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type Device struct {
	Name       string
	Platform   string
	Addresses  []netip.Addr
	Attributes map[string]string
	KeyRef     string // tier 1 pin; empty when not pinned
}

type KeyGroup struct {
	CIDR       netip.Prefix // zero value when this is an attribute group
	Attributes map[string]string
	KeyRef     string
}

type Inventory struct {
	Devices   []Device
	KeyGroups []KeyGroup
}

type Resolved struct {
	Device Device
	KeyRef string
}

// Trie is a map from address to resolved device; the key_ref is decided at build
// time so Lookup is a single map read on the hot path.
type Trie struct {
	byAddr map[netip.Addr]Resolved
}

func Build(inv Inventory) (*Trie, error) {
	t := &Trie{byAddr: make(map[netip.Addr]Resolved)}
	owner := make(map[netip.Addr]string)
	for _, d := range inv.Devices {
		keyRef, err := resolveKeyRef(d, inv.KeyGroups)
		if err != nil {
			return nil, err
		}
		for _, a := range d.Addresses {
			if prev, dup := owner[a]; dup {
				return nil, fmt.Errorf("admission: address %s claimed by both %q and %q", a, prev, d.Name)
			}
			owner[a] = d.Name
			if keyRef == "" {
				continue // in inventory, but no group admits it: refused (spec §10)
			}
			t.byAddr[a] = Resolved{Device: d, KeyRef: keyRef}
		}
	}
	return t, nil
}

func (t *Trie) Lookup(a netip.Addr) (Resolved, bool) {
	r, ok := t.byAddr[a]
	return r, ok
}

func resolveKeyRef(d Device, groups []KeyGroup) (string, error) {
	if d.KeyRef != "" {
		return d.KeyRef, nil // tier 1
	}
	var attrHits []KeyGroup
	for _, g := range groups {
		if len(g.Attributes) > 0 && attrsMatch(d.Attributes, g.Attributes) {
			attrHits = append(attrHits, g)
		}
	}
	if len(attrHits) > 1 {
		return "", fmt.Errorf("admission: device %q matches key groups %q and %q in the attribute tier", d.Name, attrHits[0].KeyRef, attrHits[1].KeyRef)
	}
	if len(attrHits) == 1 {
		return attrHits[0].KeyRef, nil // tier 2
	}
	// Tier 3: longest prefix across all the device's addresses must agree.
	best := ""
	bestBits := -1
	for _, a := range d.Addresses {
		var hits []KeyGroup
		for _, g := range groups {
			if g.CIDR.IsValid() && g.CIDR.Contains(a) {
				hits = append(hits, g)
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].CIDR.Bits() > hits[j].CIDR.Bits() })
		if len(hits) == 0 {
			continue
		}
		if len(hits) > 1 && hits[0].CIDR.Bits() == hits[1].CIDR.Bits() {
			return "", fmt.Errorf("admission: device %q address %s matches key groups %q and %q at equal prefix length", d.Name, a, hits[0].KeyRef, hits[1].KeyRef)
		}
		if hits[0].CIDR.Bits() > bestBits {
			best, bestBits = hits[0].KeyRef, hits[0].CIDR.Bits()
		}
	}
	return best, nil
}

func attrsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// File schema (snake_case).
type fileInventory struct {
	Devices []struct {
		Name       string            `yaml:"name"`
		Platform   string            `yaml:"platform"`
		Addresses  []string          `yaml:"addresses"`
		Attributes map[string]string `yaml:"attributes"`
		KeyRef     string            `yaml:"key_ref"`
	} `yaml:"devices"`
	KeyGroups []struct {
		Match struct {
			CIDR       string            `yaml:"cidr"`
			Attributes map[string]string `yaml:"attributes"`
		} `yaml:"match"`
		KeyRef string `yaml:"key_ref"`
	} `yaml:"key_groups"`
}

func LoadFile(path string) (Inventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, err
	}
	var f fileInventory
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Inventory{}, fmt.Errorf("admission: %s: %w", path, err)
	}
	var inv Inventory
	for _, d := range f.Devices {
		dev := Device{Name: d.Name, Platform: d.Platform, Attributes: d.Attributes, KeyRef: d.KeyRef}
		for _, s := range d.Addresses {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: device %q: %w", d.Name, err)
			}
			dev.Addresses = append(dev.Addresses, a)
		}
		inv.Devices = append(inv.Devices, dev)
	}
	for _, g := range f.KeyGroups {
		kg := KeyGroup{Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		if g.Match.CIDR != "" {
			p, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: key group %q: %w", g.KeyRef, err)
			}
			kg.CIDR = p
		}
		if kg.KeyRef == "" {
			return Inventory{}, fmt.Errorf("admission: key group without key_ref")
		}
		inv.KeyGroups = append(inv.KeyGroups, kg)
	}
	return inv, nil
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/admission -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/admission
git commit -m "feat(admission): file inventory, key groups, deterministic tier resolution"
```

---

### Task 8: Store interface and the in-memory implementation

**Files:**
- Create: `internal/store/store.go`, `internal/store/memory/memory.go`
- Test: `internal/store/memory/memory_test.go`

**Interfaces:**
- Produces:
  ```go
  package store
  type TokenKey struct { NAS string; Username string }            // NAS is the device name from admission
  type Token struct { Secret []byte; Kind string /* login|enable */; Reusable bool; ExpiresAt time.Time }
  type Receipt struct { CredentialSHA256 [32]byte; Status uint8; CtxID string; ExpiresAt time.Time }
  type ReceiptKey struct { NAS, Port, Username string }
  type Context struct { CtxID, Principal, Username, RemAddr string; PrivLvl uint8; CreatedAt time.Time }
  type ContextKey struct { NAS, Port string }
  var ErrNotFound = errors.New("store: not found")
  type Store interface {
      PutToken(ctx context.Context, k TokenKey, t Token) (count int, err error)   // returns the set size after the write
      Candidates(ctx context.Context, k TokenKey) ([]Token, error)               // unexpired members
      // RedeemAndReceipt removes the token whose Secret equals secret from the set and writes the receipt,
      // atomically. Returns ErrNotFound if it was already removed (the race loser).
      RedeemAndReceipt(ctx context.Context, k TokenKey, secret []byte, rk ReceiptKey, r Receipt) error
      GetReceipt(ctx context.Context, rk ReceiptKey) (Receipt, error)
      PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
      GetContext(ctx context.Context, k ContextKey) (Context, error)
      DeleteContext(ctx context.Context, k ContextKey) error
  }
  ```
- Plan 2 adds encryption at rest, `blob`, the indexes, and idempotency records to this interface. Nothing here is thrown away; the in-memory store is the test double for every later plan.
- Expiry is the store's job (design §8): an expired token is absent from `Candidates`.

- [ ] **Step 1: Write the interface**

`internal/store/store.go`:
```go
// Package store is the narrow interface every shared record passes through
// (design §12). Implementations are pluggable; memory is the reference.
package store

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("store: not found")

type TokenKey struct {
	NAS      string // device name from admission
	Username string // canonical form
}

type Token struct {
	Secret    []byte
	Kind      string // "login" | "enable"
	Reusable  bool
	ExpiresAt time.Time
}

type ReceiptKey struct{ NAS, Port, Username string }

type Receipt struct {
	CredentialSHA256 [32]byte
	Status           uint8 // the authentication REPLY status that was sent
	CtxID            string
	ExpiresAt        time.Time
}

type ContextKey struct{ NAS, Port string }

type Context struct {
	CtxID     string
	Principal string
	Username  string
	RemAddr   string
	PrivLvl   uint8
	CreatedAt time.Time
}

type Store interface {
	PutToken(ctx context.Context, k TokenKey, t Token) (count int, err error)
	Candidates(ctx context.Context, k TokenKey) ([]Token, error)
	RedeemAndReceipt(ctx context.Context, k TokenKey, secret []byte, rk ReceiptKey, r Receipt) error
	GetReceipt(ctx context.Context, rk ReceiptKey) (Receipt, error)
	PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
	GetContext(ctx context.Context, k ContextKey) (Context, error)
	DeleteContext(ctx context.Context, k ContextKey) error
}
```

- [ ] **Step 2: Write the failing tests**

`internal/store/memory/memory_test.go`:
```go
package memory

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

func TestTokenLifecycle(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}

	n, err := s.PutToken(ctx, k, store.Token{Secret: []byte("t1"), Kind: "login", ExpiresAt: now.Add(time.Minute)})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	n, _ = s.PutToken(ctx, k, store.Token{Secret: []byte("t2"), Kind: "login", ExpiresAt: now.Add(time.Second)})
	if n != 2 {
		t.Fatalf("second put count %d", n)
	}
	c, _ := s.Candidates(ctx, k)
	if len(c) != 2 {
		t.Fatalf("candidates %d", len(c))
	}

	now = now.Add(2 * time.Second) // t2 expires
	c, _ = s.Candidates(ctx, k)
	if len(c) != 1 || !bytes.Equal(c[0].Secret, []byte("t1")) {
		t.Fatalf("after expiry %+v", c)
	}

	rk := store.ReceiptKey{NAS: "leaf-01", Port: "vty0", Username: "alice"}
	r := store.Receipt{Status: 1, CtxID: "01J", ExpiresAt: now.Add(30 * time.Second)}
	if err := s.RedeemAndReceipt(ctx, k, []byte("t1"), rk, r); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemAndReceipt(ctx, k, []byte("t1"), rk, r); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second redeem must lose: %v", err)
	}
	got, err := s.GetReceipt(ctx, rk)
	if err != nil || got.CtxID != "01J" {
		t.Fatalf("receipt %+v %v", got, err)
	}
	if c, _ := s.Candidates(ctx, k); len(c) != 0 {
		t.Fatal("token still present after redemption")
	}
}

func TestRedeemIsAtomicUnderRace(t *testing.T) {
	s := New(time.Now)
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{Secret: []byte("x"), ExpiresAt: time.Now().Add(time.Minute)})
	rk := store.ReceiptKey{NAS: "n", Port: "p", Username: "u"}
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.RedeemAndReceipt(ctx, k, []byte("x"), rk, store.Receipt{ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one redeemer must win, got %d", wins)
	}
}

func TestContextTTL(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Port: "vty0"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if c, err := s.GetContext(ctx, k); err != nil || c.CtxID != "c1" {
		t.Fatalf("%+v %v", c, err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired context still readable: %v", err)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/store/... -v`
Expected: FAIL, `memory` package does not exist.

- [ ] **Step 4: Implement**

`internal/store/memory/memory.go`:
```go
// Package memory is the in-process store.Store. It exists so the daemon can be
// integration-tested as a single binary (design §12) and as the lab store.
package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

type Store struct {
	now      func() time.Time
	mu       sync.Mutex
	tokens   map[store.TokenKey][]store.Token
	receipts map[store.ReceiptKey]store.Receipt
	contexts map[store.ContextKey]ctxEntry
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
}

func New(now func() time.Time) *Store {
	return &Store{
		now:      now,
		tokens:   make(map[store.TokenKey][]store.Token),
		receipts: make(map[store.ReceiptKey]store.Receipt),
		contexts: make(map[store.ContextKey]ctxEntry),
	}
}

func (s *Store) live(k store.TokenKey) []store.Token {
	now := s.now()
	out := s.tokens[k][:0]
	for _, t := range s.tokens[k] {
		if t.ExpiresAt.After(now) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		delete(s.tokens, k)
	} else {
		s.tokens[k] = out
	}
	return out
}

func (s *Store) PutToken(_ context.Context, k store.TokenKey, t store.Token) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live(k)
	s.tokens[k] = append(s.tokens[k], t)
	return len(s.tokens[k]), nil
}

func (s *Store) Candidates(_ context.Context, k store.TokenKey) ([]store.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Token(nil), s.live(k)...), nil
}

func (s *Store) RedeemAndReceipt(_ context.Context, k store.TokenKey, secret []byte, rk store.ReceiptKey, r store.Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.live(k)
	for i, t := range set {
		if bytes.Equal(t.Secret, secret) {
			if !t.Reusable {
				s.tokens[k] = append(set[:i:i], set[i+1:]...)
				if len(s.tokens[k]) == 0 {
					delete(s.tokens, k)
				}
			}
			s.receipts[rk] = r
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *Store) GetReceipt(_ context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.receipts[rk]
	if !ok || !r.ExpiresAt.After(s.now()) {
		delete(s.receipts, rk)
		return store.Receipt{}, store.ErrNotFound
	}
	return r, nil
}

func (s *Store) PutContext(_ context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[k] = ctxEntry{c: c, exp: s.now().Add(ttl)}
	return nil
}

func (s *Store) GetContext(_ context.Context, k store.ContextKey) (store.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.Context{}, store.ErrNotFound
	}
	return e.c, nil
}

func (s *Store) DeleteContext(_ context.Context, k store.ContextKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, k)
	return nil
}

var _ store.Store = (*Store)(nil)
```

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/store/... -race -v`
Expected: PASS, including the race test under `-race`.

- [ ] **Step 6: Commit**

```bash
git add internal/store
git commit -m "feat(store): narrow store interface and in-memory implementation"
```

---

### Task 9: Decision log emitter and reason vocabulary

**Files:**
- Create: `internal/decision/log.go`, `internal/decision/reasons.go`
- Test: `internal/decision/log_test.go`

**Interfaces:**
- Produces:
  ```go
  type Reason string   // constants below; the closed vocabulary of spec §5.7
  type Record struct {
      TS time.Time `json:"ts"`; Event string `json:"event"`; Verdict string `json:"verdict,omitempty"`; Reason Reason `json:"reason,omitempty"`
      Principal string `json:"principal,omitempty"`
      Auth *Auth `json:"auth,omitempty"`; Device *Device `json:"device,omitempty"`; Session *Session `json:"session,omitempty"`
      Request *Request `json:"request,omitempty"`
      Flags string `json:"flags,omitempty"`; Attribution string `json:"attribution,omitempty"`; TaskID string `json:"task_id,omitempty"`
      AcctRecord *AcctRecord `json:"record,omitempty"`
      Unvalidated *Unvalidated `json:"unvalidated,omitempty"`
  }
  type Auth struct { Method string `json:"method"`; CredentialSHA256 string `json:"credential_sha256"` }
  type Device struct { NAS string `json:"nas"`; Name string `json:"name"`; Platform string `json:"platform"` }
  type Session struct { CtxID string `json:"ctx_id"`; Port string `json:"port"`; RemAddr string `json:"rem_addr"`; Privilege uint8 `json:"privilege"` }
  type Request struct { Raw []string `json:"raw"`; Vector []string `json:"vector"` }
  type AcctRecord struct { Raw []string `json:"raw"`; Vector []string `json:"vector"`; PrivLvl uint8 `json:"priv_lvl"`; StartTime, StopTime, ElapsedTime int64 (omitempty) }
  type Unvalidated struct { Source, Diagnosis, KeyRef string; Version int; Type, SeqNo uint8; SessionID uint32; Length uint32; BodySHA256 string }
  type Emitter interface { Emit(Record) }
  func NewJSONLines(w io.Writer) Emitter       // one JSON object per line, never sampled
  func CredentialHash(presented []byte) string // hex sha256
  ```

- [ ] **Step 1: Write the reason constants**

`internal/decision/reasons.go`:
```go
package decision

// Reason is the closed vocabulary of spec §5.7. Handlers use these constants
// and nothing else; the log and the metrics share them.
type Reason string

const (
	// mint (broker; plan 7) — listed so the vocabulary is complete in one place.
	GrantsMatched         Reason = "grants_matched"
	NoGrantsMatched       Reason = "no_grants_matched"
	UsernameCollision     Reason = "username_collision"
	TrustDomainUnresolved Reason = "trust_domain_unresolved"

	// redeem
	TokenRedeemed      Reason = "token_redeemed"
	TokenNotFound      Reason = "token_not_found"
	DeviceMismatch     Reason = "device_mismatch"
	CredentialMismatch Reason = "credential_mismatch"
	ReceiptReplayed    Reason = "receipt_replayed"
	TokenKindMismatch  Reason = "token_kind_mismatch"

	// authorize_session / authorize_command / escalate
	ContextMatched         Reason = "context_matched"
	EscalationGranted      Reason = "escalation_granted"
	PermitDominates        Reason = "permit_dominates"
	PipeStageDenied        Reason = "pipe_stage_denied"
	ServiceUnsupported     Reason = "service_unsupported"
	EnableRefused          Reason = "enable_refused"
	CeilingExceeded        Reason = "ceiling_exceeded"
	NoRuleMatched          Reason = "no_rule_matched"
	NoPermitDominatesDeny  Reason = "no_permit_dominates_deny"
	ContextMissing         Reason = "context_missing"
	UsernameMismatch       Reason = "username_mismatch"
	RemAddrMismatch        Reason = "rem_addr_mismatch"
	PrivilegeExceeded      Reason = "privilege_exceeded"
	SessionExpired         Reason = "session_expired"
	ContextStale           Reason = "context_stale"
	CredentialRevoked      Reason = "credential_revoked"
	DeviceUnknown          Reason = "device_unknown"
	PlatformUnknown        Reason = "platform_unknown"
	BlobUnavailable        Reason = "blob_unavailable"
	DeviceQuarantined      Reason = "device_quarantined"
)

// Events.
const (
	EventMint             = "mint"
	EventRedeem           = "redeem"
	EventAuthorizeSession = "authorize_session"
	EventAuthorizeCommand = "authorize_command"
	EventEscalate         = "escalate"
	EventBlob             = "blob"
	EventAccount          = "account"
	EventUnvalidated      = "unvalidated" // not a decision; header-only diagnosis record (spec §10)
)

const (
	VerdictPermit = "permit"
	VerdictDeny   = "deny"
)
```

- [ ] **Step 2: Write the failing tests**

`internal/decision/log_test.go`:
```go
package decision

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEmitWritesOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLines(&buf)
	ts := time.Date(2026, 9, 4, 2, 11, 7, 412_000_000, time.UTC)
	e.Emit(Record{TS: ts, Event: EventRedeem, Verdict: VerdictPermit, Reason: TokenRedeemed,
		Principal: "user:alice@example.com",
		Auth:      &Auth{Method: "pap", CredentialSHA256: CredentialHash([]byte("tok"))},
		Device:    &Device{NAS: "10.20.0.7", Name: "leaf-01", Platform: "arista_eos"},
		Session:   &Session{CtxID: "01J", Port: "vty0", RemAddr: "198.51.100.4", Privilege: 1}})
	e.Emit(Record{TS: ts, Event: EventAccount, Flags: "stop", Attribution: "unattributed"})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	if m["ts"] != "2026-09-04T02:11:07.412Z" || m["event"] != "redeem" || m["reason"] != "token_redeemed" {
		t.Fatalf("%v", m)
	}
	if strings.Contains(lines[0], "tok\"") {
		t.Fatal("credential leaked into the log")
	}
	if _, ok := m["policy"]; ok {
		t.Fatal("empty policy block must be omitted")
	}
	for k := range m {
		if strings.ToLower(k) != k || strings.Contains(k, "-") {
			t.Fatalf("key %q is not snake_case", k)
		}
	}
}

func TestCredentialHashIsHexSHA256(t *testing.T) {
	h := CredentialHash([]byte("abc"))
	if h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("%s", h)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/decision -v`
Expected: FAIL, `undefined: NewJSONLines`.

- [ ] **Step 4: Implement**

`internal/decision/log.go`:
```go
// Package decision is the single emitter for port49's own record stream:
// decisions, accounting, blobs, and header-only diagnosis records (spec §5.7).
package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Record struct {
	TS          time.Time    `json:"ts"`
	Event       string       `json:"event"`
	Verdict     string       `json:"verdict,omitempty"`
	Reason      Reason       `json:"reason,omitempty"`
	Principal   string       `json:"principal,omitempty"`
	Auth        *Auth        `json:"auth,omitempty"`
	Device      *Device      `json:"device,omitempty"`
	Session     *Session     `json:"session,omitempty"`
	Request     *Request     `json:"request,omitempty"`
	Flags       string       `json:"flags,omitempty"`
	Attribution string       `json:"attribution,omitempty"`
	TaskID      string       `json:"task_id,omitempty"`
	AcctRecord  *AcctRecord  `json:"record,omitempty"`
	Unvalidated *Unvalidated `json:"unvalidated,omitempty"`
	ServerMsg   string       `json:"server_msg,omitempty"`
}

type Auth struct {
	Method           string `json:"method"`
	CredentialSHA256 string `json:"credential_sha256"`
}

type Device struct {
	NAS      string `json:"nas"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

type Session struct {
	CtxID     string `json:"ctx_id"`
	Port      string `json:"port"`
	RemAddr   string `json:"rem_addr"`
	Privilege uint8  `json:"privilege"`
}

type Request struct {
	Raw    []string `json:"raw"`
	Vector []string `json:"vector"`
}

type AcctRecord struct {
	Raw         []string `json:"raw"`
	Vector      []string `json:"vector"`
	PrivLvl     uint8    `json:"priv_lvl"`
	StartTime   int64    `json:"start_time,omitempty"`
	StopTime    int64    `json:"stop_time,omitempty"`
	ElapsedTime int64    `json:"elapsed_time,omitempty"`
}

// Unvalidated is what is recorded for a packet no key validated: cleartext header
// fields, the source, and a hash of the body — never the body.
type Unvalidated struct {
	Source     string `json:"source"`
	Diagnosis  string `json:"diagnosis"`
	KeyRef     string `json:"key_ref,omitempty"`
	Version    int    `json:"version,omitempty"`
	Type       uint8  `json:"type"`
	SeqNo      uint8  `json:"seq_no"`
	SessionID  uint32 `json:"session_id"`
	Length     uint32 `json:"length"`
	BodySHA256 string `json:"body_sha256"`
}

type Emitter interface {
	Emit(Record)
}

type jsonLines struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLines(w io.Writer) Emitter { return &jsonLines{w: w} }

func (j *jsonLines) Emit(r Record) {
	r.TS = r.TS.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return // a record that cannot marshal is a programming error; never block the wire
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.w.Write(append(b, '\n'))
}

// CredentialHash identifies a presented credential in the log without revealing it.
func CredentialHash(presented []byte) string {
	sum := sha256.Sum256(presented)
	return hex.EncodeToString(sum[:])
}

// MarshalJSON renders ts with millisecond precision in UTC, matching the spec examples.
func (r Record) MarshalJSON() ([]byte, error) {
	type alias Record
	return json.Marshal(struct {
		TS string `json:"ts"`
		alias
	}{TS: r.TS.Format("2006-01-02T15:04:05.000Z07:00"), alias: alias(r)})
}
```

Note: the embedded `alias` also carries a `TS` field tagged `ts`; Go's encoding/json gives the outer field precedence, so exactly one `ts` is emitted. The test asserts the format.

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/decision -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/decision
git commit -m "feat(decision): JSON-lines emitter and the closed reason vocabulary"
```

---

### Task 10: Metrics and per-source limits

**Files:**
- Create: `internal/daemon/metrics/metrics.go`, `internal/daemon/limits/limits.go`
- Test: `internal/daemon/limits/limits_test.go`

**Interfaces:**
- Produces (metrics; every label bounded, no device identity):
  ```go
  type Metrics struct {
      Requests      *prometheus.CounterVec   // port49_requests_total{exchange, outcome}
      Latency       *prometheus.HistogramVec // port49_request_seconds{exchange}
      Decisions     *prometheus.CounterVec   // port49_decisions_total{event, verdict, reason}
      Unvalidated   *prometheus.CounterVec   // port49_unvalidated_packets_total{diagnosis}
      KeyValidations*prometheus.CounterVec   // port49_key_validations_total{key_ref, version, outcome}
      Connections   *prometheus.GaugeVec     // port49_connections{state="open"|"refused_cap"|"idle_closed"}
      AuthFailures  prometheus.Counter       // port49_authentication_failures_total
      SpoolDepth    prometheus.Gauge         // port49_accounting_spool_depth
      SpoolDrops    prometheus.Counter       // port49_accounting_spool_drops_total
      StoreOps      *prometheus.CounterVec   // port49_store_operations_total{op, outcome}
  }
  func New(reg prometheus.Registerer) *Metrics
  ```
- Produces (limits):
  ```go
  type Config struct { PerNASConnections int; IdleTimeout time.Duration; MalformedBackoffBase, MalformedBackoffMax time.Duration; AuthFailureDelayBase, AuthFailureDelayMax time.Duration; AuthFailureWindow time.Duration }
  type Limiter struct { /* opaque */ }
  func New(c Config, now func() time.Time) *Limiter
  func (l *Limiter) Acquire(src netip.Addr) (release func(), ok bool)   // per-NAS connection cap
  func (l *Limiter) Malformed(src netip.Addr) time.Duration           // records a strike; returns the delay before the close
  func (l *Limiter) AuthFailure(nas, username string) time.Duration   // records; returns the delay before replying FAIL; never locks
  ```

- [ ] **Step 1: Add the Prometheus dependency**

Run: `go get github.com/prometheus/client_golang@v1.19.1`

- [ ] **Step 2: Write metrics**

`internal/daemon/metrics/metrics.go`:
```go
// Package metrics defines every daemon metric in one place (design §15). Labels
// are bounded by construction; device identity never appears here.
package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Requests       *prometheus.CounterVec
	Latency        *prometheus.HistogramVec
	Decisions      *prometheus.CounterVec
	Unvalidated    *prometheus.CounterVec
	KeyValidations *prometheus.CounterVec
	Connections    *prometheus.GaugeVec
	AuthFailures   prometheus.Counter
	SpoolDepth     prometheus.Gauge
	SpoolDrops     prometheus.Counter
	StoreOps       *prometheus.CounterVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_requests_total",
			Help: "TACACS+ exchanges handled, by exchange type and outcome."}, []string{"exchange", "outcome"}),
		Latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "port49_request_seconds",
			Help: "Exchange handling latency.", Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1}}, []string{"exchange"}),
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_decisions_total",
			Help: "Decision records by event, verdict, and reason (same vocabulary as the log)."}, []string{"event", "verdict", "reason"}),
		Unvalidated: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_unvalidated_packets_total",
			Help: "Packets no accepted key validated, by diagnosis."}, []string{"diagnosis"}),
		KeyValidations: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_key_validations_total",
			Help: "Key trial outcomes by key_ref and version."}, []string{"key_ref", "version", "outcome"}),
		Connections: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_connections",
			Help: "Connections by state."}, []string{"state"}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_authentication_failures_total",
			Help: "Authentication failures from admitted devices."}),
		SpoolDepth: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_accounting_spool_depth",
			Help: "Accounting records waiting for the sink."}),
		SpoolDrops: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_accounting_spool_drops_total",
			Help: "Accounting records discarded by the spool."}),
		StoreOps: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_store_operations_total",
			Help: "Store operations by op and outcome."}, []string{"op", "outcome"}),
	}
	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
		m.Connections, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.StoreOps)
	return m
}
```

- [ ] **Step 3: Write the failing limiter tests**

`internal/daemon/limits/limits_test.go`:
```go
package limits

import (
	"net/netip"
	"testing"
	"time"
)

func cfg() Config {
	return Config{PerNASConnections: 2, IdleTimeout: time.Second,
		MalformedBackoffBase: 100 * time.Millisecond, MalformedBackoffMax: time.Second,
		AuthFailureDelayBase: 200 * time.Millisecond, AuthFailureDelayMax: 2 * time.Second, AuthFailureWindow: time.Minute}
}

func TestPerNASCapIsPerSource(t *testing.T) {
	l := New(cfg(), time.Now)
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	r1, ok1 := l.Acquire(a)
	r2, ok2 := l.Acquire(a)
	_, ok3 := l.Acquire(a)
	_, okB := l.Acquire(b)
	if !ok1 || !ok2 || ok3 || !okB {
		t.Fatalf("cap: %v %v %v other=%v", ok1, ok2, ok3, okB)
	}
	r1()
	if _, ok := l.Acquire(a); !ok {
		t.Fatal("release must free a slot")
	}
	r2()
}

func TestMalformedBackoffGrowsAndCaps(t *testing.T) {
	l := New(cfg(), time.Now)
	a := netip.MustParseAddr("10.0.0.1")
	d1, d2, d3 := l.Malformed(a), l.Malformed(a), l.Malformed(a)
	if !(d1 < d2 && d2 < d3) {
		t.Fatalf("not growing: %v %v %v", d1, d2, d3)
	}
	var last time.Duration
	for i := 0; i < 20; i++ {
		last = l.Malformed(a)
	}
	if last != time.Second {
		t.Fatalf("cap: %v", last)
	}
}

func TestAuthFailureDelaysButNeverLocks(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	d1 := l.AuthFailure("leaf-01", "alice")
	var last time.Duration
	for i := 0; i < 100; i++ {
		last = l.AuthFailure("leaf-01", "alice")
	}
	if d1 >= last || last != 2*time.Second {
		t.Fatalf("delays: first %v last %v", d1, last)
	}
	// Past the window the counter resets; nothing is ever "locked".
	now = now.Add(2 * time.Minute)
	if d := l.AuthFailure("leaf-01", "alice"); d != d1 {
		t.Fatalf("window reset: %v vs %v", d, d1)
	}
}
```

- [ ] **Step 4: Run to verify failure**

Run: `go test ./internal/daemon/limits -v`
Expected: FAIL, package does not exist.

- [ ] **Step 5: Implement**

`internal/daemon/limits/limits.go`:
```go
// Package limits implements the per-source listener limits of design §11.
// Limits are per source before they are global, so one device cannot deny
// service to the fleet. Nothing here ever locks an account.
package limits

import (
	"net/netip"
	"sync"
	"time"
)

type Config struct {
	PerNASConnections    int
	IdleTimeout          time.Duration
	MalformedBackoffBase time.Duration
	MalformedBackoffMax  time.Duration
	AuthFailureDelayBase time.Duration
	AuthFailureDelayMax  time.Duration
	AuthFailureWindow    time.Duration
}

type failure struct {
	count int
	last  time.Time
}

type Limiter struct {
	cfg  Config
	now  func() time.Time
	mu   sync.Mutex
	open map[netip.Addr]int
	bad  map[netip.Addr]int
	auth map[string]failure // key: nas + "\x00" + username
}

func New(c Config, now func() time.Time) *Limiter {
	return &Limiter{cfg: c, now: now, open: map[netip.Addr]int{}, bad: map[netip.Addr]int{}, auth: map[string]failure{}}
}

// Acquire takes a connection slot for src. ok is false when the per-NAS cap is
// reached; the caller refuses only that connection.
func (l *Limiter) Acquire(src netip.Addr) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[src] >= l.cfg.PerNASConnections {
		return nil, false
	}
	l.open[src]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.open[src]--
			if l.open[src] == 0 {
				delete(l.open, src)
			}
			l.mu.Unlock()
		})
	}, true
}

// Malformed records a malformed packet from src and returns how long to hold
// the connection before closing it: base * 2^(strikes-1), capped.
func (l *Limiter) Malformed(src netip.Addr) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bad[src]++
	return backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, l.bad[src])
}

// AuthFailure records a failed authentication for (nas, username) and returns
// the delay to apply before the FAIL reply. Counts reset after the window.
func (l *Limiter) AuthFailure(nas, username string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := nas + "\x00" + username
	f := l.auth[k]
	if l.now().Sub(f.last) > l.cfg.AuthFailureWindow {
		f.count = 0
	}
	f.count++
	f.last = l.now()
	l.auth[k] = f
	return backoff(l.cfg.AuthFailureDelayBase, l.cfg.AuthFailureDelayMax, f.count)
}

func backoff(base, max time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/daemon/... -v && go vet ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/daemon
git commit -m "feat(daemon): metrics set and per-source limits"
```

---

### Task 11: Authentication handler — ASCII, PAP, CHAP against the store

**Files:**
- Create: `internal/daemon/authen/authen.go`, `internal/daemon/authen/username.go`
- Test: `internal/daemon/authen/authen_test.go`

**Interfaces:**
- Consumes: `store.Store`, `decision.Emitter`, `limits.Limiter`, `metrics.Metrics`, `wire.*`.
- Produces:
  ```go
  type Peer struct { NAS string /* device name */; NASAddr string; Platform string }
  type Handler struct { /* opaque */ }
  func New(s store.Store, e decision.Emitter, l *limits.Limiter, m *metrics.Metrics, now func() time.Time, newCtxID func() string, receiptTTL, contextTTL time.Duration) *Handler
  // Session is one authentication session (one session_id). Feed it packets; it returns the reply body
  // to send. done is true when the session is finished (PASS/FAIL/ERROR sent).
  type Session struct { /* opaque */ }
  func (h *Handler) NewSession(peer Peer) *Session
  func (s *Session) Start(ctx context.Context, p wire.AuthenStart) (reply wire.AuthenReply, done bool)
  func (s *Session) Continue(ctx context.Context, p wire.AuthenContinue) (reply wire.AuthenReply, done bool)
  func Canonical(username string) string   // lower-case, strip DOMAIN\ prefix and @suffix (spec §2)
  ```
- Behaviour (design §8, spec §5.6, §5.7):
  - ASCII: START without user → `GETUSER`; then `GETPASS` (NOECHO); CONTINUE with the password is the presented credential. ABORT flag → done, no record.
  - PAP: `Data` is the presented credential.
  - CHAP: `Data = ppp_id ‖ challenge ‖ response(16)`; for each candidate compute `MD5(ppp_id ‖ secret ‖ challenge)`; the presented credential for the receipt hash is `Data` itself.
  - Receipt first: if a receipt exists for `(nas, port, username)` and `CredentialHash(presented)` matches → replay its status, reason `receipt_replayed`, same `ctx_id`, **no store redemption**. Receipt exists but hash differs → FAIL `credential_mismatch`.
  - Otherwise fetch candidates under `(nas, Canonical(user))`, filter `Kind == "login"` for `authen_service` login and `"enable"` for enable, verify, `RedeemAndReceipt`; on `ErrNotFound` from the race, re-read the receipt and replay it (design §12: the loser answers PASS from the receipt). Create context `(nas, port)`.
  - Enable service (`$enab15$` user) is **plan 2**; here an enable START returns FAIL `token_kind_mismatch` unless a matching `Kind: "enable"` token exists under the wire username, which keeps the lab able to test the exchange.
  - No candidate matches → FAIL `token_not_found` after `Limiter.AuthFailure` delay. (The device tag and `device_mismatch` are plan 2.)
  - Every outcome emits one `redeem` record with `auth.credential_sha256`, never the credential.

- [ ] **Step 1: Write the username canonicalization and its test first**

`internal/daemon/authen/username.go`:
```go
package authen

import "strings"

// Canonical is the form the broker writes tokens under and the daemon looks
// them up by: lower-cased, with a DOMAIN\ prefix or an @suffix removed (spec §2).
func Canonical(username string) string {
	u := strings.ToLower(strings.TrimSpace(username))
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[:i]
	}
	return u
}
```

- [ ] **Step 2: Write the failing tests**

`internal/daemon/authen/authen_test.go`:
```go
package authen

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type fixture struct {
	h     *Handler
	st    *memory.Store
	log   *bytes.Buffer
	now   time.Time
	peer  Peer
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{log: &bytes.Buffer{}, now: time.Unix(1_757_041_495, 0), peer: Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}}
	f.st = memory.New(func() time.Time { return f.now })
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return f.now })
	f.h = New(f.st, decision.NewJSONLines(f.log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return f.now }, func() string { ids++; return "ctx" + string(rune('0'+ids)) },
		30*time.Second, time.Hour)
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_tok1"), Kind: "login", ExpiresAt: f.now.Add(15 * time.Minute)})
	return f
}

func TestTypesMatch(t *testing.T) { Canonical("x") }

func (f *fixture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{"alice": "alice", "ALICE": "alice", `CORP\Alice`: "alice", "alice@corp.example.com": "alice"} {
		if got := Canonical(in); got != want {
			t.Fatalf("%q → %q", in, got)
		}
	}
}

func TestPAPRedeemsAndCreatesContext(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	reply, done := s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("Alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_tok1")})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("reply %+v done %v", reply, done)
	}
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"})
	if err != nil || c.Username != "alice" || c.RemAddr != "198.51.100.4" || c.CtxID != "ctx1" {
		t.Fatalf("context %+v err %v", c, err)
	}
	if cands, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(cands) != 0 {
		t.Fatal("token not consumed")
	}
	r := f.records(t)
	if len(r) != 1 || r[0]["event"] != "redeem" || r[0]["verdict"] != "permit" || r[0]["reason"] != "token_redeemed" {
		t.Fatalf("%v", r)
	}
	if strings.Contains(f.log.String(), "p49_tok1") {
		t.Fatal("token leaked into the log")
	}
}

func TestRetransmissionReplaysReceipt(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_tok1")}
	f.h.NewSession(f.peer).Start(context.Background(), start)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("retry must PASS from the receipt: %+v", reply)
	}
	r := f.records(t)
	if r[1]["reason"] != "receipt_replayed" || r[1]["session"].(map[string]any)["ctx_id"] != "ctx1" {
		t.Fatalf("%v", r[1])
	}
	// Same line and username, different credential: the receipt must not stand in for the check.
	start.Data = []byte("something-else")
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusFail || f.records(t)[2]["reason"] != "credential_mismatch" {
		t.Fatalf("%+v %v", reply, f.records(t)[2])
	}
}

func TestUnknownTokenFails(t *testing.T) {
	f := setup(t)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty1"), Data: []byte("wrong")})
	if !done || reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "token_not_found" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

func TestASCIIMultiRound(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	r1, done := s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, Port: []byte("vty0")})
	if done || r1.Status != wire.AuthenStatusGetUser {
		t.Fatalf("%+v", r1)
	}
	r2, done := s.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("alice")})
	if done || r2.Status != wire.AuthenStatusGetPass || r2.Flags&wire.AuthenReplyFlagNoEcho == 0 {
		t.Fatalf("%+v", r2)
	}
	r3, done := s.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("p49_tok1")})
	if !done || r3.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", r3)
	}
}

func TestASCIIAbort(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin})
	_, done := s.Continue(context.Background(), wire.AuthenContinue{Flags: wire.AuthenContinueFlagAbort})
	if !done || len(f.records(t)) != 0 {
		t.Fatal("abort must end the session without a record")
	}
}

func TestCHAP(t *testing.T) {
	f := setup(t)
	challenge := []byte("0123456789abcdef")
	sum := md5.Sum(append(append([]byte{0x2a}, []byte("p49_tok1")...), challenge...))
	data := append(append([]byte{0x2a}, challenge...), sum[:]...)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: data})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	// A re-prompt with a fresh challenge does not match the receipt and fails (design §8).
	sum2 := md5.Sum(append(append([]byte{0x2b}, []byte("p49_tok1")...), []byte("fedcba9876543210")...))
	data2 := append(append([]byte{0x2b}, []byte("fedcba9876543210")...), sum2[:]...)
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: data2})
	if reply.Status != wire.AuthenStatusFail {
		t.Fatalf("fresh challenge must not replay: %+v", reply)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/daemon/authen -v`
Expected: FAIL, `undefined: New`.

- [ ] **Step 4: Implement the handler**

`internal/daemon/authen/authen.go`:
```go
// Package authen runs the RFC 8907 authentication exchange against the token
// set in the store (design §8; spec §5.6, §5.7). It never sees a broker.
package authen

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Peer struct {
	NAS      string
	NASAddr  string
	Platform string
}

type Handler struct {
	store      store.Store
	log        decision.Emitter
	limits     *limits.Limiter
	metrics    *metrics.Metrics
	now        func() time.Time
	newCtxID   func() string
	receiptTTL time.Duration
	contextTTL time.Duration
}

func New(s store.Store, e decision.Emitter, l *limits.Limiter, m *metrics.Metrics, now func() time.Time,
	newCtxID func() string, receiptTTL, contextTTL time.Duration) *Handler {
	return &Handler{store: s, log: e, limits: l, metrics: m, now: now, newCtxID: newCtxID, receiptTTL: receiptTTL, contextTTL: contextTTL}
}

type Session struct {
	h     *Handler
	peer  Peer
	start wire.AuthenStart
	user  string // as typed
	phase int    // 0 new, 1 waiting for user, 2 waiting for password
}

func (h *Handler) NewSession(peer Peer) *Session { return &Session{h: h, peer: peer} }

func (s *Session) Start(ctx context.Context, p wire.AuthenStart) (wire.AuthenReply, bool) {
	s.start = p
	s.user = string(p.User)
	if p.Action != wire.AuthenActionLogin {
		return wire.AuthenReply{Status: wire.AuthenStatusFail}, true
	}
	switch p.AuthenType {
	case wire.AuthenTypePAP:
		return s.verify(ctx, "pap", p.Data, p.Data)
	case wire.AuthenTypeCHAP:
		return s.verifyCHAP(ctx, p.Data)
	case wire.AuthenTypeASCII:
		if s.user == "" {
			s.phase = 1
			return wire.AuthenReply{Status: wire.AuthenStatusGetUser, ServerMsg: []byte("Username: ")}, false
		}
		s.phase = 2
		return wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: wire.AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}, false
	default:
		return wire.AuthenReply{Status: wire.AuthenStatusError, ServerMsg: []byte("port49: authentication type not supported")}, true
	}
}

func (s *Session) Continue(ctx context.Context, p wire.AuthenContinue) (wire.AuthenReply, bool) {
	if p.Flags&wire.AuthenContinueFlagAbort != 0 {
		return wire.AuthenReply{}, true
	}
	switch s.phase {
	case 1:
		s.user = string(p.UserMsg)
		s.phase = 2
		return wire.AuthenReply{Status: wire.AuthenStatusGetPass, Flags: wire.AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}, false
	case 2:
		return s.verify(ctx, "ascii", p.UserMsg, p.UserMsg)
	}
	return wire.AuthenReply{Status: wire.AuthenStatusError}, true
}

// verify handles PAP and ASCII, where the presented credential is the token itself.
func (s *Session) verify(ctx context.Context, method string, presented, secret []byte) (wire.AuthenReply, bool) {
	return s.redeem(ctx, method, presented, func(t store.Token) bool { return bytes.Equal(t.Secret, secret) })
}

func (s *Session) verifyCHAP(ctx context.Context, data []byte) (wire.AuthenReply, bool) {
	if len(data) < 1+1+md5.Size {
		return wire.AuthenReply{Status: wire.AuthenStatusFail}, true
	}
	id, challenge, response := data[0], data[1:len(data)-md5.Size], data[len(data)-md5.Size:]
	return s.redeem(ctx, "chap", data, func(t store.Token) bool {
		m := md5.New()
		m.Write([]byte{id})
		m.Write(t.Secret)
		m.Write(challenge)
		return bytes.Equal(m.Sum(nil), response)
	})
}

func (s *Session) redeem(ctx context.Context, method string, presented []byte, match func(store.Token) bool) (wire.AuthenReply, bool) {
	username := Canonical(s.user)
	port := string(s.start.Port)
	remAddr := string(s.start.RemAddr)
	rk := store.ReceiptKey{NAS: s.peer.NAS, Port: port, Username: username}
	credHash := sha256.Sum256(presented)
	rec := decision.Record{TS: s.h.now(), Event: decision.EventRedeem,
		Auth:    &decision.Auth{Method: method, CredentialSHA256: decision.CredentialHash(presented)},
		Device:  &decision.Device{NAS: s.peer.NASAddr, Name: s.peer.NAS, Platform: s.peer.Platform},
		Session: &decision.Session{Port: port, RemAddr: remAddr, Privilege: s.start.PrivLvl}}

	// 1. Receipt: a retransmission replays; a different credential on the same line fails.
	if r, err := s.h.store.GetReceipt(ctx, rk); err == nil {
		if r.CredentialSHA256 == credHash {
			rec.Session.CtxID = r.CtxID
			return s.finish(rec, r.Status, decision.ReceiptReplayed)
		}
		return s.fail(rec, decision.CredentialMismatch)
	}

	// 2. Candidates under (nas, username), filtered by kind.
	kind := "login"
	if s.start.Service == wire.AuthenServiceEnable {
		kind = "enable"
	}
	cands, err := s.h.store.Candidates(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username})
	if err != nil {
		return wire.AuthenReply{Status: wire.AuthenStatusError, ServerMsg: []byte("port49: store unavailable")}, true
	}
	var winner *store.Token
	for i := range cands {
		if match(cands[i]) {
			winner = &cands[i]
			break
		}
	}
	if winner == nil {
		return s.fail(rec, decision.TokenNotFound)
	}
	if winner.Kind != kind {
		return s.fail(rec, decision.TokenKindMismatch)
	}

	// 3. Atomic redemption; the loser of a race adopts the winner's receipt.
	ctxID := s.h.newCtxID()
	receipt := store.Receipt{CredentialSHA256: credHash, Status: wire.AuthenStatusPass, CtxID: ctxID, ExpiresAt: s.h.now().Add(s.h.receiptTTL)}
	if err := s.h.store.RedeemAndReceipt(ctx, store.TokenKey{NAS: s.peer.NAS, Username: username}, winner.Secret, rk, receipt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if r, rerr := s.h.store.GetReceipt(ctx, rk); rerr == nil && r.CredentialSHA256 == credHash {
				rec.Session.CtxID = r.CtxID
				return s.finish(rec, r.Status, decision.ReceiptReplayed)
			}
			return s.fail(rec, decision.TokenNotFound)
		}
		return wire.AuthenReply{Status: wire.AuthenStatusError, ServerMsg: []byte("port49: store unavailable")}, true
	}
	_ = s.h.store.PutContext(ctx, store.ContextKey{NAS: s.peer.NAS, Port: port},
		store.Context{CtxID: ctxID, Username: username, RemAddr: remAddr, PrivLvl: s.start.PrivLvl, CreatedAt: s.h.now()}, s.h.contextTTL)
	rec.Session.CtxID = ctxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}

func (s *Session) finish(rec decision.Record, status uint8, reason decision.Reason) (wire.AuthenReply, bool) {
	rec.Verdict = decision.VerdictPermit
	if status != wire.AuthenStatusPass {
		rec.Verdict = decision.VerdictDeny
	}
	rec.Reason = reason
	s.h.log.Emit(rec)
	s.h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(reason)).Inc()
	return wire.AuthenReply{Status: status}, true
}

func (s *Session) fail(rec decision.Record, reason decision.Reason) (wire.AuthenReply, bool) {
	delay := s.h.limits.AuthFailure(s.peer.NAS, Canonical(s.user))
	s.h.metrics.AuthFailures.Inc()
	time.Sleep(delay)
	rec.ServerMsg = "port49: authentication failed — mint a new token with `port49 token`"
	reply, done := s.finish(rec, wire.AuthenStatusFail, reason)
	reply.ServerMsg = []byte(rec.ServerMsg)
	return reply, done
}
```

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/daemon/authen -race -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/daemon/authen
git commit -m "feat(authen): ASCII, PAP, CHAP redemption with receipts and failure delay"
```

---

### Task 12: Authorization handler with a pluggable Authorizer and the lab policy

**Files:**
- Create: `internal/daemon/author/author.go`, `internal/daemon/author/lab.go`
- Test: `internal/daemon/author/author_test.go`

**Interfaces:**
- Consumes: `store.Store` (`GetContext`), `decision.Emitter`, `metrics.Metrics`, `wire.AuthorRequest/Response`.
- Produces:
  ```go
  // Decision is what an Authorizer returns; the policy engine (plan 4) implements Authorizer for real.
  type Decision struct { Permit bool; Reason decision.Reason; ServerMsg string; Attributes []string /* session only, e.g. "priv-lvl=15" */ }
  type Authorizer interface {
      Session(ctx context.Context, c store.Context, args []string) Decision
      Command(ctx context.Context, c store.Context, vector []string, args []string) Decision
  }
  type Handler struct { /* opaque */ }
  func New(s store.Store, a Authorizer, e decision.Emitter, m *metrics.Metrics, now func() time.Time) *Handler
  func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AuthorRequest) wire.AuthorResponse
  func ParseArgs(args [][]byte) (kv map[string]string, cmd string, cmdArgs []string, raw []string)  // splits on '=' or '*'; collects cmd-arg in order; strips a trailing "<cr>"
  // Lab authorizer: permits everything except listed commands, which it denies with a server_msg (closes L2).
  type Lab struct { SessionAttributes []string; DenyPrefixes []string }
  ```
- Handling (spec §5.2, §5.3): no context → `FAIL`, `context_missing`, `server_msg` "port49: this session was not authenticated by port49"; username on the request ≠ `ctx.Username` (canonical) → `FAIL`, `username_mismatch`, and `DeleteContext`; `service` not `shell` → `FAIL`, `service_unsupported`; empty `cmd` → session authorization returning `PASS_ADD` with attributes; otherwise command authorization. Every outcome emits one `authorize_session` or `authorize_command` record with `request.raw` and `request.vector`.

- [ ] **Step 1: Write the failing tests**

`internal/daemon/author/author_test.go`:
```go
package author

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

var peer = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}

func setup(t *testing.T) (*Handler, *memory.Store, *bytes.Buffer) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"},
		store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15}, time.Hour)
	log := &bytes.Buffer{}
	lab := &Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload", "copy running-config tftp:"}}
	return New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now), st, log
}

func req(user, port string, args ...string) wire.AuthorRequest {
	r := wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte(port)}
	for _, a := range args {
		r.Args = append(r.Args, []byte(a))
	}
	return r
}

func lastRecord(t *testing.T, log *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseArgs(t *testing.T) {
	kv, cmd, cmdArgs, raw := ParseArgs([][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=running-config"), []byte("cmd-arg=<cr>"), []byte("priv-lvl*15")})
	if kv["service"] != "shell" || kv["priv-lvl"] != "15" || cmd != "show" || strings.Join(cmdArgs, " ") != "running-config" || len(raw) != 5 {
		t.Fatalf("%v %q %v %v", kv, cmd, cmdArgs, raw)
	}
}

func TestSessionAuthorizationReturnsAttributes(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd="))
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 1 || string(resp.Args[0]) != "priv-lvl=15" {
		t.Fatalf("%+v", resp)
	}
	if r := lastRecord(t, log); r["event"] != "authorize_session" || r["reason"] != "context_matched" {
		t.Fatalf("%v", r)
	}
}

func TestCommandPermitAndDenyWithServerMsg(t *testing.T) {
	h, _, log := setup(t)
	if resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>")); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	r := lastRecord(t, log)
	vec := r["request"].(map[string]any)["vector"].([]any)
	if r["event"] != "authorize_command" || len(vec) != 2 || vec[1] != "version" {
		t.Fatalf("%v", r)
	}
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=reload", "cmd-arg=<cr>"))
	if resp.Status != wire.AuthorStatusFail || !strings.HasPrefix(string(resp.ServerMsg), "port49: denied") {
		t.Fatalf("%+v", resp)
	}
}

func TestNoContextIsDistinct(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty9", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "context_missing" || len(resp.ServerMsg) == 0 {
		t.Fatalf("%+v", resp)
	}
}

func TestUsernameMismatchInvalidates(t *testing.T) {
	h, st, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("bob", "vty0", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "username_mismatch" {
		t.Fatalf("%+v", resp)
	}
	if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"}); err == nil {
		t.Fatal("context must be invalidated")
	}
}

func TestUnsupportedService(t *testing.T) {
	h, _, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=ppp", "protocol=ip"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "service_unsupported" {
		t.Fatalf("%+v", resp)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/daemon/author -v`
Expected: FAIL, package does not exist.

- [ ] **Step 3: Implement the handler**

`internal/daemon/author/author.go`:
```go
// Package author runs session and command authorization (spec §5.2, §5.3)
// against login context, delegating the policy question to an Authorizer.
package author

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Decision struct {
	Permit     bool
	Reason     decision.Reason
	ServerMsg  string
	Attributes []string
}

type Authorizer interface {
	Session(ctx context.Context, c store.Context, args []string) Decision
	Command(ctx context.Context, c store.Context, vector []string, args []string) Decision
}

type Handler struct {
	store   store.Store
	authz   Authorizer
	log     decision.Emitter
	metrics *metrics.Metrics
	now     func() time.Time
}

func New(s store.Store, a Authorizer, e decision.Emitter, m *metrics.Metrics, now func() time.Time) *Handler {
	return &Handler{store: s, authz: a, log: e, metrics: m, now: now}
}

// ParseArgs splits RFC 8907 AV pairs. A trailing cmd-arg of "<cr>" is dropped
// from cmdArgs but kept in raw (spec §5.8).
func ParseArgs(args [][]byte) (kv map[string]string, cmd string, cmdArgs []string, raw []string) {
	kv = make(map[string]string, len(args))
	for _, a := range args {
		s := string(a)
		raw = append(raw, s)
		i := strings.IndexAny(s, "=*")
		if i < 0 {
			continue
		}
		k, v := s[:i], s[i+1:]
		switch k {
		case "cmd":
			cmd = v
		case "cmd-arg":
			cmdArgs = append(cmdArgs, v)
		default:
			kv[k] = v
		}
	}
	if n := len(cmdArgs); n > 0 && cmdArgs[n-1] == "<cr>" {
		cmdArgs = cmdArgs[:n-1]
	}
	return kv, cmd, cmdArgs, raw
}

func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AuthorRequest) wire.AuthorResponse {
	kv, cmd, cmdArgs, raw := ParseArgs(req.Args)
	port := string(req.Port)
	vector := append([]string{cmd}, cmdArgs...)
	if cmd == "" {
		vector = nil
	}
	rec := decision.Record{TS: h.now(), Event: decision.EventAuthorizeCommand,
		Device:  &decision.Device{NAS: peer.NASAddr, Name: peer.NAS, Platform: peer.Platform},
		Session: &decision.Session{Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		Request: &decision.Request{Raw: raw, Vector: vector}}
	if cmd == "" {
		rec.Event = decision.EventAuthorizeSession
	}

	c, err := h.store.GetContext(ctx, store.ContextKey{NAS: peer.NAS, Port: port})
	if errors.Is(err, store.ErrNotFound) {
		return h.deny(rec, decision.ContextMissing, "port49: this session was not authenticated by port49 — log in again")
	}
	if err != nil {
		return wire.AuthorResponse{Status: wire.AuthorStatusError, ServerMsg: []byte("port49: store unavailable")}
	}
	rec.Session.CtxID = c.CtxID
	rec.Principal = c.Principal
	if authen.Canonical(string(req.User)) != c.Username {
		_ = h.store.DeleteContext(ctx, store.ContextKey{NAS: peer.NAS, Port: port})
		return h.deny(rec, decision.UsernameMismatch, "port49: username does not match the authenticated session")
	}
	if svc := kv["service"]; svc != "shell" {
		return h.deny(rec, decision.ServiceUnsupported, "port49: service "+svc+" is not authorized by port49")
	}

	var d Decision
	if cmd == "" {
		d = h.authz.Session(ctx, c, raw)
	} else {
		d = h.authz.Command(ctx, c, vector, raw)
	}
	if !d.Permit {
		return h.deny(rec, d.Reason, d.ServerMsg)
	}
	rec.Verdict, rec.Reason = decision.VerdictPermit, d.Reason
	h.emit(rec)
	resp := wire.AuthorResponse{Status: wire.AuthorStatusPassAdd}
	for _, a := range d.Attributes {
		resp.Args = append(resp.Args, []byte(a))
	}
	return resp
}

func (h *Handler) deny(rec decision.Record, reason decision.Reason, msg string) wire.AuthorResponse {
	rec.Verdict, rec.Reason, rec.ServerMsg = decision.VerdictDeny, reason, msg
	h.emit(rec)
	return wire.AuthorResponse{Status: wire.AuthorStatusFail, ServerMsg: []byte(msg)}
}

func (h *Handler) emit(rec decision.Record) {
	h.log.Emit(rec)
	h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(rec.Reason)).Inc()
}
```

- [ ] **Step 4: Implement the lab authorizer**

`internal/daemon/author/lab.go`:
```go
package author

import (
	"context"
	"strings"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// Lab is the authorizer used before the policy engine exists (plan 4). It
// returns fixed session attributes and denies commands by prefix, with a
// server_msg, which is exactly what lab register entries L2 and L10 need.
type Lab struct {
	SessionAttributes []string
	DenyPrefixes      []string
}

func (l *Lab) Session(_ context.Context, _ store.Context, _ []string) Decision {
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: l.SessionAttributes}
}

func (l *Lab) Command(_ context.Context, _ store.Context, vector []string, _ []string) Decision {
	line := strings.Join(vector, " ")
	for _, p := range l.DenyPrefixes {
		if strings.HasPrefix(line, p) {
			return Decision{Permit: false, Reason: decision.NoPermitDominatesDeny,
				ServerMsg: "port49: denied by lab_deny (" + p + ") — see 'port49 explain'"}
		}
	}
	return Decision{Permit: true, Reason: decision.PermitDominates}
}
```

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/daemon/author -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/daemon/author
git commit -m "feat(author): session and command authorization with pluggable Authorizer and lab policy"
```

---

### Task 13: Accounting handler and spool

**Files:**
- Create: `internal/daemon/acct/acct.go`, `internal/daemon/acct/spool.go`
- Test: `internal/daemon/acct/acct_test.go`, `internal/daemon/acct/spool_test.go`

**Interfaces:**
- Consumes: `store.Store` (`GetContext`), `decision.Emitter`, `metrics.Metrics`, `author.ParseArgs`, `wire.AcctRequest/Reply`.
- Produces:
  ```go
  type Spool struct { /* opaque */ }
  func NewSpool(capacity int, overflowPath string, sink decision.Emitter, m *metrics.Metrics) (*Spool, error)
  func (s *Spool) Offer(r decision.Record) error      // nil after a durable hand-off; ErrSpoolFull only when memory is full and the overflow file cannot be written
  func (s *Spool) Run(ctx context.Context)            // drains to sink; returns when ctx is done and the buffer is empty
  var ErrSpoolFull = errors.New("acct: spool full")
  type Handler struct { /* opaque */ }
  func New(s store.Store, sp *Spool, m *metrics.Metrics, now func() time.Time) *Handler
  func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AcctRequest) wire.AcctReply
  ```
- Behaviour (spec §5.8): flags → `"start"|"stop"|"watchdog"`; record `raw` verbatim and `vector` with `<cr>` stripped; `task_id`, `start_time`, `stop_time`, `elapsed_time` parsed from AV pairs; attribution `resolved` with `ctx_id` when a context exists for `(nas, port)` and its username matches, else `unattributed` with `ctx_id: null`; annotation of context (`task_id` binding, `closing`) is **plan 2** since the context shape here has no `task_id` yet. Reply `SUCCESS` after `Offer` returns nil, `ERROR` only on `ErrSpoolFull`. Redaction patterns come with adapters in plan 5; nothing is redacted here, and the plan-5 task MUST add it before any deployment.

- [ ] **Step 1: Write the failing spool tests**

`internal/daemon/acct/spool_test.go`:
```go
package acct

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

func TestSpoolDrainsInOrder(t *testing.T) {
	out := &bytes.Buffer{}
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "overflow.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	for i := 0; i < 3; i++ {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"task_id":"a"`) || !strings.Contains(lines[2], `"task_id":"c"`) {
		t.Fatalf("%q", out.String())
	}
}

func TestSpoolOverflowsToDiskNotToError(t *testing.T) {
	out := &bytes.Buffer{}
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	sp, _ := NewSpool(2, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	// Not running: the memory buffer fills at 2, the rest must go to disk and still return nil.
	for i := 0; i < 5; i++ {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "x"}); err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if n := strings.Count(out.String(), "\n"); n != 5 {
		t.Fatalf("drained %d of 5", n)
	}
}

func TestSpoolFullWhenDiskUnwritable(t *testing.T) {
	sp, _ := NewSpool(1, "/proc/port49-cannot-write-here/overflow.jsonl", decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	sp.Offer(decision.Record{Event: decision.EventAccount})
	if err := sp.Offer(decision.Record{Event: decision.EventAccount}); err != ErrSpoolFull {
		t.Fatalf("want ErrSpoolFull, got %v", err)
	}
}
```

- [ ] **Step 2: Write the failing handler tests**

`internal/daemon/acct/acct_test.go`:
```go
package acct

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

var peer = authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}

func setup(t *testing.T) (*Handler, *bytes.Buffer, func()) {
	t.Helper()
	st := memory.New(time.Now)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"},
		store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice"}, time.Hour)
	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now)
	return h, out, func() { cancel(); <-done }
}

func acct(flags uint8, user, port string, args ...string) wire.AcctRequest {
	r := wire.AcctRequest{Flags: flags, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte(port), RemAddr: []byte("198.51.100.4")}
	for _, a := range args {
		r.Args = append(r.Args, []byte(a))
	}
	return r
}

func TestCommandStopIsResolvedAndCRStripped(t *testing.T) {
	h, out, stop := setup(t)
	reply := h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0",
		"task_id=43", "service=shell", "cmd=show", "cmd-arg=running-config", "cmd-arg=<cr>", "start_time=1757041502", "stop_time=1757041502"))
	stop()
	if reply.Status != wire.AcctStatusSuccess {
		t.Fatalf("%+v", reply)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
		t.Fatal(err)
	}
	rec := m["record"].(map[string]any)
	if m["event"] != "account" || m["flags"] != "stop" || m["attribution"] != "resolved" || m["task_id"] != "43" ||
		m["principal"] != "user:alice@example.com" || m["session"].(map[string]any)["ctx_id"] != "ctx1" {
		t.Fatalf("%v", m)
	}
	if raw := rec["raw"].([]any); raw[len(raw)-1] != "stop_time=1757041502" || len(raw) != 7 {
		t.Fatalf("raw %v", raw)
	}
	if vec := rec["vector"].([]any); len(vec) != 2 || vec[1] != "running-config" {
		t.Fatalf("vector %v", vec)
	}
	if rec["stop_time"].(float64) != 1757041502 {
		t.Fatalf("%v", rec)
	}
}

func TestUnattributedIsRecordedNotDiscarded(t *testing.T) {
	h, out, stop := setup(t)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "bob", "vty0", "task_id=9", "service=shell", "cmd="))
	stop()
	var m map[string]any
	json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m)
	if m["attribution"] != "unattributed" || m["session"].(map[string]any)["ctx_id"] != "" {
		t.Fatalf("%v", m)
	}
}

func TestWatchdogIsRecorded(t *testing.T) {
	h, out, stop := setup(t)
	reply := h.Handle(context.Background(), peer, acct(wire.AcctFlagWatchdog, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	stop()
	if reply.Status != wire.AcctStatusSuccess || !strings.Contains(out.String(), `"flags":"watchdog"`) {
		t.Fatalf("%+v %s", reply, out.String())
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/daemon/acct -v`
Expected: FAIL, package does not exist.

- [ ] **Step 4: Implement the spool**

`internal/daemon/acct/spool.go`:
```go
package acct

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

var ErrSpoolFull = errors.New("acct: spool full")

// Spool is a bounded in-memory buffer with a disk-backed overflow (spec §5.8).
// Offer returns nil only after a durable hand-off; Run drains to the sink in
// order: memory first, then whatever overflowed.
type Spool struct {
	mem          chan decision.Record
	overflowPath string
	sink         decision.Emitter
	metrics      *metrics.Metrics
	mu           sync.Mutex
	overflowed   int
}

func NewSpool(capacity int, overflowPath string, sink decision.Emitter, m *metrics.Metrics) (*Spool, error) {
	if capacity < 1 {
		return nil, errors.New("acct: spool capacity must be at least 1")
	}
	return &Spool{mem: make(chan decision.Record, capacity), overflowPath: overflowPath, sink: sink, metrics: m}, nil
}

func (s *Spool) Offer(r decision.Record) error {
	select {
	case s.mem <- r:
		s.metrics.SpoolDepth.Set(float64(len(s.mem)))
		return nil
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.overflowPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	defer f.Close()
	b, _ := json.Marshal(r)
	if _, err := f.Write(append(b, '\n')); err != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	if err := f.Sync(); err != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	s.overflowed++
	return nil
}

func (s *Spool) Run(ctx context.Context) {
	for {
		select {
		case r := <-s.mem:
			s.sink.Emit(r)
			s.metrics.SpoolDepth.Set(float64(len(s.mem)))
		case <-time.After(10 * time.Millisecond):
			s.drainOverflow()
		case <-ctx.Done():
			for len(s.mem) > 0 {
				s.sink.Emit(<-s.mem)
			}
			s.drainOverflow()
			s.metrics.SpoolDepth.Set(0)
			return
		}
	}
}

func (s *Spool) drainOverflow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overflowed == 0 {
		return
	}
	f, err := os.Open(s.overflowPath)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var r decision.Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			s.sink.Emit(r)
		}
	}
	f.Close()
	os.Remove(s.overflowPath)
	s.overflowed = 0
}
```

`decision.Record` needs an `UnmarshalJSON` counterpart to its custom `MarshalJSON` so the overflow file round-trips. Add to `internal/decision/log.go`:
```go
func (r *Record) UnmarshalJSON(b []byte) error {
	type alias Record
	var a struct {
		TS string `json:"ts"`
		*alias
	}
	a.alias = (*alias)(r)
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	ts, err := time.Parse("2006-01-02T15:04:05.000Z07:00", a.TS)
	if err != nil {
		return err
	}
	r.TS = ts
	return nil
}
```

- [ ] **Step 5: Implement the handler**

`internal/daemon/acct/acct.go`:
```go
// Package acct records device accounting as `account` events (spec §5.8).
// Accounting never enforces, never deletes state, and is never written to the store.
package acct

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Handler struct {
	store   store.Store
	spool   *Spool
	metrics *metrics.Metrics
	now     func() time.Time
}

func New(s store.Store, sp *Spool, m *metrics.Metrics, now func() time.Time) *Handler {
	return &Handler{store: s, spool: sp, metrics: m, now: now}
}

func flagsName(f uint8) string {
	switch {
	case f&wire.AcctFlagWatchdog != 0:
		return "watchdog"
	case f&wire.AcctFlagStart != 0:
		return "start"
	case f&wire.AcctFlagStop != 0:
		return "stop"
	}
	return "unknown"
}

func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AcctRequest) wire.AcctReply {
	kv, cmd, cmdArgs, raw := author.ParseArgs(req.Args)
	port := string(req.Port)
	var vector []string
	if cmd != "" {
		vector = append([]string{cmd}, cmdArgs...)
	}
	rec := decision.Record{TS: h.now(), Event: decision.EventAccount, Flags: flagsName(req.Flags),
		Attribution: "unattributed", TaskID: kv["task_id"],
		Device:  &decision.Device{NAS: peer.NASAddr, Name: peer.NAS, Platform: peer.Platform},
		Session: &decision.Session{Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		AcctRecord: &decision.AcctRecord{Raw: raw, Vector: vector, PrivLvl: req.PrivLvl,
			StartTime: num(kv["start_time"]), StopTime: num(kv["stop_time"]), ElapsedTime: num(kv["elapsed_time"])}}

	if c, err := h.store.GetContext(ctx, store.ContextKey{NAS: peer.NAS, Port: port}); err == nil &&
		c.Username == authen.Canonical(string(req.User)) {
		rec.Attribution = "resolved"
		rec.Principal = c.Principal
		rec.Session.CtxID = c.CtxID
	}

	if err := h.spool.Offer(rec); err != nil {
		if errors.Is(err, ErrSpoolFull) {
			h.metrics.Requests.WithLabelValues("acct", "error").Inc()
			return wire.AcctReply{Status: wire.AcctStatusError, ServerMsg: []byte("port49: accounting spool full")}
		}
	}
	h.metrics.Requests.WithLabelValues("acct", "success").Inc()
	return wire.AcctReply{Status: wire.AcctStatusSuccess}
}

func num(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/daemon/acct ./internal/decision -race -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/daemon/acct internal/decision/log.go
git commit -m "feat(acct): accounting records with durable spool and attribution"
```

---

### Task 14: Configuration, connection handling, listener, and the binary

**Files:**
- Create: `internal/config/config.go`, `internal/daemon/server/conn.go`, `internal/daemon/server/server.go`
- Modify: `cmd/port49d/main.go`
- Test: `internal/config/config_test.go`, `internal/daemon/server/server_test.go` (end-to-end over TCP with a client built from `wire`)

**Interfaces:**
- Produces (config, `port49d.yaml`, all snake_case):
  ```yaml
  listen: ":49"
  metrics_listen: ":9049"
  inventory_file: /etc/port49/inventory.yaml
  keys:
    prod_key:
      current: {version: 3, secret_env: PORT49_KEY_PROD_V3}
      accept:  [{version: 2, secret_env: PORT49_KEY_PROD_V2}]
      retired: [{version: 1, secret_env: PORT49_KEY_PROD_V1}]   # diagnosis only
  limits:
    per_nas_connections: 32
    idle_timeout: 30s
    malformed_backoff_base: 100ms
    malformed_backoff_max: 5s
    auth_failure_delay_base: 500ms
    auth_failure_delay_max: 5s
    auth_failure_window: 10m
  receipt_ttl: 30s
  context_idle_ttl: 12h
  accounting:
    spool_capacity: 10000
    spool_overflow_path: /var/lib/port49/acct-overflow.jsonl
  lab:                                   # optional; only for plan-1 lab work
    session_attributes: ["priv-lvl=15"]
    deny_prefixes: ["reload"]
    seed_tokens:                          # (nas, username, secret, kind); ttl is context_idle_ttl
      - {nas: leaf-01, username: alice, secret: p49_labtoken1, kind: login}
  ```
  ```go
  type Config struct { Listen, MetricsListen, InventoryFile string; Keys map[string]KeySet; Limits limits.Config; ReceiptTTL, ContextIdleTTL time.Duration; Accounting AccountingConfig; Lab *LabConfig }
  type KeySet struct { Current KeyVersion; Accept, Retired []KeyVersion }
  type KeyVersion struct { Version int; SecretEnv string }
  func Load(path string) (Config, error)                 // parses, applies defaults, validates: every key_ref in the inventory's key groups exists in keys; every secret_env is set
  func (c Config) Keyring() map[string]keyring.Set        // resolved secrets, ordered current, accept, retired
  ```
- Produces (server):
  ```go
  type Deps struct { Admission *admission.Trie; Keys map[string]keyring.Set; Store store.Store; Authen *authen.Handler; Author *author.Handler; Acct *acct.Handler; Limits *limits.Limiter; Metrics *metrics.Metrics; Log decision.Emitter; Now func() time.Time; IdleTimeout time.Duration }
  func Serve(ctx context.Context, ln net.Listener, d Deps) error
  ```
- Connection behaviour (spec §10, design §11):
  1. `Limits.Acquire(src)`; refused → close, `port49_connections{state="refused_cap"}`.
  2. Admission lookup by source address; unknown → read one header only, emit an `unvalidated` record with diagnosis `unadmitted_source`, close.
  3. Read 12-byte header; `Validate`; on failure emit `unvalidated` (`not_tacacs` or `unencrypted_refused`), `Limits.Malformed` backoff, close. **Body never read into a log.**
  4. Read `Length` bytes. First packet on the connection: `keyring.Set.Resolve`; cache the version. Later packets: obfuscate with the cached version only; if `Validates` fails, treat as malformed.
  5. Dispatch by type; one authentication `Session` per `session_id`; reply obfuscated with the cached version; `seq_no = request + 1`.
  6. Without `FlagSingleConnect`, close after the exchange completes; with it, keep serving until idle timeout.
  7. Idle timeout via `SetReadDeadline` before every header read.

- [ ] **Step 1: Write the failing config test**

`internal/config/config_test.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `
listen: ":4949"
inventory_file: %s
keys:
  prod_key:
    current: {version: 3, secret_env: T_PROD_V3}
    accept:  [{version: 2, secret_env: T_PROD_V2}]
    retired: [{version: 1, secret_env: T_PROD_V1}]
limits: {per_nas_connections: 4}
lab:
  session_attributes: ["priv-lvl=15"]
  seed_tokens:
    - {nas: leaf-01, username: alice, secret: p49_lab, kind: login}
`

const inv = `
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: prod_key}
`

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaultsAndResolvesKeys(t *testing.T) {
	t.Setenv("T_PROD_V3", "three")
	t.Setenv("T_PROD_V2", "two")
	t.Setenv("T_PROD_V1", "one")
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "port49d.yaml", sprintf(sample, invPath)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":4949" || c.Limits.PerNASConnections != 4 || c.Limits.IdleTimeout == 0 || c.ReceiptTTL == 0 || c.ContextIdleTTL == 0 {
		t.Fatalf("%+v", c)
	}
	ks := c.Keyring()["prod_key"]
	if len(ks.Versions) != 3 || string(ks.Versions[0].Secret) != "three" || !ks.Versions[2].Retired {
		t.Fatalf("%+v", ks)
	}
	if c.Lab == nil || len(c.Lab.SeedTokens) != 1 || c.Lab.SeedTokens[0].Username != "alice" {
		t.Fatalf("%+v", c.Lab)
	}
}

func TestLoadRefusesMissingSecretAndUnknownKeyRef(t *testing.T) {
	invPath := write(t, "inventory.yaml", inv)
	if _, err := Load(write(t, "a.yaml", sprintf(sample, invPath))); err == nil {
		t.Fatal("unset secret_env must fail")
	}
	t.Setenv("T_PROD_V3", "x")
	t.Setenv("T_PROD_V2", "x")
	t.Setenv("T_PROD_V1", "x")
	bad := write(t, "inv2.yaml", "devices: []\nkey_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: nope}]\n")
	if _, err := Load(write(t, "b.yaml", sprintf(sample, bad))); err == nil {
		t.Fatal("key_ref not in keys must fail")
	}
}

func sprintf(f, a string) string { return replace(f, "%s", a) }
func replace(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Implement config**

`internal/config/config.go`:
```go
// Package config loads port49d.yaml. Keys are snake_case; secrets come from the
// environment by name, never inline.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/keyring"
)

type KeyVersion struct {
	Version   int    `yaml:"version"`
	SecretEnv string `yaml:"secret_env"`
}

type KeySet struct {
	Current KeyVersion   `yaml:"current"`
	Accept  []KeyVersion `yaml:"accept"`
	Retired []KeyVersion `yaml:"retired"`
}

type AccountingConfig struct {
	SpoolCapacity     int    `yaml:"spool_capacity"`
	SpoolOverflowPath string `yaml:"spool_overflow_path"`
}

type SeedToken struct {
	NAS      string `yaml:"nas"`
	Username string `yaml:"username"`
	Secret   string `yaml:"secret"`
	Kind     string `yaml:"kind"`
}

type LabConfig struct {
	SessionAttributes []string    `yaml:"session_attributes"`
	DenyPrefixes      []string    `yaml:"deny_prefixes"`
	SeedTokens        []SeedToken `yaml:"seed_tokens"`
}

type limitsYAML struct {
	PerNASConnections    int           `yaml:"per_nas_connections"`
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
	MalformedBackoffBase time.Duration `yaml:"malformed_backoff_base"`
	MalformedBackoffMax  time.Duration `yaml:"malformed_backoff_max"`
	AuthFailureDelayBase time.Duration `yaml:"auth_failure_delay_base"`
	AuthFailureDelayMax  time.Duration `yaml:"auth_failure_delay_max"`
	AuthFailureWindow    time.Duration `yaml:"auth_failure_window"`
}

type fileConfig struct {
	Listen         string            `yaml:"listen"`
	MetricsListen  string            `yaml:"metrics_listen"`
	InventoryFile  string            `yaml:"inventory_file"`
	Keys           map[string]KeySet `yaml:"keys"`
	Limits         limitsYAML        `yaml:"limits"`
	ReceiptTTL     time.Duration     `yaml:"receipt_ttl"`
	ContextIdleTTL time.Duration     `yaml:"context_idle_ttl"`
	Accounting     AccountingConfig  `yaml:"accounting"`
	Lab            *LabConfig        `yaml:"lab"`
}

type Config struct {
	Listen         string
	MetricsListen  string
	InventoryFile  string
	Keys           map[string]KeySet
	Limits         limits.Config
	ReceiptTTL     time.Duration
	ContextIdleTTL time.Duration
	Accounting     AccountingConfig
	Lab            *LabConfig
	secrets        map[string]string
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var f fileConfig
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}
	c := Config{
		Listen: or(f.Listen, ":49"), MetricsListen: or(f.MetricsListen, ":9049"), InventoryFile: f.InventoryFile,
		Keys: f.Keys, ReceiptTTL: orD(f.ReceiptTTL, 30*time.Second), ContextIdleTTL: orD(f.ContextIdleTTL, 12*time.Hour),
		Accounting: f.Accounting, Lab: f.Lab, secrets: map[string]string{},
		Limits: limits.Config{
			PerNASConnections:    orI(f.Limits.PerNASConnections, 32),
			IdleTimeout:          orD(f.Limits.IdleTimeout, 30*time.Second),
			MalformedBackoffBase: orD(f.Limits.MalformedBackoffBase, 100*time.Millisecond),
			MalformedBackoffMax:  orD(f.Limits.MalformedBackoffMax, 5*time.Second),
			AuthFailureDelayBase: orD(f.Limits.AuthFailureDelayBase, 500*time.Millisecond),
			AuthFailureDelayMax:  orD(f.Limits.AuthFailureDelayMax, 5*time.Second),
			AuthFailureWindow:    orD(f.Limits.AuthFailureWindow, 10*time.Minute),
		},
	}
	if c.Accounting.SpoolCapacity == 0 {
		c.Accounting.SpoolCapacity = 10000
	}
	if c.Accounting.SpoolOverflowPath == "" {
		c.Accounting.SpoolOverflowPath = "/var/lib/port49/acct-overflow.jsonl"
	}
	if c.InventoryFile == "" {
		return Config{}, fmt.Errorf("config: inventory_file is required")
	}
	for ref, ks := range c.Keys {
		for _, v := range append(append([]KeyVersion{ks.Current}, ks.Accept...), ks.Retired...) {
			s, ok := os.LookupEnv(v.SecretEnv)
			if !ok || s == "" {
				return Config{}, fmt.Errorf("config: key %s version %d: environment variable %s is not set", ref, v.Version, v.SecretEnv)
			}
			c.secrets[v.SecretEnv] = s
		}
	}
	inv, err := admission.LoadFile(c.InventoryFile)
	if err != nil {
		return Config{}, err
	}
	for _, g := range inv.KeyGroups {
		if _, ok := c.Keys[g.KeyRef]; !ok {
			return Config{}, fmt.Errorf("config: key group references key_ref %q which is not in keys", g.KeyRef)
		}
	}
	for _, d := range inv.Devices {
		if d.KeyRef != "" {
			if _, ok := c.Keys[d.KeyRef]; !ok {
				return Config{}, fmt.Errorf("config: device %q pins key_ref %q which is not in keys", d.Name, d.KeyRef)
			}
		}
	}
	return c, nil
}

// Keyring resolves every key set to its secrets, ordered current, accept, retired.
func (c Config) Keyring() map[string]keyring.Set {
	out := make(map[string]keyring.Set, len(c.Keys))
	for ref, ks := range c.Keys {
		set := keyring.Set{Ref: ref}
		set.Versions = append(set.Versions, keyring.Version{Number: ks.Current.Version, Secret: []byte(c.secrets[ks.Current.SecretEnv])})
		for _, v := range ks.Accept {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: []byte(c.secrets[v.SecretEnv])})
		}
		for _, v := range ks.Retired {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: []byte(c.secrets[v.SecretEnv]), Retired: true})
		}
		out[ref] = set
	}
	return out
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
func orD(v, d time.Duration) time.Duration {
	if v == 0 {
		return d
	}
	return v
}
func orI(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}
```

- [ ] **Step 3: Run config tests**

Run: `go test ./internal/config -v`
Expected: PASS.

- [ ] **Step 4: Write the failing end-to-end server test**

`internal/daemon/server/server_test.go`:
```go
package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// client is a minimal TACACS+ client built on the wire package.
type client struct {
	conn net.Conn
	key  []byte
	sid  uint32
	seq  uint8
}

func (c *client) send(t *testing.T, typ wire.Type, body []byte, flags uint8) {
	t.Helper()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: c.seq, Flags: flags, SessionID: c.sid, Length: uint32(len(body))}
	pkt := append(h.Encode(), wire.Obfuscate(h, c.key, body)...)
	if _, err := c.conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	c.seq += 2
}

func (c *client) recv(t *testing.T) (wire.Header, []byte) {
	t.Helper()
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(c.conn, hb); err != nil {
		t.Fatal(err)
	}
	h, _ := wire.DecodeHeader(hb)
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		t.Fatal(err)
	}
	return h, wire.Obfuscate(h, c.key, body)
}

func startServer(t *testing.T, log *bytes.Buffer) (addr string, st *memory.Store) {
	t.Helper()
	inv := admission.Inventory{
		Devices:   []admission.Device{{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}},
		KeyGroups: []admission.KeyGroup{{CIDR: netip.MustParsePrefix("127.0.0.0/8"), KeyRef: "prod_key"}},
	}
	trie, err := admission.Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	st = memory.New(time.Now)
	st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_e2e"), Kind: "login", ExpiresAt: time.Now().Add(time.Minute)})
	m := metrics.New(prometheus.NewRegistry())
	em := decision.NewJSONLines(log)
	lim := limits.New(limits.Config{PerNASConnections: 2, IdleTimeout: time.Second, MalformedBackoffBase: time.Millisecond,
		MalformedBackoffMax: time.Millisecond, AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: time.Millisecond, AuthFailureWindow: time.Minute}, time.Now)
	sp, _ := acct.NewSpool(16, t.TempDir()+"/o.jsonl", em, m)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go sp.Run(ctx)
	ids := 0
	d := Deps{Admission: trie,
		Keys:   map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{{Number: 2, Secret: []byte("k2")}, {Number: 1, Secret: []byte("k1"), Retired: true}}}},
		Store:  st,
		Authen: authen.New(st, em, lim, m, time.Now, func() string { ids++; return "ctx" }, 30*time.Second, time.Hour),
		Author: author.New(st, &author.Lab{SessionAttributes: []string{"priv-lvl=15"}, DenyPrefixes: []string{"reload"}}, em, m, time.Now),
		Acct:   acct.New(st, sp, m, time.Now),
		Limits: lim, Metrics: m, Log: em, Now: time.Now, IdleTimeout: time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go Serve(ctx, ln, d)
	return ln.Addr().String(), st
}

func dial(t *testing.T, addr string, key []byte) *client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{conn: conn, key: key, sid: 0xabcd1234, seq: 1}
}

func TestPAPLoginThenAuthorizeThenAccount(t *testing.T) {
	log := &bytes.Buffer{}
	addr, _ := startServer(t, log)

	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_e2e")}.Encode(), 0)
	h, body := c.recv(t)
	reply, err := wire.DecodeAuthenReply(body)
	if err != nil || reply.Status != wire.AuthenStatusPass || h.SeqNo != 2 {
		t.Fatalf("%+v %v seq=%d", reply, err, h.SeqNo)
	}

	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}.Encode(), 0)
	_, body = c.recv(t)
	ar, _ := wire.DecodeAuthorResponse(body)
	if ar.Status != wire.AuthorStatusPassAdd || string(ar.Args[0]) != "priv-lvl=15" {
		t.Fatalf("%+v", ar)
	}

	c = dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAcct, wire.AcctRequest{Flags: wire.AcctFlagStop, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Args: [][]byte{[]byte("task_id=1"), []byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version"), []byte("cmd-arg=<cr>")}}.Encode(), 0)
	_, body = c.recv(t)
	if cr, _ := wire.DecodeAcctReply(body); cr.Status != wire.AcctStatusSuccess {
		t.Fatalf("%+v", cr)
	}
	time.Sleep(50 * time.Millisecond)
	if !bytes.Contains(log.Bytes(), []byte(`"event":"account"`)) || !bytes.Contains(log.Bytes(), []byte(`"attribution":"resolved"`)) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestRetiredKeyIdentifiesButIsRefused(t *testing.T) {
	log := &bytes.Buffer{}
	addr, _ := startServer(t, log)
	c := dial(t, addr, []byte("k1"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a retired key must get no reply")
	}
	if !bytes.Contains(log.Bytes(), []byte(`"diagnosis":"matches_retired"`)) || bytes.Contains(log.Bytes(), []byte("p49_e2e")) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestUnencryptedFlagIsRefusedBeforeBody(t *testing.T) {
	log := &bytes.Buffer{}
	addr, _ := startServer(t, log)
	c := dial(t, addr, nil)
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("SECRET")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: wire.FlagUnencrypted, SessionID: 1, Length: uint32(len(body))}
	c.conn.Write(append(h.Encode(), body...))
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	c.conn.Read(make([]byte, 1))
	if !bytes.Contains(log.Bytes(), []byte(`"diagnosis":"unencrypted_refused"`)) || bytes.Contains(log.Bytes(), []byte("SECRET")) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestNotTACACSIsCountedAndBodyNeverLogged(t *testing.T) {
	log := &bytes.Buffer{}
	addr, _ := startServer(t, log)
	c := dial(t, addr, nil)
	junk := make([]byte, 40)
	binary.BigEndian.PutUint32(junk[8:12], 4) // a plausible length but version 0x00
	copy(junk[12:], "GET / HTTP/1.1\r\n")
	c.conn.Write(junk)
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	c.conn.Read(make([]byte, 1))
	if !bytes.Contains(log.Bytes(), []byte(`"diagnosis":"not_tacacs"`)) || bytes.Contains(log.Bytes(), []byte("HTTP")) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestPerNASCapRefusesThirdConnection(t *testing.T) {
	log := &bytes.Buffer{}
	addr, _ := startServer(t, log)
	c1, c2 := dial(t, addr, []byte("k2")), dial(t, addr, []byte("k2"))
	_ = c1
	_ = c2
	time.Sleep(20 * time.Millisecond)
	c3 := dial(t, addr, []byte("k2"))
	c3.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c3.conn.Read(make([]byte, 1)); err == nil || err == context.DeadlineExceeded {
		t.Fatalf("third connection must be closed, got %v", err)
	}
}

func TestSingleConnectServesTwoExchanges(t *testing.T) {
	log := &bytes.Buffer{}
	addr, st := startServer(t, log)
	st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_second"), Kind: "login", ExpiresAt: time.Now().Add(time.Minute)})
	c := dial(t, addr, []byte("k2"))
	for i, tok := range []string{"p49_e2e", "p49_second"} {
		c.sid = uint32(100 + i)
		c.seq = 1
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("alice"), Port: []byte("vty" + string(rune('0'+i))), Data: []byte(tok)}.Encode(), wire.FlagSingleConnect)
		_, body := c.recv(t)
		if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
			t.Fatalf("exchange %d: %+v", i, r)
		}
	}
}
```

- [ ] **Step 5: Run to verify failure**

Run: `go test ./internal/daemon/server -v`
Expected: FAIL, package does not exist.

- [ ] **Step 6: Implement the connection handler**

`internal/daemon/server/conn.go`:
```go
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type conn struct {
	d        Deps
	c        net.Conn
	src      netip.Addr
	dev      admission.Resolved
	keys     keyring.Set
	version  int // 0 until the first packet validates
	sessions map[uint32]*authen.Session
}

func (s *conn) unvalidated(h wire.Header, body []byte, diag string, version int) {
	sum := sha256.Sum256(body)
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated, Unvalidated: &decision.Unvalidated{
		Source: s.src.String(), Diagnosis: diag, KeyRef: s.dev.KeyRef, Version: version,
		Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length, BodySHA256: hex.EncodeToString(sum[:])}})
	s.d.Metrics.Unvalidated.WithLabelValues(diag).Inc()
}

func (s *conn) serve(ctx context.Context) {
	defer s.c.Close()
	for {
		s.c.SetReadDeadline(s.d.Now().Add(s.d.IdleTimeout))
		hb := make([]byte, wire.HeaderLen)
		if _, err := io.ReadFull(s.c, hb); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			s.d.Metrics.Connections.WithLabelValues("idle_closed").Inc()
			return
		}
		h, _ := wire.DecodeHeader(hb)

		// Unadmitted source: read nothing more, record the header, close.
		if s.dev.KeyRef == "" {
			s.unvalidated(h, nil, "unadmitted_source", 0)
			time.Sleep(s.d.Limits.Malformed(s.src))
			return
		}
		if err := h.Validate(); err != nil {
			diag := string(keyring.DiagNotTACACS)
			if errors.Is(err, wire.ErrUnencrypted) {
				diag = string(keyring.DiagUnencrypted)
			}
			s.unvalidated(h, nil, diag, 0)
			time.Sleep(s.d.Limits.Malformed(s.src))
			return
		}
		obf := make([]byte, h.Length)
		if _, err := io.ReadFull(s.c, obf); err != nil {
			return
		}

		var body []byte
		if s.version == 0 {
			r := s.keys.Resolve(h, obf)
			switch r.Diagnosis {
			case keyring.DiagValidated:
				s.version = r.Version
				body = r.Body
				s.d.Metrics.KeyValidations.WithLabelValues(s.keys.Ref, itoa(r.Version), "validated").Inc()
			default:
				s.unvalidated(h, obf, string(r.Diagnosis), r.Version)
				s.d.Metrics.KeyValidations.WithLabelValues(s.keys.Ref, itoa(r.Version), string(r.Diagnosis)).Inc()
				time.Sleep(s.d.Limits.Malformed(s.src))
				return
			}
		} else {
			body = wire.Obfuscate(h, s.keys.Secret(s.version), obf)
			if !keyring.Validates(h, body) {
				s.unvalidated(h, obf, "malformed_after_validation", s.version)
				time.Sleep(s.d.Limits.Malformed(s.src))
				return
			}
		}

		replyBody, replyType, done := s.dispatch(ctx, h, body)
		if replyBody != nil {
			rh := wire.Header{MajorVersion: h.MajorVersion, MinorVersion: h.MinorVersion, Type: replyType, SeqNo: h.SeqNo + 1,
				Flags: h.Flags & wire.FlagSingleConnect, SessionID: h.SessionID, Length: uint32(len(replyBody))}
			s.c.SetWriteDeadline(s.d.Now().Add(s.d.IdleTimeout))
			if _, err := s.c.Write(append(rh.Encode(), wire.Obfuscate(rh, s.keys.Secret(s.version), replyBody)...)); err != nil {
				return
			}
		}
		if done && h.Flags&wire.FlagSingleConnect == 0 {
			return
		}
	}
}

// dispatch runs one packet through the right handler and returns the reply body.
// done reports whether the session on this connection has finished.
func (s *conn) dispatch(ctx context.Context, h wire.Header, body []byte) ([]byte, wire.Type, bool) {
	peer := authen.Peer{NAS: s.dev.Device.Name, NASAddr: s.src.String(), Platform: s.dev.Device.Platform}
	start := s.d.Now()
	defer func() { s.d.Metrics.Latency.WithLabelValues(exchange(h.Type)).Observe(s.d.Now().Sub(start).Seconds()) }()
	switch h.Type {
	case wire.TypeAuthen:
		sess, ok := s.sessions[h.SessionID]
		if h.SeqNo == 1 || !ok {
			p, err := wire.DecodeAuthenStart(body)
			if err != nil {
				return nil, h.Type, true
			}
			sess = s.d.Authen.NewSession(peer)
			s.sessions[h.SessionID] = sess
			reply, done := sess.Start(ctx, p)
			if done {
				delete(s.sessions, h.SessionID)
			}
			s.d.Metrics.Requests.WithLabelValues("authen", outcome(reply.Status == wire.AuthenStatusPass)).Inc()
			return reply.Encode(), h.Type, done
		}
		p, err := wire.DecodeAuthenContinue(body)
		if err != nil {
			return nil, h.Type, true
		}
		reply, done := sess.Continue(ctx, p)
		if done {
			delete(s.sessions, h.SessionID)
		}
		if p.Flags&wire.AuthenContinueFlagAbort != 0 {
			return nil, h.Type, true
		}
		return reply.Encode(), h.Type, done
	case wire.TypeAuthor:
		p, err := wire.DecodeAuthorRequest(body)
		if err != nil {
			return nil, h.Type, true
		}
		resp := s.d.Author.Handle(ctx, peer, p)
		s.d.Metrics.Requests.WithLabelValues("author", outcome(resp.Status == wire.AuthorStatusPassAdd || resp.Status == wire.AuthorStatusPassRepl)).Inc()
		return resp.Encode(), h.Type, true
	case wire.TypeAcct:
		p, err := wire.DecodeAcctRequest(body)
		if err != nil {
			return nil, h.Type, true
		}
		return s.d.Acct.Handle(ctx, peer, p).Encode(), h.Type, true
	}
	return nil, h.Type, true
}

func exchange(t wire.Type) string {
	switch t {
	case wire.TypeAuthen:
		return "authen"
	case wire.TypeAuthor:
		return "author"
	}
	return "acct"
}

func outcome(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
```

- [ ] **Step 7: Implement the listener**

`internal/daemon/server/server.go`:
```go
// Package server owns the TCP listener and the per-connection loop: admission,
// key trial, dispatch, and every limit of design §11.
package server

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/store"
)

type Deps struct {
	Admission   *admission.Trie
	Keys        map[string]keyring.Set
	Store       store.Store
	Authen      *authen.Handler
	Author      *author.Handler
	Acct        *acct.Handler
	Limits      *limits.Limiter
	Metrics     *metrics.Metrics
	Log         decision.Emitter
	Now         func() time.Time
	IdleTimeout time.Duration
}

func Serve(ctx context.Context, ln net.Listener, d Deps) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Accept-queue pressure: back off briefly rather than spin; the kernel sheds.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		src := netip.MustParseAddrPort(c.RemoteAddr().String()).Addr().Unmap()
		release, ok := d.Limits.Acquire(src)
		if !ok {
			d.Metrics.Connections.WithLabelValues("refused_cap").Inc()
			c.Close()
			continue
		}
		d.Metrics.Connections.WithLabelValues("open").Inc()
		dev, _ := d.Admission.Lookup(src)
		cc := &conn{d: d, c: c, src: src, dev: dev, keys: d.Keys[dev.KeyRef], sessions: map[uint32]*authen.Session{}}
		go func() {
			defer release()
			defer d.Metrics.Connections.WithLabelValues("open").Dec()
			cc.serve(ctx)
		}()
	}
}
```

- [ ] **Step 8: Run to verify pass**

Run: `go test ./internal/daemon/server -race -v`
Expected: PASS, all six tests. If `TestPerNASCapRefusesThirdConnection` is flaky, the third `Read` must observe a closed connection: check the server closes refused connections before returning to `Accept`.

- [ ] **Step 9: Wire the binary**

`cmd/port49d/main.go`:
```go
// Command port49d is the TACACS+ daemon.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

func main() {
	cfgPath := flag.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "port49d:", err)
		os.Exit(1)
	}
}

func newCtxID() string {
	var b [10]byte
	rand.Read(b[:])
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	inv, err := admission.LoadFile(cfg.InventoryFile)
	if err != nil {
		return err
	}
	trie, err := admission.Build(inv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log := decision.NewJSONLines(os.Stdout)
	st := memory.New(time.Now)
	lim := limits.New(cfg.Limits, time.Now)
	spool, err := acct.NewSpool(cfg.Accounting.SpoolCapacity, cfg.Accounting.SpoolOverflowPath, log, m)
	if err != nil {
		return err
	}
	go spool.Run(ctx)

	var authz author.Authorizer = &author.Lab{SessionAttributes: []string{"priv-lvl=15"}}
	if cfg.Lab != nil {
		authz = &author.Lab{SessionAttributes: cfg.Lab.SessionAttributes, DenyPrefixes: cfg.Lab.DenyPrefixes}
		for _, t := range cfg.Lab.SeedTokens {
			if _, err := st.PutToken(ctx, store.TokenKey{NAS: t.NAS, Username: authen.Canonical(t.Username)},
				store.Token{Secret: []byte(t.Secret), Kind: t.Kind, ExpiresAt: time.Now().Add(cfg.ContextIdleTTL)}); err != nil {
				return err
			}
		}
	}

	deps := server.Deps{Admission: trie, Keys: cfg.Keyring(), Store: st,
		Authen: authen.New(st, log, lim, m, time.Now, newCtxID, cfg.ReceiptTTL, cfg.ContextIdleTTL),
		Author: author.New(st, authz, log, m, time.Now),
		Acct:   acct.New(st, spool, m, time.Now),
		Limits: lim, Metrics: m, Log: log, Now: time.Now, IdleTimeout: cfg.Limits.IdleTimeout}

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		http.ListenAndServe(cfg.MetricsListen, mux)
	}()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n", cfg.Listen, cfg.MetricsListen, len(inv.Devices))
	return server.Serve(ctx, ln, deps)
}
```

- [ ] **Step 10: Build, vet, run the whole suite**

Run: `make build && make vet && make test`
Expected: binary builds; no vet output; every package PASS.

- [ ] **Step 11: Smoke-run the binary against loopback**

Write `/tmp/claude-1000/-home-rwendt-git-port49/dc901c27-fbba-4903-9586-93fc85a7cca6/scratchpad/port49d.yaml`:
```yaml
listen: "127.0.0.1:4949"
metrics_listen: "127.0.0.1:9049"
inventory_file: ./tests/lab/inventory-loopback.yaml
keys:
  lab_key:
    current: {version: 1, secret_env: PORT49_LAB_KEY}
accounting:
  spool_overflow_path: /tmp/claude-1000/-home-rwendt-git-port49/dc901c27-fbba-4903-9586-93fc85a7cca6/scratchpad/acct-overflow.jsonl
lab:
  session_attributes: ["priv-lvl=15"]
  deny_prefixes: ["reload"]
  seed_tokens:
    - {nas: loopback, username: alice, secret: p49_labtoken1, kind: login}
```
and `tests/lab/inventory-loopback.yaml`:
```yaml
devices:
  - {name: loopback, platform: generic, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: lab_key}
```
Run: `PORT49_LAB_KEY=labsecret ./bin/port49d -config /tmp/claude-1000/-home-rwendt-git-port49/dc901c27-fbba-4903-9586-93fc85a7cca6/scratchpad/port49d.yaml &` then `curl -s 127.0.0.1:9049/metrics | grep port49_connections`
Expected: stderr line `listening on 127.0.0.1:4949`; metrics endpoint answers. Kill the background process afterward.

- [ ] **Step 12: Commit**

```bash
git add cmd internal/config internal/daemon/server tests/lab/inventory-loopback.yaml
git commit -m "feat(port49d): config, connection loop with key trial and limits, listener, binary"
```

---

### Task 15: Containerlab harness and the lab register tests

**Files:**
- Create: `tests/lab/README.md`, `tests/lab/topologies/eos.clab.yml`, `tests/lab/topologies/vjunos.clab.yml`, `tests/lab/configs/eos-startup.cfg`, `tests/lab/configs/vjunos-startup.conf`, `tests/lab/inventory-lab.yaml`, `tests/lab/port49d-lab.yaml`, `tests/lab/harness_test.go`, `tests/lab/register_test.go`, `tests/lab/results/.gitkeep`
- All Go files: `//go:build lab`

**Interfaces:**
- Consumes: the built `bin/port49d`; SSH via `golang.org/x/crypto/ssh`; `tcpdump` inside the containerlab host namespace for captures.
- Produces: `tests/lab/results/L<N>-<platform>.md`, one per closed entry, in the format spec §15 rule 3 requires: platform, image version, observation, pointer to the capture in `tests/lab/captures/` (git-ignored; the results note quotes the relevant bytes).

**Prerequisites (Ryan):**

1. **containerlab** — v0.79.0 on both PCs (lab PC 2026-09-07, main PC 2026-09-15), via the
   official installer
   (`curl -fsSL https://get.containerlab.dev -o /tmp/clab-install.sh && sudo bash /tmp/clab-install.sh --verify-checksum`;
   it checksum-verifies the release `.deb`), followed by `sudo usermod -aG clab_admins $USER`
   and a new login shell. Upgrade with `containerlab version upgrade`. On any *other* machine,
   redo this — and the subnet check below, whose answer is per-machine.
2. **Docker running**, with the user in `docker` and `clab_admins`. On WSL2 prefer Docker
   installed natively in the distro over Docker Desktop: containerlab drives network namespaces
   directly. Verified working on this PC (Docker 29.1.3, native, systemd, cgroups v2).
3. **A free management subnet — check before you deploy, it is machine-specific.** The
   topologies below are written against `172.100.100.0/24`, *not* containerlab's `172.20.20.0/24`
   default, because on this PC an idle compose network (`thecape_default`) already claims
   `172.20.0.0/16` and the deploy fails with `Requested subnet(s) ... overlap an existing Docker
   network`. Deleting that network does not hold — compose recreates it on the same subnet — so
   the lab moves instead. On the main PC the same check ran 2026-09-15 and `172.100.100.0/24`
   is free there too (Docker holds `172.17.0.0/16` and `172.18.0.0/16`; the host routes
   `172.25.112.0/20`). On any machine, list what is taken first and pick a subnet that is not:

   ```sh
   for n in $(docker network ls --format '{{.Name}}'); do
     printf '%-24s %s\n' "$n" "$(docker network inspect "$n" \
       --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}')"
   done
   ip -4 route | awk '{print $1}'   # also avoid anything the host already routes
   ```

   If the answer differs from `172.100.100.0/24`, it changes in **eight files of this task, which
   must all agree**: `topologies/eos.clab.yml`, `topologies/vjunos.clab.yml`, and
   `topologies/vsrx.clab.yml` (`ipv4-subnet` and `mgmt-ipv4`), both startup configs (`tacacs-server host` for EOS, `tacplus-server` for
   Junos), `inventory-lab.yaml` (device addresses and the `cidr` match), `port49d-lab.yaml`
   (`listen`), and the platform table in `harness_test.go`. `grep -rn '172\.100\.100\.' tests/lab/`
   should find them all and nothing else. Note that the address in the startup configs and in
   `listen` is the subnet's **`.1` gateway** — the host namespace, where `port49d` runs; the
   device reaches it across the clab bridge. Smoke-tested on this PC with a throwaway
   `linux`-kind node: the device container reached a host listener at the bridge `.1` over both
   ICMP and TCP.
4. **Device images — on hand as of 2026-09-15.** The source of truth is Google Drive,
   `My Drive/Network Images`; on WSL the streaming drive is not automounted, so
   `sudo mount -t drvfs G: /mnt/g` first (a line `G: /mnt/g drvfs defaults 0 0` in `/etc/fstab`
   makes it stick). Build from a **local copy**, never from the Drive mount — vrnetlab reads
   the disk repeatedly and drvfs is slow. On Ryan's main PC the full set is already copied to
   `/mnt/c/Users/rhwen/Network Images/` (sizes verified against Drive 2026-09-15); on any other
   machine, copy the three this task needs from Drive to local storage first. **Everything in the folder is a VM disk built with vrnetlab**
   (`git clone https://github.com/srl-labs/vrnetlab`; KVM required, and `/dev/kvm` is present
   on both PCs). The Arista platform is therefore vEOS, a VM like the Junos ones. cEOS would
   be simpler — a native container, no KVM, boots in seconds — but the download needs an
   arista.com account, which Ryan does not have, so it is an optional swap, not the plan.

   | File | containerlab kind | vrnetlab dir | Used by |
   |---|---|---|---|
   | `veos-4.32.2F/hda.qcow2` + `cdrom.iso` | `arista_veos` | `veos` | this task, `arista_eos` |
   | cEOS tarball, if ever obtained | `ceos` | none — `docker import` | optional swap for the row above |
   | `vJunos-router-23.4R2-S2.1.qcow2` | `juniper_vjunosrouter` | `vjunosrouter` | this task, `juniper_junos` |
   | `junos-vsrx3-x86-64-21.4R3.15.qcow2` | `juniper_vsrx` | `vsrx` | this task, `juniper_junos` — the platform L11 was measured on, at the spec's own `srx_unpatched` example version |
   | `junos-vsrx3-x86-64-23.4R1.9.qcow2` | `juniper_vsrx` | `vsrx` | plan 5, projection across Junos versions |
   | `vJunosEvolved-23.4R2-S2.1.qcow2` | `juniper_vjunosevolved` | `vjunosevolved` | plan 5 |
   | `nexus9300v64.10.4.2.F.qcow2` | `cisco_n9kv` | `n9kv` | plan 3, NX-API (L7) |
   | `cat9kv-prd-17.12.01prd9.qcow2` | `cisco_cat9kv` | `cat9kv` | plan 3, IOS-XE `$enab15$` (L3) |
   | `c8000v-universalk9_8G_serial.17.13.01a.qcow2` | `cisco_c8000v` | `c8000v` | plan 3, IOS-XE |
   | `xrv9k-fullk9-x-7.11.1.qcow2` | `cisco_xrv9k` | `xrv9k` | later |
   | `asav9-20-2-2.qcow2`, `paloalto-10.1.6.qcow2` | `cisco_asav`, `paloalto_panos` | `asav`, `pan` | later |
   | `veos-4.29.2F/` | `arista_veos` | `veos` | spare older EOS |

   Build steps for the three this task uses:
   - **vEOS.** vrnetlab's `veos` build globs Arista's file names, so copy `hda.qcow2` to
     `vrnetlab/veos/vEOS-lab-4.32.2F.qcow2` and `cdrom.iso` to
     `vrnetlab/veos/Aboot-veos-serial-8.0.2.iso` (any `Aboot-veos-serial-*.iso` name is
     accepted; the ISO is the Aboot loader the VM needs), then `make` in `vrnetlab/veos`.
     With a cEOS tarball instead, `docker import` it as `ceos:4.32.2F` and switch the `kind:`
     and `image:` lines in `eos.clab.yml` to the values in its comment; the startup config is
     the same EOS CLI either way.
   - **vJunos-router.** `cp vJunos-router-23.4R2-S2.1.qcow2 vrnetlab/vjunosrouter/ && make -C vrnetlab/vjunosrouter`.
   - **vSRX.** `cp junos-vsrx3-x86-64-21.4R3.15.qcow2 vrnetlab/vsrx/ && make -C vrnetlab/vsrx`.

   After each `make`, read the tag off `docker images`. vrnetlab renamed its images from
   `vrnetlab/vr-<kind>` to `vrnetlab/<vendor>_<kind>` in 2024 and the topologies below use the
   new names; if a checkout produced the old form, edit the `image:` line to match. The lab
   tasks skip any platform whose image is absent, so one built image is enough to start. All
   three are VMs and take several minutes to boot on first deploy; the harness waits up to six.

- [ ] **Step 1: Write the lab README**

`tests/lab/README.md`:
```markdown
# Lab harness

Runs `port49d` against real network OS images in containerlab and closes lab register
entries (policy engine spec §15). Nothing here runs under `go test ./...`; it needs the
`lab` build tag: `make lab`.

## Setup

1. containerlab: `bash -c "$(curl -sL https://get.containerlab.dev)"`, and Docker running.
2. **Check the management subnet is free on *this* machine before deploying.** These topologies
   use `172.100.100.0/24` rather than containerlab's `172.20.20.0/24` default, because that
   default collided with an existing Docker network on the machine they were written on. The
   collision is per-machine, so re-check on any new one: list the taken subnets with
   `docker network ls --format '{{.Name}}'` piped through
   `docker network inspect <n> --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'`, and check
   `ip -4 route` too. A clash fails the deploy with `Requested subnet(s) ... overlap an existing
   Docker network`. To move the lab, change the address in all eight files that carry it —
   `grep -rn '172\.100\.100\.' .` finds them — keeping `port49d`'s `listen` and the device
   configs' server address on the subnet's `.1` gateway.
3. Images: the source is Google Drive `My Drive/Network Images` (on WSL:
   `sudo mount -t drvfs G: /mnt/g`); build from a local copy, not the mount (on the main PC:
   `/mnt/c/Users/rhwen/Network Images/`). All are VM disks built with vrnetlab
   (`git clone https://github.com/srl-labs/vrnetlab`; KVM required). Any subset works and an
   absent image skips its platform:
   - vEOS 4.32.2F: copy `veos-4.32.2F/hda.qcow2` to `vrnetlab/veos/vEOS-lab-4.32.2F.qcow2` and
     `cdrom.iso` to `vrnetlab/veos/Aboot-veos-serial-8.0.2.iso`, then `make -C vrnetlab/veos`.
     (A cEOS tarball, which needs an arista.com account, would instead be `docker import`ed
     as `ceos:4.32.2F` with the `kind:`/`image:` in `topologies/eos.clab.yml` changed per its
     comment.)
   - vJunos-router 23.4R2-S2.1: copy the qcow2 into `vrnetlab/vjunosrouter`, `make` there.
   - vSRX 21.4R3.15: copy the qcow2 into `vrnetlab/vsrx`, `make` there.
   Check `docker images` for the tag each build produced and match the `image:` lines in
   `topologies/`.
4. `export PORT49_LAB_KEY=labsecret`
5. `make build && make lab`

## What runs

- `harness_test.go` deploys one topology per available platform: the device plus `port49d`
  on the host namespace, reachable from the device at the host's clab bridge address.
- `register_test.go` has one test per open register entry this plan closes:
  L1, L2, L5, L6, L8, L10. Each writes `results/L<N>-<platform>.md` when it passes.

## Captures

`tcpdump -i <clab bridge> port 49 -w captures/<test>.pcap` runs around each test.
Captures are git-ignored; the results note quotes the fields that matter.
```

- [ ] **Step 2: Write the topologies and startup configs**

`tests/lab/topologies/eos.clab.yml`:
```yaml
name: port49-eos
topology:
  nodes:
    leaf1:
      kind: arista_veos             # with a cEOS tarball instead: kind ceos, image ceos:4.32.2F
      image: vrnetlab/arista_veos:4.32.2F
      startup-config: ../configs/eos-startup.cfg
      mgmt-ipv4: 172.100.100.11
mgmt:
  network: port49-lab
  ipv4-subnet: 172.100.100.0/24
```

`tests/lab/configs/eos-startup.cfg`:
```
hostname leaf1
username breakglass privilege 15 secret 0 breakglass-only
!
tacacs-server host 172.100.100.1 key 0 labsecret
!
aaa group server tacacs+ port49
   server 172.100.100.1
!
aaa authentication login default group port49 local
aaa authentication enable default group port49 local
aaa authorization exec default group port49 local
aaa authorization commands all default group port49 local
aaa accounting exec default start-stop group port49
aaa accounting commands all default start-stop group port49
!
management api http-commands
   no shutdown
!
management ssh
   idle-timeout 60
```

`tests/lab/topologies/vjunos.clab.yml`:
```yaml
name: port49-vjunos
topology:
  nodes:
    srx1:
      kind: juniper_vjunosrouter
      image: vrnetlab/juniper_vjunos-router:23.4R2-S2.1
      startup-config: ../configs/vjunos-startup.conf
      mgmt-ipv4: 172.100.100.21
mgmt:
  network: port49-lab
  ipv4-subnet: 172.100.100.0/24
```

`tests/lab/topologies/vsrx.clab.yml` (the SRX is the platform the L11 measurements came from;
it shares the Junos startup config):
```yaml
name: port49-vsrx
topology:
  nodes:
    vsrx1:
      kind: juniper_vsrx
      image: vrnetlab/juniper_vsrx:21.4R3.15
      startup-config: ../configs/vjunos-startup.conf
      mgmt-ipv4: 172.100.100.22
mgmt:
  network: port49-lab
  ipv4-subnet: 172.100.100.0/24
```

`tests/lab/configs/vjunos-startup.conf` (shared by both Junos topologies):
```
system {
    host-name srx1;
    authentication-order tacplus;
    tacplus-server {
        172.100.100.1 secret "labsecret";
    }
    login {
        user remote {
            uid 2001;
            class p49-readonly;
        }
        user breakglass {
            uid 2002;
            class super-user;
            authentication {
                plain-text-password-value "breakglass-only";
            }
        }
        class p49-readonly {
            permissions [ view view-configuration ];
        }
    }
    accounting {
        events [ login change-log interactive-commands ];
        destination {
            tacplus {
                server {
                    172.100.100.1 secret "labsecret";
                }
            }
        }
    }
}
```

`tests/lab/inventory-lab.yaml`:
```yaml
devices:
  - {name: leaf1, platform: arista_eos,    addresses: [172.100.100.11]}
  - {name: srx1,  platform: juniper_junos, addresses: [172.100.100.21]}
  - {name: vsrx1, platform: juniper_junos, addresses: [172.100.100.22]}
key_groups:
  - {match: {cidr: 172.100.100.0/24}, key_ref: lab_key}
```

`tests/lab/port49d-lab.yaml`:
```yaml
listen: "172.100.100.1:49"
metrics_listen: "127.0.0.1:9049"
inventory_file: tests/lab/inventory-lab.yaml
keys:
  lab_key:
    current: {version: 1, secret_env: PORT49_LAB_KEY}
accounting:
  spool_overflow_path: /tmp/port49-lab-acct-overflow.jsonl
lab:
  session_attributes: ["priv-lvl=15"]
  deny_prefixes: ["reload", "request system reboot"]
  seed_tokens:
    - {nas: leaf1, username: alice, secret: p49_labtoken1, kind: login}
    - {nas: leaf1, username: alice, secret: p49_labtoken2, kind: login}
    - {nas: leaf1, username: alice, secret: p49_labtoken3, kind: login}
    - {nas: srx1,  username: alice, secret: p49_labtoken1, kind: login}
    - {nas: srx1,  username: alice, secret: p49_labtoken2, kind: login}
    - {nas: vsrx1, username: alice, secret: p49_labtoken1, kind: login}
    - {nas: vsrx1, username: alice, secret: p49_labtoken2, kind: login}
    - {nas: leaf1, username: longpw, secret: p49_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789, kind: login}
    - {nas: srx1,  username: longpw, secret: p49_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789, kind: login}
    - {nas: vsrx1, username: longpw, secret: p49_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789, kind: login}
```

- [ ] **Step 3: Write the harness**

`tests/lab/harness_test.go`:
```go
//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type platform struct {
	name, topo, addr, node string
}

var platforms = []platform{
	{"arista_eos", "topologies/eos.clab.yml", "172.100.100.11", "leaf1"},
	{"juniper_junos", "topologies/vjunos.clab.yml", "172.100.100.21", "srx1"},
	{"juniper_junos-vsrx", "topologies/vsrx.clab.yml", "172.100.100.22", "vsrx1"},
}

type lab struct {
	t       *testing.T
	p       platform
	daemon  *exec.Cmd
	logPath string
	capPath string
	tcpdump *exec.Cmd
}

func imagePresent(topo string) bool {
	raw, _ := os.ReadFile(topo)
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "image:") {
			img := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "image:"))
			return exec.Command("docker", "image", "inspect", img).Run() == nil
		}
	}
	return false
}

func deploy(t *testing.T, p platform) *lab {
	t.Helper()
	if !imagePresent(p.topo) {
		t.Skipf("%s: image not present", p.name)
	}
	if out, err := exec.Command("sudo", "containerlab", "deploy", "--reconfigure", "-t", p.topo).CombinedOutput(); err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("sudo", "containerlab", "destroy", "-t", p.topo).Run() })

	l := &lab{t: t, p: p, logPath: filepath.Join(t.TempDir(), "decisions.jsonl")}
	logf, _ := os.Create(l.logPath)
	l.daemon = exec.Command("../../bin/port49d", "-config", "port49d-lab.yaml")
	l.daemon.Dir = "../.."
	l.daemon.Stdout = logf
	l.daemon.Stderr = os.Stderr
	l.daemon.Env = append(os.Environ(), "PORT49_LAB_KEY=labsecret")
	if err := l.daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.daemon.Process.Kill(); logf.Close() })
	waitForDevice(t, p.addr)
	return l
}

func waitForDevice(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		if c, err := ssh.Dial("tcp", addr+":22", &ssh.ClientConfig{User: "probe", Auth: []ssh.AuthMethod{ssh.Password("x")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second}); err == nil {
			c.Close()
			return
		} else if strings.Contains(err.Error(), "unable to authenticate") {
			return // SSH is up; auth failure is expected for the probe user
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("%s never came up", addr)
}

func (l *lab) capture(name string) func() {
	os.MkdirAll("captures", 0o755)
	l.capPath = filepath.Join("captures", fmt.Sprintf("%s-%s.pcap", name, l.p.name))
	l.tcpdump = exec.Command("sudo", "tcpdump", "-i", "any", "-w", l.capPath, "tcp port 49")
	l.tcpdump.Start()
	time.Sleep(time.Second)
	return func() { l.tcpdump.Process.Signal(os.Interrupt); l.tcpdump.Wait() }
}

// login opens an SSH session with the given password (a seeded token) and runs
// commands, returning combined output per command.
func (l *lab) login(user, password string, commands ...string) ([]string, error) {
	c, err := ssh.Dial("tcp", l.p.addr+":22", &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var outs []string
	for _, cmd := range commands {
		s, err := c.NewSession()
		if err != nil {
			return outs, err
		}
		var buf bytes.Buffer
		s.Stdout, s.Stderr = &buf, &buf
		_ = s.Run(cmd)
		outs = append(outs, buf.String())
		s.Close()
	}
	return outs, nil
}

func (l *lab) records() []map[string]any {
	f, _ := os.Open(l.logPath)
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func (l *lab) result(entry, observation string) {
	os.MkdirAll("results", 0o755)
	path := filepath.Join("results", fmt.Sprintf("%s-%s.md", entry, l.p.name))
	body := fmt.Sprintf("# %s — %s\n\n- Date: %s\n- Platform: %s (%s)\n- Capture: `%s`\n\n## Observation\n\n%s\n",
		entry, l.p.name, time.Now().UTC().Format("2006-01-02"), l.p.name, l.p.node, l.capPath, observation)
	os.WriteFile(path, []byte(body), 0o644)
}

func TestLoginRoundTrip(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			l := deploy(t, p)
			stop := l.capture("login")
			defer stop()
			out, err := l.login("alice", "p49_labtoken1", "show version")
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			if len(out) == 0 || len(out[0]) == 0 {
				t.Fatal("no output from show version")
			}
			var sawRedeem, sawSession bool
			for _, r := range l.records() {
				sawRedeem = sawRedeem || r["event"] == "redeem" && r["reason"] == "token_redeemed"
				sawSession = sawSession || r["event"] == "authorize_session"
			}
			if !sawRedeem || !sawSession {
				t.Fatalf("redeem=%v session=%v", sawRedeem, sawSession)
			}
		})
	}
}
```

- [ ] **Step 4: Write the register tests**

`tests/lab/register_test.go`:
```go
//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L1: what the port field contains per platform (SSH transport in this plan; eAPI/NX-API in plan 3).
func TestL1PortField(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			l := deploy(t, p)
			stop := l.capture("L1")
			defer stop()
			if _, err := l.login("alice", "p49_labtoken1", "show version"); err != nil {
				t.Fatal(err)
			}
			if _, err := l.login("alice", "p49_labtoken2", "show version"); err != nil {
				t.Fatal(err)
			}
			var ports []string
			for _, r := range l.records() {
				if r["event"] == "redeem" {
					ports = append(ports, r["session"].(map[string]any)["port"].(string))
				}
			}
			if len(ports) < 2 {
				t.Fatalf("ports %v", ports)
			}
			l.result("L1", fmt.Sprintf("Two concurrent-ish SSH logins produced `port` values %q and %q over SSH. "+
				"Unique per session: %v. (eAPI/NX-API transports: plan 3.)", ports[0], ports[1], ports[0] != ports[1]))
		})
	}
}

// L2: is server_msg on an authorization REPLY displayed, and at what length does it truncate?
func TestL2ServerMsgDisplayed(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			if strings.HasPrefix(p.name, "juniper_junos") {
				t.Skip("session-only platform: no per-command REPLY (spec decision 21)")
			}
			l := deploy(t, p)
			stop := l.capture("L2")
			defer stop()
			out, err := l.login("alice", "p49_labtoken1", "reload")
			if err != nil {
				t.Fatal(err)
			}
			shown := strings.Contains(out[0], "port49: denied by lab_deny")
			l.result("L2", fmt.Sprintf("Command `reload` denied with server_msg. Displayed to the operator: %v.\n\nDevice output:\n\n```\n%s\n```", shown, out[0]))
			if !shown {
				t.Logf("server_msg not shown; recorded as the observation")
			}
		})
	}
}

// L5: which platforms send accounting WATCHDOG, how often, with or without arguments.
func TestL5Watchdog(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			l := deploy(t, p)
			stop := l.capture("L5")
			defer stop()
			go l.login("alice", "p49_labtoken1", "show version", "sleep 120")
			time.Sleep(150 * time.Second)
			n := 0
			withArgs := 0
			for _, r := range l.records() {
				if r["event"] == "account" && r["flags"] == "watchdog" {
					n++
					if raw := r["record"].(map[string]any)["raw"].([]any); len(raw) > 2 {
						withArgs++
					}
				}
			}
			l.result("L5", fmt.Sprintf("Over a 150s idle-then-active session: %d WATCHDOG records, %d carrying arguments.", n, withArgs))
		})
	}
}

// L6: how reliably and how late exec START and STOP arrive.
func TestL6AccountingLatency(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			l := deploy(t, p)
			stop := l.capture("L6")
			defer stop()
			t0 := time.Now()
			if _, err := l.login("alice", "p49_labtoken1", "show version"); err != nil {
				t.Fatal(err)
			}
			t1 := time.Now()
			time.Sleep(10 * time.Second)
			var start, stopRec time.Time
			for _, r := range l.records() {
				if r["event"] != "account" {
					continue
				}
				ts, _ := time.Parse("2006-01-02T15:04:05.000Z07:00", r["ts"].(string))
				switch r["flags"] {
				case "start":
					if start.IsZero() {
						start = ts
					}
				case "stop":
					if raw := r["record"].(map[string]any)["vector"]; raw == nil {
						stopRec = ts
					}
				}
			}
			l.result("L6", fmt.Sprintf("Login at %s, logout at %s. Exec START arrived %v after login; exec STOP arrived %v after logout. Missing START: %v; missing STOP: %v.",
				t0.Format(time.RFC3339Nano), t1.Format(time.RFC3339Nano), start.Sub(t0), stopRec.Sub(t1), start.IsZero(), stopRec.IsZero()))
		})
	}
}

// L8: maximum password length accepted at the interactive prompt (SSH here) — the 30-character token must clear it.
func TestL8PasswordLength(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			l := deploy(t, p)
			stop := l.capture("L8")
			defer stop()
			long := "p49_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789"
			_, err := l.login("longpw", long, "show version")
			var presented string
			for _, r := range l.records() {
				if r["event"] == "redeem" && r["principal"] == "" {
					presented = r["reason"].(string)
				}
			}
			l.result("L8", fmt.Sprintf("A %d-character password over SSH: login error=%v; daemon saw reason %q. "+
				"If token_not_found, the device truncated before sending (compare capture data_len).", len(long), err, presented))
		})
	}
}

// L10: does `service` arrive as shell or junos-exec, and the exact spelling of every attribute.
func TestL10ServiceAndAttributeSpellings(t *testing.T) {
	for _, p := range platforms {
		t.Run(p.name, func(t *testing.T) {
			l := deploy(t, p)
			stop := l.capture("L10")
			defer stop()
			l.login("alice", "p49_labtoken1", "show version")
			seen := map[string]bool{}
			for _, r := range l.records() {
				if r["request"] == nil {
					continue
				}
				for _, a := range r["request"].(map[string]any)["raw"].([]any) {
					seen[strings.SplitN(a.(string), "=", 2)[0]] = true
				}
			}
			var keys []string
			for k := range seen {
				keys = append(keys, k)
			}
			l.result("L10", fmt.Sprintf("Attribute names seen on authorization requests: %s.", strings.Join(keys, ", ")))
		})
	}
}
```

- [ ] **Step 5: Add the SSH dependency and verify the lab package compiles**

Run: `go get golang.org/x/crypto@v0.26.0 && go vet -tags lab ./tests/lab/...`
Expected: no output. (`go test ./...` without the tag still ignores this package.)

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum tests/lab
git commit -m "test(lab): containerlab harness and lab register tests for L1, L2, L5, L6, L8, L10"
```

- [ ] **Step 7: When containerlab and an image are installed — run the lab**

Run: `export PORT49_LAB_KEY=labsecret && make build && make lab`
Expected: `TestLoginRoundTrip` passes on every platform whose image is present; each `TestL<N>` writes `tests/lab/results/L<N>-<platform>.md`. Then close the entries in spec §15 by editing each row's Status to `closed — measured <date>; tests/lab/results/L<N>-<platform>.md` per platform, and commit that as `docs: close lab register entries measured in plan 1`.

---

## Self-review

**Spec coverage against design §19 step 1 and the sections it cites**

| Requirement | Task |
|---|---|
| RFC 8907 header, all three exchanges, canonical codecs, fuzzing (design §16 "fuzzing") | 2, 3, 4, 5 |
| Header validation: version, type, odd seq, 4096 ceiling; unencrypted refused; single-connect honored (spec §10) | 2, 14 |
| Key trial by length identity; reply with the validating key; per-connection cache; retired identifies never admits (spec §10) | 6, 14 |
| Admission: file inventory, key groups, three tiers, collision refused, no-group refused (spec §10) | 7 |
| Unvalidated packets: header + source + body hash, never the body; diagnosis buckets (spec §10) | 9, 14 |
| Listener limits: per-NAS cap, malformed backoff, idle timeout, auth-failure delay that never locks (design §11) | 10, 14 |
| Store: match-and-delete in a keyed set, atomic remove-and-receipt, expiry by the store, in-memory implementation (design §8, §12) | 8 |
| Receipt bound to credential hash; retransmission replays; different credential fails; race loser adopts (design §8, §12) | 8, 11 |
| ASCII / PAP / CHAP; CHAP re-prompt fails (design §8, §14) | 11 |
| Username canonicalization as a key transformation (spec §2) | 11 |
| Session authorization with attributes; command authorization; `context_missing` distinct; username mismatch invalidates; `service_unsupported`; `server_msg` on denial (spec §5.2, §5.3) | 12 |
| Accounting: START/WATCHDOG/STOP, `<cr>` strip, raw + vector, attribution, SUCCESS after spool, ERROR only when full, spool depth/drops metrics (spec §5.8) | 13 |
| Decision log: one JSON line per record, closed reason vocabulary, no credentials (spec §5.7) | 9 |
| Metrics with bounded labels, no device identity (design §15) | 10 |
| Config in snake_case, secrets from the environment | 14 |
| Lab register L1, L2, L5, L6, L8, L10 (spec §15; design §19 step 1) | 15 |

**Deferred to plan 2, and said so in the task that would otherwise cover it:** device tag and `device_mismatch`; encryption at rest; blob, indexes, idempotency records; enable-token lookup through context; `task_id` binding and `closing`; redaction (plan 5, adapters). Plan 3 covers eAPI/NX-API transports for L1 and L7.

**Placeholder scan:** no TBD/TODO; every code step carries the code; no "similar to Task N".

**Type consistency, checked:** `authen.Peer` is the peer type used by `author.Handle` and `acct.Handle`; `store.Token.Kind` strings are `"login"`/`"enable"` in Task 8, 11, and the config seed; `decision.Record.Session.CtxID` empty string is what the acct test reads as `""` for unattributed; `keyring.Set.Secret(version)` returns nil for a retired version, and `conn.serve` only reaches it after `DiagValidated`, so a nil key is impossible on the reply path; `author.ParseArgs` is the single AV-pair parser and `acct` imports it; `limits.Config` is embedded in `config.Config` by value with the same field names.

**Two things an implementer should know:**
- `decision.Record` has custom `MarshalJSON`/`UnmarshalJSON` for the millisecond `ts`; tests in Tasks 9 and 13 assert both directions.
- `TestPerNASCapRefusesThirdConnection` depends on the server closing a refused connection before the client's read; `Serve` does that synchronously before the next `Accept`.

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-09-06-01-protocol-core.md`. Tasks 1–14 run entirely on this machine with Go 1.22. Task 15 compiles now and runs once containerlab and an image are installed.
