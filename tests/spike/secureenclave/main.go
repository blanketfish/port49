//go:build darwin

// Command secureenclave is plan 9c's spike for L63: can an unsigned port49,
// built with CGO_ENABLED=0, create a Secure Enclave key, find it again from a
// second process and from a rebuilt binary, and sign with it? It is the check
// a Mac user runs (decision 45 ruling 6, gate SE1). From the root of a port49
// checkout, with Go installed, run:
//
//	go run ./tests/spike/secureenclave
//
// and then, for the locked-screen cell (it asks you to lock the screen):
//
//	go run ./tests/spike/secureenclave locked
//
// and report both outputs, with your macOS version and Mac model. Each prints
// `cell <name>: pass` or `cell <name>: fail OSStatus <n> <description>` for
// each cell, and the first ends `SE1: pass` or `SE1: fail`. Neither prints
// key bytes or a signature, and each deletes the keys it made. The calls are
// the backend's own (internal/hwkey/secureenclave/secapi).
//
// The cells, with no arguments:
//   - control: a software P-256 key, not kept, made and signed with by the
//     same calls with no kSecAttrTokenID. It must pass, or the run is invalid:
//     the calls themselves are wrong, and nothing else here means anything.
//   - create-permanent: a Secure Enclave key, kept in the keychain under a
//     label of this run's own.
//   - find: a second process (this program run again) finds that key by its
//     label, as port49's agent would find the key its login made.
//   - sign: a third process signs with it, and the signature verifies.
//   - find-rebuilt: a copy of this program built again with another
//     buildMark (`go build -ldflags=-X main.buildMark=...`, which this program
//     runs and prints), so its code signature differs as a port49 upgrade's
//     does, finds the key and signs with it. Port49 keeps the issued key
//     across sign-ins, so a key an upgrade cannot see would be leaked and
//     remade at every upgrade.
//   - held-after-delete (an observation, not part of SE1): a key reference
//     held while the key's keychain item is deleted, as an agent holds one
//     when its key is removed under it: does it still sign?
//   - create-ephemeral: a Secure Enclave key not kept, signed with in this
//     process (the fallback ruling 6 would weigh if keeping a key is refused).
//
// SE1 passes when create-permanent, find, sign and find-rebuilt pass.
//
// With `locked`: a key is made, you lock the screen, and while it is locked a
// held reference signs (locked-sign-held, as the agent's refresh signs) and a
// new process finds and signs (locked-find-sign). The keys are made
// kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly so both should pass.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/hwkey/secureenclave/secapi"
)

// buildMark tells one build of this program from another: find-rebuilt sets
// it with -ldflags -X, so the rebuilt binary, and its code signature, differ.
var buildMark = "first"

// spikePackage is this program, which find-rebuilt builds again.
const spikePackage = "github.com/rhwendt/port49/tests/spike/secureenclave"

// lockWait is how long the locked cells wait for the screen to be locked.
const lockWait = 45 * time.Second

func main() {
	if err := secapi.Load(); err != nil {
		fmt.Println("cell load: fail", err)
		fmt.Println("SE1: fail")
		os.Exit(1)
	}
	// A cell run as a second process: `find LABEL` or `sign LABEL`.
	if len(os.Args) == 3 {
		var err error
		switch os.Args[1] {
		case "find":
			err = find(os.Args[2])
		case "sign":
			err = signWith(os.Args[2])
		default:
			err = fmt.Errorf("no cell %q", os.Args[1])
		}
		report(os.Args[1], err)
		if err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "locked" {
		os.Exit(runLocked())
	}
	if len(os.Args) != 1 {
		fmt.Println("usage: go run ./tests/spike/secureenclave [locked]")
		os.Exit(2)
	}
	os.Exit(runAll())
}

// newLabel is a label of this run's own.
func newLabel() (string, error) {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	return "port49-l63-" + hex.EncodeToString(rnd[:]), nil
}

// cleanup deletes the keys labeled label, and says so when it cannot.
func cleanup(label string) {
	if err := secapi.DeleteKeys(label, true); err != nil && !secapi.NotFound(err) {
		fmt.Printf("cleanup: the key labeled %s was not deleted: %v; report this line with the output\n", label, err)
	}
}

// runAll runs every cell in order and reads gate SE1.
func runAll() int {
	label, err := newLabel()
	if err != nil {
		fmt.Println("random:", err)
		return 1
	}
	fmt.Println("build", buildMark)

	control := report("control", control())
	if !control {
		fmt.Println("the control failed: the calls themselves are wrong, so this run is INVALID; report it as such")
		fmt.Println("SE1: fail")
		return 1
	}
	created := report("create-permanent", createPermanent(label))
	self, err := os.Executable()
	if err != nil {
		report("find", err)
		created = false
	}
	found := created && again(self, "find", "find", label)
	signed := created && again(self, "sign", "sign", label)
	rebuilt := created && fromRebuild(self, label)
	if created {
		heldAfterDelete(label)
		// The key is removed whatever the cells said.
		cleanup(label)
	}
	report("create-ephemeral", createEphemeral())
	if created && found && signed && rebuilt {
		fmt.Println("SE1: pass")
		return 0
	}
	fmt.Println("SE1: fail")
	return 1
}

// fromRebuild is the cell find-rebuilt: this program built again with another
// buildMark, and so another code signature, finds the key labeled label and
// signs with it.
func fromRebuild(self, label string) bool {
	dir, err := os.MkdirTemp("", "port49-l63-")
	if err != nil {
		return report("find-rebuilt", err)
	}
	defer os.RemoveAll(dir)
	exe := filepath.Join(dir, "secureenclave-rebuilt")
	args := []string{"build", "-ldflags=-X main.buildMark=rebuilt-" + label, "-o", exe, spikePackage}
	fmt.Println("running: go", strings.Join(args, " "))
	if out, err := exec.Command("go", args...).CombinedOutput(); err != nil {
		return report("find-rebuilt", fmt.Errorf("the rebuild failed (%v; run from a port49 checkout, with go on "+
			"PATH): %s", err, strings.TrimSpace(string(out))))
	}
	a, errA := fileSum(self)
	b, errB := fileSum(exe)
	if err := errors.Join(errA, errB); err != nil {
		return report("find-rebuilt", err)
	}
	if a == b {
		return report("find-rebuilt", errors.New("the rebuilt copy is this program byte for byte, so the cell "+
			"measures nothing"))
	}
	return again(exe, "sign", "find-rebuilt", label)
}

// fileSum is the SHA-256 of the file at path.
func fileSum(path string) ([32]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// heldAfterDelete is the observation held-after-delete: a reference to the
// key labeled label, held while every key with that label is deleted, then
// asked to sign. Either answer is a measurement; it is not part of SE1.
func heldAfterDelete(label string) {
	k, err := only(label)
	if err != nil {
		fmt.Printf("observe held-after-delete: not run (%v)\n", err)
		return
	}
	defer secapi.Release(k)
	if err := secapi.DeleteKeys(label, true); err != nil {
		fmt.Printf("observe held-after-delete: not run (the delete: %v)\n", err)
		return
	}
	if err := signAndVerify(k); err != nil {
		fmt.Printf("observe held-after-delete: refused (%v)\n", err)
		return
	}
	fmt.Println("observe held-after-delete: signs")
}

// runLocked is the locked cells: a key is made, the user locks the screen,
// and while it is locked a held reference and a new process each sign.
func runLocked() int {
	label, err := newLabel()
	if err != nil {
		fmt.Println("random:", err)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Println("cell locked: fail", err)
		return 1
	}
	k, err := secapi.CreateKey(label, true, true)
	if !report("locked-create", err) {
		return 1
	}
	defer cleanup(label)
	defer secapi.Release(k)
	fmt.Printf("lock the screen now (Control-Command-Q) and leave it locked; the cells run in %v, and you may "+
		"unlock it a minute from now\n", lockWait)
	time.Sleep(lockWait)
	held := report("locked-sign-held", signAndVerify(k))
	fresh := again(self, "sign", "locked-find-sign", label)
	if held && fresh {
		return 0
	}
	return 1
}

// report prints a cell's line and says whether it passed.
func report(cell string, err error) bool {
	if err == nil {
		fmt.Printf("cell %s: pass\n", cell)
		return true
	}
	var se *secapi.Error
	if errors.As(err, &se) {
		fmt.Printf("cell %s: fail OSStatus %d %s (%s)\n", cell, se.Code, se.Description, se.Op)
		return false
	}
	fmt.Printf("cell %s: fail %v\n", cell, err)
	return false
}

// again runs cell in a second process, exe (this program, or its rebuilt
// copy), and relays its line as the cell shown.
func again(exe, cell, shown, label string) bool {
	out, err := exec.Command(exe, cell, label).CombinedOutput()
	line := strings.TrimSpace(string(out))
	rest, ok := strings.CutPrefix(line, "cell "+cell+": ")
	if !ok {
		return report(shown, fmt.Errorf("the second process said %q (%v)", line, err))
	}
	fmt.Printf("cell %s: %s\n", shown, rest)
	return err == nil && rest == "pass"
}

// signAndVerify signs a digest with k and checks the signature against k's
// public key. Neither is printed.
func signAndVerify(k secapi.Key) error {
	pub, err := secapi.PublicKey(k)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte("port49 L63"))
	sig, err := secapi.Sign(k, sum[:], crypto.SHA256)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("the signature does not verify")
	}
	return nil
}

func control() error {
	k, err := secapi.CreateKey("port49-l63-control", false, false)
	if err != nil {
		return err
	}
	defer secapi.Release(k)
	return signAndVerify(k)
}

func createPermanent(label string) error {
	k, err := secapi.CreateKey(label, true, true)
	if err != nil {
		return err
	}
	secapi.Release(k)
	return nil
}

func createEphemeral() error {
	k, err := secapi.CreateKey("port49-l63-ephemeral", true, false)
	if err != nil {
		return err
	}
	defer secapi.Release(k)
	return signAndVerify(k)
}

// only is the one Secure Enclave key labeled label.
func only(label string) (secapi.Key, error) {
	keys, err := secapi.FindKeys(label, true)
	if err != nil {
		return 0, err
	}
	if len(keys) != 1 {
		for _, k := range keys {
			secapi.Release(k)
		}
		return 0, fmt.Errorf("%d keys are labeled %s, not one", len(keys), label)
	}
	return keys[0], nil
}

func find(label string) error {
	k, err := only(label)
	if err != nil {
		return err
	}
	defer secapi.Release(k)
	_, err = secapi.PublicKey(k)
	return err
}

func signWith(label string) error {
	k, err := only(label)
	if err != nil {
		return err
	}
	defer secapi.Release(k)
	return signAndVerify(k)
}
