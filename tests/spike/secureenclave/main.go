//go:build darwin

// Command secureenclave is plan 9c's spike for L63: can an unsigned port49,
// built with CGO_ENABLED=0, create a Secure Enclave key, find it again from a
// second process, and sign with it? It is the check a Mac user runs (decision
// 45 ruling 6, gate SE1), with no arguments:
//
//	go run ./tests/spike/secureenclave
//
// It runs every cell in order, printing `cell <name>: pass` or `cell <name>:
// fail OSStatus <n> <description>` for each, then `SE1: pass` or `SE1: fail`.
// It prints no key bytes and no signature, and deletes the key it made. The
// calls are the backend's own (internal/hwkey/secureenclave/secapi).
//
// The cells:
//   - control: a software P-256 key, not kept, made and signed with by the
//     same calls with no kSecAttrTokenID. It must pass, or the run is invalid:
//     the calls themselves are wrong, and nothing else here means anything.
//   - create-permanent: a Secure Enclave key, kept in the keychain under a
//     label of this run's own.
//   - find: a second process (this program run again) finds that key by its
//     label, as port49's agent would find the key its login made.
//   - sign: a third process signs with it, and the signature verifies.
//   - create-ephemeral: a Secure Enclave key not kept, signed with in this
//     process (the fallback ruling 6 would weigh if keeping a key is refused).
//
// SE1 passes when create-permanent, find and sign pass.
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
	"strings"

	"github.com/rhwendt/port49/internal/hwkey/secureenclave/secapi"
)

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
	if len(os.Args) != 1 {
		fmt.Println("usage: go run ./tests/spike/secureenclave  (no arguments)")
		os.Exit(2)
	}
	os.Exit(runAll())
}

// runAll runs every cell in order and reads gate SE1.
func runAll() int {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		fmt.Println("random:", err)
		return 1
	}
	label := "port49-l63-" + hex.EncodeToString(rnd[:])

	control := report("control", control())
	if !control {
		fmt.Println("the control failed: the calls themselves are wrong, so this run is INVALID; report it as such")
		fmt.Println("SE1: fail")
		return 1
	}
	created := report("create-permanent", createPermanent(label))
	found := created && again("find", label)
	signed := created && again("sign", label)
	if created {
		// The key is removed whatever the cells said.
		if err := secapi.DeleteKeys(label, true); err != nil {
			fmt.Printf("cleanup: the key labeled %s was not deleted: %v; remove it with Keychain Access\n", label, err)
		}
	}
	report("create-ephemeral", createEphemeral())
	if created && found && signed {
		fmt.Println("SE1: pass")
		return 0
	}
	fmt.Println("SE1: fail")
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

// again runs cell as a second process of this program and relays its line.
func again(cell, label string) bool {
	exe, err := os.Executable()
	if err != nil {
		return report(cell, err)
	}
	out, err := exec.Command(exe, cell, label).CombinedOutput()
	line := strings.TrimSpace(string(out))
	if !strings.HasPrefix(line, "cell "+cell+": ") {
		return report(cell, fmt.Errorf("the second process said %q (%v)", line, err))
	}
	fmt.Println(line)
	return err == nil && strings.HasSuffix(line, ": pass")
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
