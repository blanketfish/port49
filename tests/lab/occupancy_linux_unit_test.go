//go:build lab && linux

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLabInheritedLockIsAdoptedAndExcludesAThird(t *testing.T) {
	if os.Getenv("P49_LOCK_CHILD") == "1" {
		path := os.Getenv("P49_LOCK_PATH")
		if _, ok, err := labInheritedLock(path); !ok || err != nil {
			fmt.Println("CHILD: not adopted:", ok, err)
			os.Exit(3)
		}
		if _, err := labOccupy(path, "third"); err == nil {
			fmt.Println("CHILD: a fresh open took the lock the parent holds")
			os.Exit(4)
		}
		// A process this binary starts must not inherit the lock: a daemon that
		// outlives a timeout would hold the lab under a dead runner's name.
		if out, err := exec.Command("sh", "-c", "test ! -e /proc/self/fd/3 && echo clean").CombinedOutput(); err != nil {
			fmt.Printf("CHILD: the lock descriptor leaked into a grandchild: %v %s\n", err, out)
			os.Exit(5)
		}
		fmt.Println("CHILD: adopted")
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "lab.lock")
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestLabInheritedLockIsAdoptedAndExcludesAThird$")
	cmd.Env = append(os.Environ(), "P49_LOCK_CHILD=1", "P49_LOCK_PATH="+path, "PORT49_LAB_LOCK_FD=3")
	cmd.ExtraFiles = []*os.File{f}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func TestLabInheritedLockRefusesAnotherFile(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "notthelock")
	defer f.Close()
	t.Setenv("PORT49_LAB_LOCK_FD", fmt.Sprint(f.Fd()))
	lock := filepath.Join(t.TempDir(), "lab.lock") // exists, so only the inode tells the files apart
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := labInheritedLock(lock); !ok || err == nil {
		t.Fatalf("a descriptor that is not the lock file must be refused: ok %v err %v", ok, err)
	}
}
