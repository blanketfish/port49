package port49d

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// keyUsage is the one line every refusal to parse prints.
const keyUsage = "usage: port49d key sealing [--id ID] [--dir DIR] [--broker-dir DIR] [--import FILE] " +
	"[--daemon-user USER] [--broker-user USER], or port49d key device NAME [--dir DIR] " +
	"[--device-owner USER] [--device-group GROUP]; a user or group given as a number is both uid and gid"

const (
	defaultSecretsDir = "/etc/port49/secrets"
	defaultKeysDir    = "/etc/port49/keys"
	sealingKeyLen     = 32
	sealingDraws      = 10
)

// keyNameRe is what --id and a device key's name may hold: letters, digits, "-", "_" and "."
// with no leading ".", so neither can reach another directory or name a hidden file.
var keyNameRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)

// keyEnv is what `port49d key` takes from the host, so a test can swap it. A zero field is the
// host's; groups, nil, makes euid and groups the host's as well.
type keyEnv struct {
	rand   io.Reader                           // the key source: crypto/rand
	euid   int                                 // who this runs as
	groups []int                               // that user's groups
	link   func(oldname, newname string) error // the hard link that puts a file in place: os.Link
	chown  func(f *os.File, uid, gid int) error
	stop   func() bool // an interrupt, terminate or hangup arrived; nil: arm is called before the first file is made
	// arm starts catching the signals, and returns the check that stop is and the function that gives
	// them back. It runs just before the first temporary file is made, so until then (a user lookup,
	// a stat, the read of an --import file) a Ctrl-C ends the command at once, as nothing is to be
	// cleaned up. Nil: the host's signals.
	arm func() (stop func() bool, release func())
	// suffix is the random part of a temporary file's name. Nil: crypto/rand.
	suffix func() (string, error)
}

// withHost fills what is unset.
func (e keyEnv) withHost() keyEnv {
	if e.rand == nil {
		e.rand = rand.Reader
	}
	if e.groups == nil {
		e.euid = os.Geteuid()
		gs, _ := os.Getgroups()
		e.groups = append([]int{os.Getegid()}, gs...)
	}
	if e.link == nil {
		e.link = os.Link
	}
	if e.chown == nil {
		e.chown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	}
	if e.arm == nil {
		e.arm = hostArm
	}
	if e.suffix == nil {
		e.suffix = func() (string, error) {
			var r [4]byte
			_, err := io.ReadFull(rand.Reader, r[:])
			return hex.EncodeToString(r[:]), err
		}
	}
	return e
}

// hostArm catches an interrupt, terminate or hangup until release, and says whether one came.
func hostArm() (func() bool, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	seen := false
	stop := func() bool {
		select {
		case <-ch:
			seen = true
		default:
		}
		return seen
	}
	return stop, func() { signal.Stop(ch) }
}

// armStop starts catching the signals, just before the first file is made, and returns the
// function that gives them back. Before it, nothing is made, so a signal's default end of the
// process is the right one.
func (k *keyRun) armStop() func() {
	if k.env.stop != nil {
		return func() {}
	}
	stop, release := k.env.arm()
	k.env.stop = stop
	return release
}

// mayChown reports whether this process may give a file to uid:gid: root may, anyone else may
// only keep it for themselves, in a group of theirs.
func (e keyEnv) mayChown(uid, gid int) bool {
	return e.euid == 0 || (uid == e.euid && slices.Contains(e.groups, gid))
}

// keyCmd is `port49d key sealing|device ...` (spec §12): it makes the secret files an operator
// would otherwise make by shell recipe, each created new in its destination directory, private
// while it is written, and linked into place only when it is complete and only if the name is
// free. It reads no config, prints no key, and leaves nothing behind on a failure.
func keyCmd(args []string, stdout, stderr io.Writer) int {
	return keyCmdWith(args, stdout, stderr, keyEnv{})
}

func keyCmdWith(args []string, stdout, stderr io.Writer, env keyEnv) int {
	k := keyRun{args: args, out: stdout, err: stderr, env: env.withHost()}
	if len(args) == 0 {
		return k.usage("")
	}
	switch args[0] {
	case "sealing":
		return k.sealing(args[1:])
	case "device":
		return k.device(args[1:])
	}
	return k.usage("")
}

type keyRun struct {
	args     []string
	out, err io.Writer
	env      keyEnv
}

// usage prints why, if it is said, and the usage line, and is exit 2.
func (k keyRun) usage(why string) int {
	if why != "" {
		fmt.Fprintln(k.err, "port49d key:", why)
	}
	fmt.Fprintln(k.err, keyUsage)
	return 2
}

func (k keyRun) fail(format string, a ...any) int {
	fmt.Fprintf(k.err, "port49d key: "+format+"\n", a...)
	return 1
}

// reason is what went wrong without the operation and the path an os error repeats, for a line
// that names the path itself.
func reason(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

// owner is who a file is given to, and the names it is printed with.
type owner struct {
	uid, gid int
	label    string
}

// resolveUser is the uid a name or a number names, and the gid of the group of that name, or the
// user's primary group where there is none: chown port49d:port49d, for a user whose group has
// another name. A number is a uid and a gid.
func resolveUser(spec string) (owner, error) {
	if n, err := strconv.Atoi(spec); err == nil && n >= 0 {
		return owner{uid: n, gid: n, label: spec + ":" + spec}, nil
	}
	u, err := user.Lookup(spec)
	if err != nil {
		return owner{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return owner{}, err
	}
	gid, gname := 0, spec
	if g, err := user.LookupGroup(spec); err == nil {
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return owner{}, err
		}
	} else {
		if gid, err = strconv.Atoi(u.Gid); err != nil {
			return owner{}, err
		}
		gname = u.Gid
		if g, err := user.LookupGroupId(u.Gid); err == nil {
			gname = g.Name
		}
	}
	return owner{uid: uid, gid: gid, label: spec + ":" + gname}, nil
}

// resolveGroup is the gid a group name or number names.
func resolveGroup(spec string) (int, error) {
	if n, err := strconv.Atoi(spec); err == nil && n >= 0 {
		return n, nil
	}
	g, err := user.LookupGroup(spec)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// resolve fills the owners, each refused by the flag that named it, then refuses all of them
// at once when this process may not chown to one; nothing has been written by then.
func (k keyRun) refuseOwners(owners ...owner) int {
	for _, o := range owners {
		if !k.env.mayChown(o.uid, o.gid) {
			return k.fail("giving a file to %s takes root; run: sudo port49d key %s", o.label, strings.Join(k.args, " "))
		}
	}
	return 0
}

func (k keyRun) checkDir(flagName, dir string) (string, int) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", k.fail("%s %s: %v", flagName, dir, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", k.fail("%s %s: %v", flagName, abs, reason(err))
	}
	if !fi.IsDir() {
		return "", k.fail("%s %s is not a directory", flagName, abs)
	}
	return abs, 0
}

// taken is the refusal for a name that is there, a symlink included, found or not: nothing is
// ever replaced.
func (k keyRun) taken(paths ...string) int {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			return k.fail("%s exists; pick a new key id", p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return k.fail("%s: %v", p, reason(err))
		}
	}
	return 0
}

// placing is the files of one command: the temporary ones, made in the destination directory,
// and the ones linked into place. rollback removes the placed ones, close the temporary ones.
type placing struct {
	temps, placed []string
}

func (p *placing) close() {
	for _, t := range p.temps {
		_ = os.Remove(t)
	}
}

func (p *placing) rollback() {
	for _, f := range p.placed {
		_ = os.Remove(f)
	}
	p.syncDirs()
	p.placed = nil
}

// syncDirs fsyncs each directory a file was linked into or removed from, so that the name, or its
// removal, is on disk when the command says it is done: a power cut an instant after "wrote" must
// not leave a key file whose contents are on disk and whose name is not, or the reverse. Best
// effort: a filesystem that cannot sync a directory has nothing more to give. No test can pin it,
// as no test can cut the power; the same holds for the f.Sync of a file below.
func (p *placing) syncDirs() {
	seen := map[string]bool{}
	for _, f := range p.placed {
		d := filepath.Dir(f)
		if seen[d] {
			continue
		}
		seen[d] = true
		if h, err := os.Open(d); err == nil {
			_ = h.Sync()
			h.Close()
		}
	}
}

// temp makes a new file in dir that no one else holds, 0600 while it is written, writes content
// and gives it to o with mode. It is O_EXCL, so a name another user planted, a link included, is
// never opened.
func (k keyRun) temp(p *placing, dir string, content []byte, o owner, mode os.FileMode) (string, error) {
	var f *os.File
	var path string
	for i := 0; ; i++ {
		s, err := k.env.suffix()
		if err != nil {
			return "", err
		}
		path = filepath.Join(dir, ".key."+s)
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i >= 10 {
			return "", reason(err)
		}
	}
	p.temps = append(p.temps, path)
	if _, err := f.Write(content); err != nil {
		f.Close()
		return "", err
	}
	if err := k.env.chown(f, o.uid, o.gid); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close()
}

// install links each temporary file to its final name, in order, checking for an interrupt before
// each link and after the last. When one fails, those already placed are removed: a host never
// holds half a pair. The temporary files are removed by the caller either way.
func (k keyRun) install(p *placing, pairs [][2]string) int {
	for _, pr := range pairs {
		if k.env.stop() {
			p.rollback()
			return k.fail("interrupted; nothing was written")
		}
		if err := k.env.link(pr[0], pr[1]); err != nil {
			p.rollback()
			if errors.Is(err, fs.ErrExist) {
				return k.fail("%s exists; pick a new key id", pr[1])
			}
			return k.fail("could not install %s: %v", pr[1], reason(err))
		}
		p.placed = append(p.placed, pr[1])
	}
	p.syncDirs()
	if k.env.stop() {
		p.rollback()
		return k.fail("interrupted; nothing was written")
	}
	return 0
}

// sealing is `key sealing`: the pair of sealing-key files, drawn, or installed from a copy.
func (k keyRun) sealing(args []string) int {
	fs := flag.NewFlagSet("key sealing", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "key id: encryption-<id>.key")
	dir := fs.String("dir", defaultSecretsDir, "destination directory")
	brokerDir := fs.String("broker-dir", "", "the broker's file goes here instead (default --dir)")
	imp := fs.String("import", "", "install the pair from this 32-byte copy instead of drawing")
	daemonUser := fs.String("daemon-user", "port49d", "owner of encryption.key")
	brokerUser := fs.String("broker-user", "port49-broker", "owner of broker-encryption.key")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return k.usage("")
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	suffix := ""
	if given["id"] {
		if !keyNameRe.MatchString(*id) {
			return k.usage(fmt.Sprintf("--id %q holds a character outside letters, digits, - _ . (no leading .), or is empty or over 128 characters", *id))
		}
		suffix = "-" + *id
	}
	if given["import"] && *imp == "" {
		return k.usage("--import names no file")
	}
	d, code := k.checkDir("--dir", *dir)
	if code != 0 {
		return code
	}
	bd := d
	if *brokerDir != "" {
		if bd, code = k.checkDir("--broker-dir", *brokerDir); code != 0 {
			return code
		}
	}
	dOwner, err := resolveUser(*daemonUser)
	if err != nil {
		return k.fail("--daemon-user %s: %v", *daemonUser, reason(err))
	}
	bOwner, err := resolveUser(*brokerUser)
	if err != nil {
		return k.fail("--broker-user %s: %v", *brokerUser, reason(err))
	}
	if code := k.refuseOwners(dOwner, bOwner); code != 0 {
		return code
	}
	dPath, bPath := filepath.Join(d, "encryption"+suffix+".key"), filepath.Join(bd, "broker-encryption"+suffix+".key")
	// Both names are checked before either file is made or any key drawn.
	if code := k.taken(dPath, bPath); code != 0 {
		return code
	}
	var key []byte
	if given["import"] {
		if key, code = k.readImport(*imp); code != 0 {
			return code
		}
	} else if key, code = k.draw(); code != 0 {
		return code
	}
	defer clear(key)
	defer k.armStop()()
	p := &placing{}
	defer p.close()
	t1, err := k.temp(p, d, key, dOwner, 0o400)
	if err != nil {
		return k.fail("the sealing key was not made: %v", err)
	}
	t2, err := k.temp(p, bd, key, bOwner, 0o400)
	if err != nil {
		return k.fail("the sealing key was not made: %v", err)
	}
	if code := k.install(p, [][2]string{{t1, dPath}, {t2, bPath}}); code != 0 {
		return code
	}
	fmt.Fprintf(k.out, "wrote %s  %s 0400\nwrote %s  %s 0400\n", dPath, dOwner.label, bPath, bOwner.label)
	if given["import"] {
		fmt.Fprintf(k.out, "installed from %s: delete that copy, and any other, now\n", *imp)
		return 0
	}
	more := ""
	if given["id"] {
		more = " --id " + *id
	}
	fmt.Fprintf(k.out, "next: copy encryption%s.key to every other host over a private channel, run "+
		"sudo port49d key sealing --import <that file>%s there, then delete the copies\n", suffix, more)
	return 0
}

// draw is a 32-byte key whose last byte is not a newline: a key file loses one trailing
// newline when it is read (§13 decision 53 ruling 1, internal/secretref), so such a key would
// load a byte short, one draw in 256. A draw that fails or ends in one is drawn again, ten times.
func (k keyRun) draw() ([]byte, int) {
	for i := 0; i < sealingDraws; i++ {
		b := make([]byte, sealingKeyLen)
		if _, err := io.ReadFull(k.env.rand, b); err == nil && b[sealingKeyLen-1] != '\n' {
			return b, 0
		}
		clear(b)
	}
	return nil, k.fail("no usable 32-byte key in %d draws", sealingDraws)
}

// readImport is the key in a copied file: a regular file of exactly 32 bytes whose last is not
// a newline, which is what draw makes. Anything else would install a key that loads short or
// not at all.
func (k keyRun) readImport(path string) ([]byte, int) {
	// Open first, without following a symlink and without waiting on a named pipe's writer, then ask
	// the open file what it is: a stat of the path and an open after it could be two different things.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, k.fail("--import %s: %v", path, reason(err))
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, k.fail("--import %s: %v", path, reason(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, k.fail("--import %s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, 2*sealingKeyLen))
	if err != nil {
		return nil, k.fail("--import %s: %v", path, err)
	}
	if len(b) != sealingKeyLen {
		clear(b)
		return nil, k.fail("--import %s is not %d bytes; copy the key file as it is", path, sealingKeyLen)
	}
	if b[sealingKeyLen-1] == '\n' {
		clear(b)
		return nil, k.fail("--import %s ends in a newline byte, which a key file loses when it is read, so it would "+
			"load %d bytes; make a new key with port49d key sealing", path, sealingKeyLen-1)
	}
	return b, 0
}

// device is `key device NAME`: one device-key version file, 32 hex characters and a newline,
// which can be typed into the device's CLI.
func (k keyRun) device(args []string) int {
	name, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, rest = args[0], args[1:]
	}
	fs := flag.NewFlagSet("key device", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", defaultKeysDir, "destination directory")
	own := fs.String("device-owner", "root", "owner of the file")
	grp := fs.String("device-group", "port49d", "group of the file")
	if err := fs.Parse(rest); err != nil {
		return k.usage("")
	}
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if name == "" || fs.NArg() != 0 {
		return k.usage("")
	}
	if !keyNameRe.MatchString(name) {
		return k.usage(fmt.Sprintf("the name %q holds a character outside letters, digits, - _ . (no leading .), or is over 128 characters", name))
	}
	d, code := k.checkDir("--dir", *dir)
	if code != 0 {
		return code
	}
	u, err := resolveUser(*own)
	if err != nil {
		return k.fail("--device-owner %s: %v", *own, reason(err))
	}
	gid, err := resolveGroup(*grp)
	if err != nil {
		return k.fail("--device-group %s: %v", *grp, reason(err))
	}
	o := owner{uid: u.uid, gid: gid, label: *own + ":" + *grp}
	if code := k.refuseOwners(o); code != 0 {
		return code
	}
	path := filepath.Join(d, name)
	if code := k.taken(path); code != 0 {
		return code
	}
	raw := make([]byte, 16)
	defer clear(raw)
	if _, err := io.ReadFull(k.env.rand, raw); err != nil {
		return k.fail("the device key was not made: %v", err)
	}
	content := []byte(hex.EncodeToString(raw) + "\n")
	defer clear(content)
	defer k.armStop()()
	p := &placing{}
	defer p.close()
	t, err := k.temp(p, d, content, o, 0o440)
	if err != nil {
		return k.fail("the device key was not made: %v", err)
	}
	if code := k.install(p, [][2]string{{t, path}}); code != 0 {
		return code
	}
	fmt.Fprintf(k.out, "wrote %s  %s 0440\ntype the key into the device's CLI from that file (tacacs-server key, key, secret), "+
		"and name it in the policy as secret_ref: file:%s\n", path, o.label, path)
	return 0
}
