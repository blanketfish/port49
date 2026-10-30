// The chart's checks, run on the output of whichever renderer is given: real helm (render_test.go,
// tag helm) or the Go stand-in (gorender_test.go). The checks are the plan 12b Task 10 tests.
package helm

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/config"
)

// doc is one rendered Kubernetes object, decoded generically.
type doc = map[string]any

// renderer renders the chart with the values files merged in order.
type renderer func(t *testing.T, valuesFiles ...string) []doc

func decodeDocs(t *testing.T, from string, b []byte) []doc {
	t.Helper()
	var out []doc
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d doc
		err := dec.Decode(&d)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("%s: rendered YAML does not decode: %v", from, err)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

// at walks a decoded value: string keys into maps, ints into lists. nil when absent.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func list(v any) []any { l, _ := v.([]any); return l }

func kindOf(d doc) string { return str(d["kind"]) }
func nameOf(d doc) string { return str(at(d, "metadata", "name")) }

func of(docs []doc, kind string) []doc {
	var out []doc
	for _, d := range docs {
		if kindOf(d) == kind {
			out = append(out, d)
		}
	}
	return out
}

func one(t *testing.T, docs []doc, kind, name string) doc {
	t.Helper()
	for _, d := range docs {
		if kindOf(d) == kind && nameOf(d) == name {
			return d
		}
	}
	t.Fatalf("no %s %q rendered", kind, name)
	return nil
}

// pod is a StatefulSet's pod spec.
func pod(d doc) any { return at(d, "spec", "template", "spec") }

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// baseValues are the chart's CI values and a policy and inventory (the compose stack's: the paths
// are the same in the chart), plus extra YAML.
func baseValues(t *testing.T, extra string) []string {
	t.Helper()
	dir := t.TempDir()
	body, err := yaml.Marshal(map[string]any{
		"policy":    read(t, "deploy/compose/config/policy.yaml"),
		"inventory": read(t, "deploy/compose/config/inventory.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(chartDir, "ci", "values.yaml")}
	for name, b := range map[string]string{"a-policy.yaml": string(body), "b-extra.yaml": extra} {
		if name == "b-extra.yaml" && extra == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files = append(files, filepath.Join(dir, "a-policy.yaml"))
	if extra != "" {
		files = append(files, filepath.Join(dir, "b-extra.yaml"))
	}
	return files
}

func render(t *testing.T, r renderer, extra string) []doc {
	t.Helper()
	return r(t, baseValues(t, extra)...)
}

// cfg is a rendered component's config, from its ConfigMap.
func cfg(t *testing.T, docs []doc, component string) map[string]any {
	t.Helper()
	cm := one(t, docs, "ConfigMap", "t-"+component)
	file := "port49d.yaml"
	if component == "broker" {
		file = "port49-broker.yaml"
	}
	m := map[string]any{}
	if err := yaml.Unmarshal([]byte(str(at(cm, "data", file))), &m); err != nil {
		t.Fatalf("the rendered %s does not decode: %v", file, err)
	}
	return m
}

func containers(p any) []any {
	return append(list(at(p, "containers")), list(at(p, "initContainers"))...)
}

// mounts is the names of the Secrets a pod mounts.
func secretsOf(p any) map[string]bool {
	out := map[string]bool{}
	for _, v := range list(at(p, "volumes")) {
		if s := str(at(v, "secret", "secretName")); s != "" {
			out[s] = true
		}
	}
	return out
}

func checkBrokerFSGroup(t *testing.T, r renderer) {
	docs := render(t, r, "")
	p := pod(one(t, docs, "StatefulSet", "t-broker"))
	// The 7e recipe: no fsGroup, or fsGroup with OnRootMismatch, never the default Always (which
	// would make state_dir group-writable at every mount and the next start would be refused).
	if g := at(p, "securityContext", "fsGroup"); g != nil && str(at(p, "securityContext", "fsGroupChangePolicy")) != "OnRootMismatch" {
		t.Errorf("the broker pod sets fsGroup %v without fsGroupChangePolicy OnRootMismatch", g)
	}
	var cmd string
	for _, c := range list(at(p, "initContainers")) {
		cmd += str(at(c, "command", 2))
	}
	if !strings.Contains(cmd, "install -d -m 0700 -o 65532 -g 65532 /var/lib/port49-broker/state") {
		t.Errorf("no initContainer makes the 0700 state directory: %q", cmd)
	}
	if got := str(at(cfg(t, docs, "broker"), "broker", "state_dir")); got != "/var/lib/port49-broker/state" {
		t.Errorf("broker.state_dir is %q, want /var/lib/port49-broker/state", got)
	}
}

func checkPort49dFSGroup(t *testing.T, r renderer) {
	docs := render(t, r, "")
	p := pod(one(t, docs, "StatefulSet", "t-port49d"))
	if str(at(p, "securityContext", "fsGroup")) != "65532" || str(at(p, "securityContext", "fsGroupChangePolicy")) != "OnRootMismatch" {
		t.Errorf("port49d's pod security context is %v, want fsGroup 65532 and OnRootMismatch", at(p, "securityContext"))
	}
	var cmd string
	for _, c := range list(at(p, "initContainers")) {
		cmd += str(at(c, "command", 2))
	}
	if !strings.Contains(cmd, "install -d -m 0700 -o 65532 -g 65532 /var/spool/port49d/data") {
		t.Errorf("no initContainer makes the 0700 spool directory: %q", cmd)
	}
	var vol any
	for _, v := range list(at(p, "volumes")) {
		if str(at(v, "name")) == "keys" {
			vol = v
		}
	}
	if str(at(vol, "secret", "secretName")) != "port49-device-keys" || str(at(vol, "secret", "defaultMode")) != "288" {
		t.Errorf("the keys volume is %v, want the Secret port49-device-keys with defaultMode 288 (0440)", vol)
	}
	found := false
	for _, m := range list(at(p, "containers", 0, "volumeMounts")) {
		if str(at(m, "name")) == "keys" {
			found = true
			if str(at(m, "mountPath")) != "/run/port49/keys" || at(m, "subPath") != nil {
				t.Errorf("the keys mount is %v, want /run/port49/keys with no subPath", m)
			}
		}
	}
	if !found {
		t.Error("port49d does not mount the keys volume")
	}
	if got := str(at(cfg(t, docs, "port49d"), "key_secret_refs", "file_dir")); got != "/run/port49/keys" {
		t.Errorf("key_secret_refs.file_dir is %q, want /run/port49/keys", got)
	}
}

func checkStatefulSets(t *testing.T, r renderer) {
	docs := render(t, r, "")
	if n := len(of(docs, "Deployment")); n != 0 {
		t.Errorf("%d Deployments rendered; both components are StatefulSets", n)
	}
	for _, name := range []string{"t-port49d", "t-broker"} {
		s := one(t, docs, "StatefulSet", name)
		if got := str(at(s, "spec", "updateStrategy", "type")); got != "RollingUpdate" {
			t.Errorf("%s updateStrategy is %q, want RollingUpdate", name, got)
		}
		if len(list(at(s, "spec", "volumeClaimTemplates"))) != 1 {
			t.Errorf("%s has no volumeClaimTemplates entry: one PVC per replica", name)
		}
	}
	if str(at(one(t, docs, "StatefulSet", "t-port49d"), "spec", "replicas")) != "2" || str(at(one(t, docs, "StatefulSet", "t-broker"), "spec", "replicas")) != "2" {
		t.Error("the default replicas are not 2 and 2")
	}
}

func checkServices(t *testing.T, r renderer) {
	docs := render(t, r, "")
	svc := one(t, docs, "Service", "t-port49d")
	if str(at(svc, "spec", "externalTrafficPolicy")) != "Local" {
		t.Errorf("externalTrafficPolicy is %q, want Local", str(at(svc, "spec", "externalTrafficPolicy")))
	}
	ports := list(at(svc, "spec", "ports"))
	if len(ports) != 1 || str(at(ports[0], "port")) != "49" {
		t.Errorf("the TACACS+ Service ports are %v, want 49 alone", ports)
	}
	with := render(t, r, "tlsListener: {enabled: true, existingSecret: port49-tls}\n")
	ports = list(at(one(t, with, "Service", "t-port49d"), "spec", "ports"))
	if len(ports) != 2 || str(at(ports[1], "port")) != "300" {
		t.Errorf("with tlsListener.enabled the ports are %v, want 49 and 300", ports)
	}
	p := pod(one(t, docs, "StatefulSet", "t-port49d"))
	ok := false
	for _, s := range list(at(p, "securityContext", "sysctls")) {
		if str(at(s, "name")) == "net.ipv4.ip_unprivileged_port_start" && str(at(s, "value")) == "0" {
			ok = true
		}
	}
	if !ok {
		t.Error("port49d's pod does not set net.ipv4.ip_unprivileged_port_start to \"0\"")
	}
	for _, name := range []string{"t-port49d", "t-broker"} {
		for _, c := range list(at(pod(one(t, docs, "StatefulSet", name)), "containers")) {
			sc := at(c, "securityContext")
			if at(sc, "runAsNonRoot") != true || at(sc, "allowPrivilegeEscalation") != false ||
				str(at(sc, "capabilities", "drop", 0)) != "ALL" || str(at(sc, "runAsUser")) != "65532" {
				t.Errorf("%s container %s: securityContext %v is not non-root, no escalation, drop ALL", name, str(at(c, "name")), sc)
			}
		}
	}
}

func checkSeparation(t *testing.T, r renderer) {
	docs := render(t, r, "")
	for _, c := range []string{"port49d", "broker"} {
		sts := one(t, docs, "StatefulSet", "t-"+c)
		pdb := one(t, docs, "PodDisruptionBudget", "t-"+c)
		if str(at(pdb, "spec", "maxUnavailable")) != "1" {
			t.Errorf("%s PDB maxUnavailable is %v, want 1", c, at(pdb, "spec", "maxUnavailable"))
		}
		if fmt.Sprint(at(pdb, "spec", "selector", "matchLabels")) != fmt.Sprint(at(sts, "spec", "selector", "matchLabels")) {
			t.Errorf("%s PDB selects %v, not the StatefulSet's pods", c, at(pdb, "spec", "selector"))
		}
		p := pod(sts)
		pref := at(p, "affinity", "podAntiAffinity", "preferredDuringSchedulingIgnoredDuringExecution", 0)
		if str(at(pref, "podAffinityTerm", "topologyKey")) != "kubernetes.io/hostname" {
			t.Errorf("%s has no preferred pod anti-affinity on hostname: %v", c, pref)
		}
		if at(p, "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution") != nil {
			t.Errorf("%s anti-affinity is required, not preferred", c)
		}
		tsc := at(p, "topologySpreadConstraints", 0)
		if str(at(tsc, "topologyKey")) != "topology.kubernetes.io/zone" || str(at(tsc, "whenUnsatisfiable")) != "ScheduleAnyway" {
			t.Errorf("%s topology spread is %v, want zone with ScheduleAnyway", c, tsc)
		}
		if _, ok := at(sts, "spec").(map[string]any)["persistentVolumeClaimRetentionPolicy"]; ok {
			t.Errorf("%s sets persistentVolumeClaimRetentionPolicy: the default retains the PVC", c)
		}
		if str(at(p, "terminationGracePeriodSeconds")) != "60" {
			t.Errorf("%s terminationGracePeriodSeconds is %v, want 60", c, at(p, "terminationGracePeriodSeconds"))
		}
	}
}

// With fsGroup and OnRootMismatch the kubelet skips its walk of a PVC only while the root is
// root:65532 with perms including 0770 and setgid (kubeletWalks); a root with the group write bit
// removed (the first design, 2755) is a mismatch at every later mount, and the walk then makes the
// data directory 2770, which the fence refuses. So the root init container sets 3770, which the
// kubelet skips and the fence excuses (sticky, root-owned), makes the data directory with an
// explicit chmod and repairs the tree below it. Nothing fenced lives under a PVC. UNVERIFIED against
// a real kubelet until Task 11's two-generation kind cell.
func checkPVCRootAndRepair(t *testing.T, r renderer) {
	docs := render(t, r, "")
	for name, v := range map[string][2]string{
		"t-port49d": {"/var/spool/port49d", "/var/spool/port49d/data"},
		"t-broker":  {"/var/lib/port49-broker", "/var/lib/port49-broker/state"},
	} {
		mount, dir := v[0], v[1]
		p := pod(one(t, docs, "StatefulSet", name))
		if str(at(p, "securityContext", "fsGroup")) != "65532" || str(at(p, "securityContext", "fsGroupChangePolicy")) != "OnRootMismatch" {
			t.Errorf("%s: pod security context %v, want fsGroup 65532 with OnRootMismatch, never Always", name, at(p, "securityContext"))
		}
		init := at(p, "initContainers", 0)
		owner := at(p, "initContainers", 1)
		if str(at(init, "name")) != "data-dir" || str(at(owner, "name")) != "data-dir-owner" || len(list(at(p, "initContainers"))) != 2 {
			t.Fatalf("%s: init containers %v, want data-dir (root, inodes only) then data-dir-owner (65532, the descent)", name, at(p, "initContainers"))
		}
		cmd := str(at(init, "command", 2))
		for _, want := range []string{
			"chown 0:65532 " + mount + " && chmod 3770 " + mount,
			"install -d -m 0700 -o 65532 -g 65532 " + dir,
			"chown 65532:65532 " + dir,
			"chmod 0700 " + dir,
			"chmod g-s " + dir,
		} {
			if !strings.Contains(cmd, want) {
				t.Errorf("%s: the root data-dir init command lacks %q:\n%s", name, want, cmd)
			}
		}
		if strings.Contains(cmd, " -R ") || strings.Contains(cmd, "find ") {
			t.Errorf("%s: the root init descends into the data directory (it holds no DAC_READ_SEARCH, the owner init does that):\n%s", name, cmd)
		}
		ocmd := str(at(owner, "command", 2))
		for _, want := range []string{
			"chmod -R go-rwx " + dir,
			"chmod -R g-s " + dir,
			"find " + dir + " ! -user 65532",
			"chown -R 65532:65532 " + dir, // the one command the failure message tells the operator to run
			"exit 1",
		} {
			if !strings.Contains(ocmd, want) {
				t.Errorf("%s: the owner init command lacks %q:\n%s", name, want, ocmd)
			}
		}
		if strings.Contains(ocmd, "chown 0:") || strings.Contains(ocmd, "chmod 3770") {
			t.Errorf("%s: the owner init touches the volume root:\n%s", name, ocmd)
		}
		caps := strs(at(init, "securityContext", "capabilities", "add"))
		if strings.Join(caps, ",") != "CHOWN,FOWNER,FSETID" {
			t.Errorf("%s: the root init adds %v, want exactly CHOWN, FOWNER, FSETID (Pod Security baseline's list has no DAC_READ_SEARCH)", name, caps)
		}
		osc := at(owner, "securityContext")
		if str(at(osc, "runAsUser")) != "65532" || str(at(osc, "runAsGroup")) != "65532" || at(osc, "runAsNonRoot") != true ||
			len(strs(at(osc, "capabilities", "add"))) != 0 || strings.Join(strs(at(osc, "capabilities", "drop")), ",") != "ALL" ||
			at(osc, "allowPrivilegeEscalation") != false || at(osc, "readOnlyRootFilesystem") != true {
			t.Errorf("%s: the owner init's securityContext is %v, want 65532:65532, non-root, drop ALL, no escalation, read-only root", name, osc)
		}
		// What the root init sets must be a root the kubelet skips and the fence excuses.
		m := regexp.MustCompile(`chown ([0-9]+):([0-9]+) \S+ && chmod ([0-7]{4}) `).FindStringSubmatch(cmd)
		if m == nil {
			t.Fatalf("%s: no chown and chmod of the volume root in %q", name, cmd)
		}
		mode, _ := strconv.ParseUint(m[3], 8, 32)
		perm := fs.FileMode(mode & 0o777)
		if mode&0o2000 != 0 {
			perm |= fs.ModeSetgid
		}
		if mode&0o1000 != 0 {
			perm |= fs.ModeSticky
		}
		if kubeletWalks(m[2], "65532", perm|fs.ModeDir, false) {
			t.Errorf("%s: root %s:%s %04o makes the kubelet walk the volume at every mount", name, m[1], m[2], mode)
		}
		if perm&fs.ModeSticky == 0 || m[1] != "0" {
			t.Errorf("%s: root %s:%s %04o: the fence excuses a group-writable ancestor only if it is sticky and root-owned", name, m[1], m[2], mode)
		}
	}
	for _, c := range []string{"port49d", "broker"} {
		var walk func(path string, v any)
		walk = func(path string, v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					walk(path+"."+k, e)
				}
			case []any:
				for i, e := range x {
					walk(path+"[]"+fmt.Sprint(i), e)
				}
			case string:
				if (strings.HasSuffix(path, "_file") || strings.HasSuffix(path, "_dir") || strings.Contains(path, "secret_ref")) &&
					(strings.Contains(x, "/var/spool/port49d") || strings.Contains(x, "/var/lib/port49-broker")) &&
					!strings.HasSuffix(path, "state_dir") && !strings.HasSuffix(path, "spool_path") {
					t.Errorf("%s: %s is %q, a fenced file under a PVC", c, path, x)
				}
			}
		}
		walk(c, cfg(t, docs, c))
	}
}

// strs is a rendered list of strings, sorted.
func strs(v any) []string {
	var out []string
	for _, e := range list(v) {
		out = append(out, str(e))
	}
	sort.Strings(out)
	return out
}

// checkContainerSecurity holds the exact hardening of every container the chart renders (Task 10
// review m-2, m-3, m-4): the root init container has the three capabilities its commands need and
// nothing else (CHOWN, FOWNER, FSETID: all in Pod Security baseline's list; it never descends, and
// neither DAC_READ_SEARCH nor DAC_OVERRIDE is held), is not privileged, cannot escalate, drops ALL, has the runtime
// default seccomp profile and a read-only root filesystem; the main containers add nothing and are
// non-root with a read-only root filesystem. `extra` values render the enrollments CronJob too.
func checkContainerSecurity(t *testing.T, r renderer) {
	docs := render(t, r, "backup: {enrollments: {enabled: true, claimName: port49-backups}}\n")
	var pods []struct {
		name string
		spec any
	}
	for _, d := range docs {
		switch kindOf(d) {
		case "StatefulSet":
			pods = append(pods, struct {
				name string
				spec any
			}{nameOf(d), pod(d)})
		case "CronJob":
			pods = append(pods, struct {
				name string
				spec any
			}{nameOf(d), at(d, "spec", "jobTemplate", "spec", "template", "spec")})
		}
	}
	if len(pods) != 3 {
		t.Fatalf("%d pod specs rendered, want both StatefulSets and the enrollments CronJob", len(pods))
	}
	wantAdd := []string{"CHOWN", "FOWNER", "FSETID"}
	for _, p := range pods {
		for _, c := range append(list(at(p.spec, "initContainers")), list(at(p.spec, "containers"))...) {
			name := p.name + "/" + str(at(c, "name"))
			sc := at(c, "securityContext")
			if at(sc, "privileged") != false {
				t.Errorf("%s: privileged is %v, want an explicit false", name, at(sc, "privileged"))
			}
			if at(sc, "allowPrivilegeEscalation") != false {
				t.Errorf("%s: allowPrivilegeEscalation is %v, want false", name, at(sc, "allowPrivilegeEscalation"))
			}
			if got := strs(at(sc, "capabilities", "drop")); strings.Join(got, ",") != "ALL" {
				t.Errorf("%s: capabilities.drop is %v, want [ALL]", name, got)
			}
			add := strs(at(sc, "capabilities", "add"))
			for _, a := range add {
				if a == "SYS_ADMIN" || a == "DAC_OVERRIDE" {
					t.Errorf("%s adds %s", name, a)
				}
			}
			if str(at(sc, "seccompProfile", "type")) != "RuntimeDefault" && str(at(p.spec, "securityContext", "seccompProfile", "type")) != "RuntimeDefault" {
				t.Errorf("%s: no RuntimeDefault seccomp profile", name)
			}
			if at(sc, "readOnlyRootFilesystem") != true {
				t.Errorf("%s: readOnlyRootFilesystem is %v, want true (the init and the processes write only to their volumes)", name, at(sc, "readOnlyRootFilesystem"))
			}
			if str(at(sc, "runAsUser")) == "0" {
				if strings.Join(add, ",") != strings.Join(wantAdd, ",") {
					t.Errorf("%s: the root container adds %v, want exactly %v", name, add, wantAdd)
				}
			} else {
				if len(add) != 0 || at(sc, "runAsNonRoot") != true {
					t.Errorf("%s: a non-root container adds %v with runAsNonRoot %v, want none and true", name, add, at(sc, "runAsNonRoot"))
				}
			}
		}
		if at(p.spec, "automountServiceAccountToken") != false {
			t.Errorf("%s: automountServiceAccountToken is %v: no pod here calls the API", p.name, at(p.spec, "automountServiceAccountToken"))
		}
	}
}

func checkEtcdIdentities(t *testing.T, r renderer) {
	docs := render(t, r, "")
	d := secretsOf(pod(one(t, docs, "StatefulSet", "t-port49d")))
	b := secretsOf(pod(one(t, docs, "StatefulSet", "t-broker")))
	if !d["port49-etcd-port49d"] || d["port49-etcd-broker"] {
		t.Errorf("port49d's pod mounts %v: it must hold its own etcd identity and never the broker's", d)
	}
	if !b["port49-etcd-broker"] || b["port49-etcd-port49d"] {
		t.Errorf("the broker's pod mounts %v: it must hold its own etcd identity and never port49d's", b)
	}
	for who, m := range map[string]map[string]bool{"port49d": d, "broker": b} {
		if !m["port49-etcd-ca"] {
			t.Errorf("%s does not mount the etcd CA Secret", who)
		}
		if !m["port49-encryption"] {
			t.Errorf("%s does not mount the encryption Secret", who)
		}
	}
	if !d["port49-device-keys"] || b["port49-device-keys"] {
		t.Errorf("the device keys must be mounted in port49d's pod alone: port49d %v, broker %v", d["port49-device-keys"], b["port49-device-keys"])
	}
}

func checkProbes(t *testing.T, r renderer) {
	docs := render(t, r, "")
	metrics := map[string]string{"t-port49d": "9049", "t-broker": "9050"}
	for name, port := range metrics {
		p := pod(one(t, docs, "StatefulSet", name))
		for _, c := range list(at(p, "containers")) {
			ports := map[string]string{}
			for _, cp := range list(at(c, "ports")) {
				ports[str(at(cp, "name"))] = str(at(cp, "containerPort"))
			}
			for probe, path := range map[string]string{"readinessProbe": "/readyz", "livenessProbe": "/healthz"} {
				pr := at(c, probe)
				hg := at(pr, "httpGet")
				if hg == nil || at(pr, "exec") != nil || at(pr, "tcpSocket") != nil {
					t.Errorf("%s %s is not a plain httpGet: %v", name, probe, pr)
					continue
				}
				if str(at(hg, "path")) != path || str(at(hg, "scheme")) != "HTTP" {
					t.Errorf("%s %s is %v, want httpGet %s over HTTP", name, probe, hg, path)
				}
				if got := ports[str(at(hg, "port"))]; got != port {
					t.Errorf("%s %s probes port %v (%q), want the metrics port %s", name, probe, at(hg, "port"), got, port)
				}
			}
			period, fail := at(c, "livenessProbe", "periodSeconds"), at(c, "livenessProbe", "failureThreshold")
			var pn, fn int
			fmt.Sscan(str(period), &pn)
			fmt.Sscan(str(fail), &fn)
			if pn*fn < 60 {
				t.Errorf("%s liveness is %d s x %d = %d s, want at least 60 (a store loss leaves /healthz unbound for seconds)", name, pn, fn, pn*fn)
			}
		}
	}
	for _, c := range []string{"port49d", "broker"} {
		cm := one(t, docs, "ConfigMap", "t-"+c)
		for k, v := range at(cm, "data").(map[string]any) {
			if strings.Contains(str(v), "admin_socket") {
				t.Errorf("%s in the %s ConfigMap names admin_socket, which was removed", k, c)
			}
		}
	}
}

func checkIssuerDiscovery(t *testing.T, r renderer) {
	if n := len(of(render(t, r, ""), "ClusterRoleBinding")); n != 0 {
		t.Fatalf("%d ClusterRoleBindings rendered with issuerDiscovery off", n)
	}
	docs := render(t, r, "issuerDiscovery: {enabled: true}\n")
	crb := of(docs, "ClusterRoleBinding")
	if len(crb) != 1 {
		t.Fatalf("%d ClusterRoleBindings rendered with issuerDiscovery on, want 1", len(crb))
	}
	var ex doc
	if err := yaml.Unmarshal([]byte(read(t, "examples/kubernetes/issuer-discovery.yaml")), &ex); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(crb[0]["roleRef"]) != fmt.Sprint(ex["roleRef"]) || fmt.Sprint(crb[0]["subjects"]) != fmt.Sprint(ex["subjects"]) {
		t.Errorf("the chart's binding %v %v differs from examples/kubernetes/issuer-discovery.yaml's %v %v",
			crb[0]["roleRef"], crb[0]["subjects"], ex["roleRef"], ex["subjects"])
	}
}

func checkHPA(t *testing.T, r renderer) {
	if n := len(of(render(t, r, ""), "HorizontalPodAutoscaler")); n != 0 {
		t.Fatalf("%d HPAs rendered with autoscaling off", n)
	}
	docs := render(t, r, "autoscaling: {enabled: true}\n")
	h := one(t, docs, "HorizontalPodAutoscaler", "t-port49d")
	if str(h["apiVersion"]) != "autoscaling/v2" {
		t.Errorf("apiVersion %q, want autoscaling/v2", h["apiVersion"])
	}
	ms := list(at(h, "spec", "metrics"))
	if len(ms) != 1 || str(at(ms[0], "type")) != "Pods" || str(at(ms[0], "pods", "metric", "name")) != "port49_connections" {
		t.Errorf("the HPA's metrics are %v, want one Pods metric port49_connections and no Resource metric", ms)
	}
	if _, ok := at(one(t, docs, "StatefulSet", "t-port49d"), "spec").(map[string]any)["replicas"]; ok {
		t.Error("the StatefulSet sets replicas under an HPA: every upgrade would reset the scale")
	}
}

func checkEtcdMembers(t *testing.T, r renderer) {
	docs := render(t, r, "")
	want := fmt.Sprint(list(at(parseValuesFile(t, filepath.Join(chartDir, "ci", "values.yaml")), "etcd", "endpoints")))
	for _, c := range []string{"port49d", "broker"} {
		got := fmt.Sprint(list(at(cfg(t, docs, c), "stores", "directory", "etcd", "endpoints")))
		if got != want {
			t.Errorf("the %s config names etcd %s, want every member of the values: %s", c, got, want)
		}
	}
}

func parseValuesFile(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A tree of the pod's paths, moved under a temporary directory, with fake files at the modes the
// fence wants, as tests/shapes does for the systemd paths.
type tree struct {
	t   *testing.T
	dir string
}

var podRoots = []string{"/etc/port49", "/run/port49/keys", "/var/spool/port49d", "/var/lib/port49-broker"}

func (tr *tree) move(s string) string {
	for _, r := range podRoots {
		s = strings.ReplaceAll(s, r, filepath.Join(tr.dir, r))
	}
	return s
}

func (tr *tree) write(abs, body string, mode os.FileMode) string {
	tr.t.Helper()
	p := filepath.Join(tr.dir, abs)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	_ = os.Remove(p)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		tr.t.Fatal(err)
	}
	return p
}

func newTree(t *testing.T) *tree {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { // t.TempDir is 0777 under the umask
		t.Fatal(err)
	}
	tr := &tree{t: t, dir: dir}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/etc/port49", 0o755}, {"/etc/port49/config", 0o755}, {"/etc/port49/secrets", 0o755},
		{"/etc/port49/etcd-ca", 0o755}, {"/etc/port49/etcd", 0o755}, {"/etc/port49/broker", 0o755},
		{"/etc/port49/tls", 0o755}, {"/etc/port49/attestation", 0o755},
		{"/run/port49/keys", 0o750}, {"/var/spool/port49d", 0o700}, {"/var/spool/port49d/data", 0o700},
		{"/var/lib/port49-broker", 0o700}, {"/var/lib/port49-broker/state", 0o700},
	} {
		p := filepath.Join(dir, d.path)
		if err := os.MkdirAll(p, d.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, d.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		"/etc/port49/etcd-ca/ca.crt", "/etc/port49/etcd/tls.crt", "/etc/port49/etcd/tls.key",
		"/etc/port49/broker/tls.crt", "/etc/port49/broker/tls.key", "/etc/port49/broker/ca.crt",
		"/etc/port49/tls/tls.crt", "/etc/port49/tls/tls.key", "/etc/port49/tls/ca.crt",
		"/etc/port49/attestation/attestation-roots.pem",
	} {
		tr.write(f, "not-a-real-pem\n", 0o440)
	}
	tr.write("/etc/port49/secrets/encryption.key", "not-a-real-key-v1-not-a-real-key", 0o440)
	tr.write("/run/port49/keys/tacacs_v1", "not-a-real-key-v1\n", 0o440)
	return tr
}

// load writes the rendered files of both ConfigMaps, moved, and loads both configs.
func (tr *tree) load(docs []doc) (d, b config.Config) {
	tr.t.Helper()
	dd := at(one(tr.t, docs, "ConfigMap", "t-port49d"), "data").(map[string]any)
	bd := at(one(tr.t, docs, "ConfigMap", "t-broker"), "data").(map[string]any)
	for k, v := range dd {
		tr.write("/etc/port49/config/"+k, tr.move(str(v)), 0o644)
	}
	dp := filepath.Join(tr.dir, "/etc/port49/config/port49d.yaml")
	tr.write("/etc/port49/config/port49-broker.yaml", tr.move(str(bd["port49-broker.yaml"])), 0o644)
	bp := filepath.Join(tr.dir, "/etc/port49/config/port49-broker.yaml")
	d, err := config.Load(dp)
	if err != nil {
		tr.t.Fatalf("the rendered port49d.yaml does not load: %v", err)
	}
	b, err = config.LoadBroker(bp)
	if err != nil {
		tr.t.Fatalf("the rendered port49-broker.yaml does not load: %v", err)
	}
	return d, b
}

func checkConfigsLoad(t *testing.T, r renderer) {
	for name, extra := range map[string]string{
		"defaults": "",
		"tls":      "tlsListener: {enabled: true, existingSecret: port49-tls}\n",
		"roots":    "broker: {attestationRootsConfigMap: port49-attestation}\n",
	} {
		t.Run(name, func(t *testing.T) {
			d, b := newTree(t).load(render(t, r, extra))
			if got := len(d.Stores.Directory.Etcd.Endpoints); got != 3 {
				t.Errorf("port49d names %d etcd endpoints, want 3", got)
			}
			if name == "tls" && d.TLSListener == nil {
				t.Error("tlsListener.enabled did not render a tls_listener")
			}
			if name == "roots" && (b.Broker == nil || b.Broker.Identity == nil || b.Broker.Identity.PerLoginMFA == nil) {
				t.Error("broker.attestationRootsConfigMap did not render attestation_roots_file")
			}
		})
	}
}

func checkMultiRegion(t *testing.T, r renderer) {
	raw := read(t, "deploy/helm/port49/examples/values-multi-region.yaml")
	docs := render(t, r, raw)
	d, b := newTree(t).load(docs)
	if d.Stores.Shared || d.Stores.Session.Etcd == nil || len(d.Stores.Session.Etcd.Endpoints) != 3 {
		t.Errorf("port49d: stores.session is %+v (shared %v), want an etcd of its own", d.Stores.Session, d.Stores.Shared)
	}
	if b.Stores.Shared || b.Stores.Session.Etcd == nil {
		t.Error("the broker has no stores.session of its own")
	}
	for _, e := range d.Stores.Directory.Etcd.Endpoints {
		for _, s := range d.Stores.Session.Etcd.Endpoints {
			if e == s {
				t.Errorf("stores.session shares the directory's member %s", e)
			}
		}
	}
}

// checks is every check on the rendered chart, in the plan's order.
var checks = []struct {
	name string
	fn   func(*testing.T, renderer)
}{
	{"TestTheBrokerPodHasNoFSGroup", checkBrokerFSGroup},
	{"TestPort49dSetsOnRootMismatch", checkPort49dFSGroup},
	{"TestBothAreStatefulSetsWithAPVCPerReplica", checkStatefulSets},
	{"TestServicesKeepTheSource", checkServices},
	{"TestSeparationAndDisruption", checkSeparation},
	{"TestPVCRootIsMadeSkippableAndTheDataDirRepaired", checkPVCRootAndRepair},
	{"TestEveryContainerIsHardenedExactly", checkContainerSecurity},
	{"TestNoPodHoldsTheOthersEtcdIdentity", checkEtcdIdentities},
	{"TestProbesNeverNeedAClientCertificate", checkProbes},
	{"TestIssuerDiscoveryIsOptIn", checkIssuerDiscovery},
	{"TestTheHPAScalesOnConnections", checkHPA},
	{"TestEveryEtcdMemberIsListed", checkEtcdMembers},
	{"TestTheMultiRegionExampleRenders", checkMultiRegion},
	{"TestRenderedConfigsLoad", checkConfigsLoad},
}
