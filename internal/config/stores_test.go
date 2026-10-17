package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// storesDoc is a file holding stores: with body under it.
func storesDoc(body string) []byte { return []byte("stores:\n" + body) }

// etcdBlock is one store's block at indent: etcd at endpoint under prefix,
// with dir's files (storeFiles) and the daemon's identity, and each of
// extra as a line under etcd:.
func etcdBlock(dir, indent, endpoint, prefix string, extra ...string) string {
	s := indent + "backend: etcd\n" + indent + "etcd:\n" +
		indent + "  endpoints: [" + endpoint + "]\n" +
		indent + "  ca_file: " + filepath.Join(dir, "ca.pem") + "\n" +
		indent + "  prefix: " + prefix + "\n" +
		indent + "  daemon: {cert_file: " + filepath.Join(dir, "d.pem") + ", key_file: " +
		filepath.Join(dir, "d-key.pem") + "}\n"
	for _, e := range extra {
		s += indent + "  " + e + "\n"
	}
	return s
}

func TestNoStoresIsOneMemoryStore(t *testing.T) {
	s, err := StoresBlocks([]byte("admin_socket: /run/port49/port49d.sock\n"))
	if err != nil || !s.Shared || s.Directory.Backend != BackendMemory || s.Session.Backend != BackendMemory ||
		s.SessionPath() != "stores.directory" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestAnOmittedSessionSharesTheDirectory(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc("  directory:\n" +
		etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/", "hold_ttl: 20s")))
	if err != nil || !s.Shared || s.Session.Etcd == nil || s.Session.Etcd.HoldTTL != 20*time.Second ||
		s.Directory.Etcd.Prefix != "/port49/" || s.SessionPath() != "stores.directory" {
		t.Fatalf("%+v %v", s, err)
	}
}

// A directory of its own may wait on a far region: its call_timeout is not
// bound by the session store's packet_deadline (ruling R22).
func TestTwoStoresResolveApart(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/", "call_timeout: 3s") +
			"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/", "hold_ttl: 20s")))
	if err != nil || s.Shared || s.Directory.Etcd.Endpoints[0] != "https://dir-0:2379" ||
		s.Directory.Etcd.CallTimeout != 3*time.Second || s.Session.Etcd.HoldTTL != 20*time.Second ||
		s.SessionPath() != "stores.session" {
		t.Fatalf("%+v %v", s, err)
	}
}

// Review Focus 4: two blocks naming one keyspace are one store, however the
// prefix's trailing slash and the host's case are written.
func TestTheSameKeyspaceTwiceIsOneStore(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://ETCD-0:2379", "/port49") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/", "hold_ttl: 20s")))
	if err != nil || !s.Shared || s.Directory.Etcd.HoldTTL != 20*time.Second || s.SessionPath() != "stores.session" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestOneStoreNamedTwiceMustAgree(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/", "call_timeout: 1s") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "name one store") ||
		!strings.Contains(err.Error(), "set etcd.call_timeout differently") {
		t.Fatalf("%v", err)
	}
}

func TestNestedKeyspacesOnOneClusterAreRefused(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/session/")))
	if err == nil || !strings.Contains(err.Error(), "would reach both") {
		t.Fatalf("%v", err)
	}
}

func TestPrefixesApartOnOneClusterAreTwoStores(t *testing.T) {
	dir := storeFiles(t)
	s, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49-directory/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err != nil || s.Shared {
		t.Fatalf("%+v %v", s, err)
	}
}

// The pre-flight's minor 10: a session block alone names what is missing.
func TestASessionStoreAloneNeedsADirectory(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc("  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "stores.directory is required") {
		t.Fatalf("%v", err)
	}
}

func TestMemoryAndEtcdAreNeverMixed(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc("  directory: {backend: memory}\n  session:\n" +
		etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "both memory") {
		t.Fatalf("%v", err)
	}
}

func TestADirectoryOfItsOwnRefusesTheSessionStoresKeys(t *testing.T) {
	dir := storeFiles(t)
	for _, k := range []string{"hold_ttl: 20s", "health: {interval: 2s}", "context_cache: {ttl: 2s}",
		"sweep_interval: 5m", "lease_grace: 2m", "breaker: {failures: 3}", "max_in_flight: {token: 8}"} {
		key := strings.SplitN(k, ":", 2)[0]
		_, err := StoresBlocks(storesDoc(
			"  directory:\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/", k) +
				"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/")))
		if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd."+key+": a session store's key") {
			t.Errorf("%s: %v", key, err)
		}
	}
	_, err := StoresBlocks(storesDoc(
		"  directory:\n    packet_deadline: 1s\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "stores.directory.packet_deadline: a session store's key") {
		t.Errorf("packet_deadline: %v", err)
	}
}

// R5: the old blocks are unknown keys, refused as any is, with no alias.
func TestTheOldBlocksAreUnknownKeys(t *testing.T) {
	if _, err := StoresBlocks([]byte("store:\n  backend: memory\n")); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Errorf("store: %v", err)
	}
	if _, err := StoresBlocks([]byte("broker:\n  directory:\n    enrollment_store: {backend: memory}\n")); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Errorf("enrollment_store: %v", err)
	}
}

func TestStoreMessagesNameTheirBlock(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://dir-0:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://sess-0:2379", "/port49/", "call_timeout: 9s")))
	if err == nil || !strings.Contains(err.Error(), "stores.session.etcd.call_timeout 9s") {
		t.Fatalf("%v", err)
	}
}

// Two blocks that share one endpoint and one prefix but list different
// members are not the same store, and one role would reach both.
func TestSharedEndpointsWithOnePrefixButOtherMembersAreRefused(t *testing.T) {
	dir := storeFiles(t)
	_, err := StoresBlocks(storesDoc(
		"  directory:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379, https://etcd-1:2379", "/port49/") +
			"  session:\n" + etcdBlock(dir, "    ", "https://etcd-0:2379", "/port49/")))
	if err == nil || !strings.Contains(err.Error(), "would reach both") {
		t.Fatalf("%v", err)
	}
}
