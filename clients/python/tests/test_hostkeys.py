import base64
import hashlib
import hmac
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from port49 import HostKeyError, hostkeys  # noqa: E402

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


@unittest.skipUnless(shutil.which("ssh") and shutil.which("ssh-keygen"), "needs OpenSSH's ssh and ssh-keygen")
class HostKeysTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.kh = os.path.join(self.dir, "known_hosts")
        open(self.kh, "w").close()

    def config(self, *lines, user=None, glob="/dev/null"):
        path = os.path.join(self.dir, "ssh_config")
        head = [f"UserKnownHostsFile {user or self.kh}", f"GlobalKnownHostsFile {glob}"]
        with open(path, "w", encoding="ascii") as f:
            f.write("\n".join([*head, *lines]) + "\n")
        return path

    def newkey(self, name):
        """A fresh Ed25519 public key, "type base64", and its .pub file."""
        path = os.path.join(self.dir, name)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True)
        with open(path + ".pub", encoding="ascii") as f:
            return " ".join(f.read().split()[:2]), path + ".pub"

    def test_nothing_known(self):
        kh = hostkeys.lookup("Leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.name, kh.keys, kh.authorities, kh.revoked, kh.krl, kh.strict, kh.write_to),
                         ("leaf1", (), (), (), "", False, self.kh))

    def test_a_key_filed_under_the_name_plain_or_hashed(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"{hostkeys.hashed('leaf1')} {ED}\nspine1 {ED}\n")
        kh = hostkeys.lookup("LEAF1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual(kh.keys, (ED,))

    def test_the_operators_alias_and_strict_yes(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"corp-leaf1 {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11",
                             ssh_config=self.config("StrictHostKeyChecking yes", "Host leaf1", "  HostKeyAlias corp-leaf1"))
        self.assertEqual((kh.name, kh.keys, kh.strict), ("corp-leaf1", (ED,), True))

    def test_marker_lines_are_kept_apart(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"@cert-authority leaf* {ED}\n@revoked * {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.keys, len(kh.authorities), kh.revoked), ((), 1, (ED,)))

    def test_a_revoked_filed_key_is_refused_before_connecting(self):  # Review Focus 6; pre-flight C1
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\n@revoked * {ED}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual(cm.exception.code, "host_key_revoked")

    def test_a_revoked_key_beside_another_is_dropped(self):  # always, not only when nothing else is filed
        other, _ = self.newkey("other")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\nleaf1 {other}\n@revoked * {ED}\n")
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config()).keys, (other,))

    def test_a_krl_revokes_a_filed_key(self):  # Review Focus 6: RevokedHostKeys, read by ssh-keygen -Q
        bad, pub = self.newkey("bad")
        good, _ = self.newkey("good")
        krl = os.path.join(self.dir, "krl")
        subprocess.run(["ssh-keygen", "-q", "-k", "-f", krl, pub], check=True)
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {bad}\n")
        cfg = self.config(f"RevokedHostKeys {krl}")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=cfg)
        self.assertEqual(cm.exception.code, "host_key_revoked")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {good}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=cfg)
        self.assertEqual((kh.keys, kh.krl), ((good,), krl))
        self.assertTrue(hostkeys.is_revoked(kh, *bad.split()))
        self.assertFalse(hostkeys.is_revoked(kh, *good.split()))

    def test_a_krl_ssh_keygen_cannot_read_is_refused(self):  # fail closed (10.2p1: exit 255, not a KRL)
        plain = os.path.join(self.dir, "plain")
        with open(plain, "w", encoding="ascii") as f:
            f.write(ED + "\n")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(f"RevokedHostKeys {plain}"))
        self.assertEqual(cm.exception.code, "host_key_uncheckable")
        self.assertIn("RevokedHostKeys", str(cm.exception))

    def test_known_hosts_command_is_refused(self):  # Review Focus 6; pre-flight C1
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("KnownHostsCommand /bin/true %H"))
        self.assertEqual(cm.exception.code, "host_key_uncheckable")
        self.assertIn("KnownHostsCommand", str(cm.exception))
        self.assertIn("port49 ssh", str(cm.exception))

    def test_a_known_hosts_file_of_dev_null_is_refused(self):  # Review Focus 7; pre-flight I7
        for user in ("/dev/null", "none"):
            with self.assertRaises(HostKeyError, msg=user) as cm:
                hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(user=user))
            self.assertEqual(cm.exception.code, "host_keys_not_kept")
            self.assertIn("UserKnownHostsFile", str(cm.exception))
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("StrictHostKeyChecking yes", user="/dev/null"))
        self.assertEqual((kh.strict, kh.write_to), (True, ""))  # the operator's yes: nothing accepted, so it stands

    def test_names_known_hosts_would_misread_are_refused(self):  # pre-flight I6
        for name in ("leaf*", "a,b", "a b", "x\ny", "leaf1\n", "@x", "|1|x", "[leaf1]:22", "-leaf", "a" * 254, ""):
            self.assertFalse(hostkeys.valid_name(name), name)
            with self.assertRaises(HostKeyError, msg=repr(name)) as cm:
                hostkeys.lookup(name, "10.0.0.11", ssh_config=self.config())
            self.assertEqual(cm.exception.code, "device_name")
        self.assertTrue(hostkeys.valid_name("a" * 253))
        self.assertTrue(hostkeys.valid_name("core-sw01.dc1"))

    def test_ssh_g_runs_as_port49_ssh_runs_it(self):  # pre-flight M6: HostName's %, and -l for Match user
        kh = hostkeys.lookup("leaf1", "fe80::1%eth0", username="alice",
                             ssh_config=self.config("Match user alice", "  HostKeyAlias alice-leaf1"))
        self.assertEqual(kh.name, "alice-leaf1")

    def test_remember_files_under_the_name_hashed_when_asked(self):
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("HashKnownHosts yes"))
        hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=open(os.devnull, "w"))
        with open(self.kh, encoding="ascii") as f:
            line = f.read()
        self.assertTrue(line.startswith("|1|"))
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config()).keys, (ED,))
        found = subprocess.run(["ssh-keygen", "-F", "leaf1", "-f", self.kh], capture_output=True, text=True).stdout
        self.assertIn(ED.split()[1], found)

    def test_concurrent_first_contacts_file_one_whole_line(self):  # Review Focus 4; append skips a key already filed
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        null = open(os.devnull, "w")
        threads = [threading.Thread(target=hostkeys.remember, args=(kh, "ssh-ed25519", ED.split()[1], null))
                   for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        with open(self.kh, encoding="ascii") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, [f"leaf1 {ED}"])
        self.assertEqual(kh.name, "leaf1")

    def test_concurrent_appends_under_other_names_write_whole_lines(self):  # Review Focus 3
        threads = [threading.Thread(target=hostkeys.append, args=(self.kh, f"10.0.0.{i}", [ED]),
                                    kwargs={"hash_names": False}) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        with open(self.kh, encoding="ascii") as f:
            lines = f.read().splitlines()
        self.assertEqual(sorted(lines), sorted(f"10.0.0.{i} {ED}" for i in range(20)))


    def test_hashed_is_openssh_form(self):
        salt = b"\x01" * 20
        want = "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(
            hmac.new(salt, b"leaf1", hashlib.sha1).digest()).decode()
        self.assertEqual(hostkeys.hashed("leaf1", salt), want)

    # Task 9 controller rulings (C1, I6, N4, Task 2's measured forms).

    def refused(self, code, setting, *args, **kw):
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup(*args, **kw)
        self.assertEqual(cm.exception.code, code)
        self.assertIn(setting, str(cm.exception))
        return cm.exception

    def test_an_ssh_config_ssh_cannot_read_is_refused(self):
        self.refused("ssh_config_unread", "ssh", "leaf1", "10.0.0.11", ssh_config=os.path.join(self.dir, "missing"))
        self.refused("ssh_config_unread", "ssh", "leaf1", "10.0.0.11", ssh_config=self.config(), ssh="/nonexistent/ssh")

    def test_a_user_known_hosts_file_absent_from_ssh_g_is_refused(self):  # 8.5p1 prints nothing for `none`
        fake = os.path.join(self.dir, "fakessh")
        with open(fake, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\necho 'stricthostkeychecking ask'\necho 'globalknownhostsfile /dev/null'\n")
        os.chmod(fake, 0o755)
        self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11", ssh=fake)

    def test_a_split_or_relative_known_hosts_value_is_refused(self):
        fake = os.path.join(self.dir, "fakessh")
        for value in ("/a b/kh /c/kh", "kh", "/ok/kh relative/kh"):
            with open(fake, "w", encoding="ascii") as f:
                f.write(f"#!/bin/sh\necho 'stricthostkeychecking ask'\necho 'userknownhostsfile {value}'\n"
                        "echo 'globalknownhostsfile /dev/null'\n")
            os.chmod(fake, 0o755)
            e = self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11", ssh=fake)
            self.assertIn("absolute", str(e), value)

    def test_a_known_hosts_file_that_cannot_keep_a_key_is_refused(self):  # as port49 ssh's knownHostsCannotKeep
        link = os.path.join(self.dir, "nullink")
        os.symlink("/dev/null", link)
        e = self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11",
                         ssh_config=self.config(user=link))
        self.assertIn("/dev/null", str(e))
        self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11",
                     ssh_config=self.config(user=self.dir))  # a directory
        self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11",
                     ssh_config=self.config(user=os.path.join(self.dir, "nodir", "kh")))
        os.symlink(os.path.join(self.dir, "nowhere"), os.path.join(self.dir, "dangling"))
        self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11",
                     ssh_config=self.config(user=os.path.join(self.dir, "dangling")))

    @unittest.skipIf(os.geteuid() == 0, "root can write anything")
    def test_an_unwritable_known_hosts_file_or_directory_is_refused(self):
        os.chmod(self.kh, 0o400)
        e = self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertIn(self.kh, str(e))
        ro = os.path.join(self.dir, "ro")
        os.mkdir(ro)
        os.chmod(ro, 0o500)
        self.addCleanup(os.chmod, ro, 0o700)
        self.refused("host_keys_not_kept", "UserKnownHostsFile", "leaf1", "10.0.0.11",
                     ssh_config=self.config(user=os.path.join(ro, "kh")))
        # under the operator's yes nothing is written, so a read-only file stands
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("StrictHostKeyChecking yes"))
        self.assertTrue(kh.strict)

    def test_a_missing_file_in_a_writable_directory_is_accepted(self):
        new = os.path.join(self.dir, "new_known_hosts")
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(user=new)).write_to, new)

    def test_the_first_known_hosts_file_is_where_keys_are_written(self):
        second = os.path.join(self.dir, "second")
        with open(second, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(user=f"{self.kh} {second}"))
        self.assertEqual((kh.write_to, kh.keys), (self.kh, (ED,)))

    def test_the_global_file_is_read_with_its_tilde_and_percent_d_expanded(self):  # K6: -G prints them verbatim
        home = pwd.getpwuid(os.getuid()).pw_dir
        want = hostkeys._expand("~/g1 %d/g2 /abs/g3".split(), home)
        self.assertEqual(want, [os.path.join(home, "g1"), os.path.join(home, "g2"), "/abs/g3"])
        self.assertEqual(hostkeys._expand(["~"], home), [home])

    def test_a_certificate_authority_alone_is_reported(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"@cert-authority * {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.keys, len(kh.authorities)), ((), 1))

    def test_keys_in_the_global_file_count(self):
        glob = os.path.join(self.dir, "global")
        with open(glob, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\n")
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(glob=glob)).keys, (ED,))

    def test_match_host_sees_the_minted_address(self):
        kh = hostkeys.lookup("leaf1", "10.9.9.9", ssh_config=self.config("Match host 10.9.9.9",
                                                                        "  HostKeyAlias by-address"))
        self.assertEqual(kh.name, "by-address")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("Match host 10.9.9.9",
                                                                         "  HostKeyAlias by-address"))
        self.assertEqual(kh.name, "leaf1")

    # Fix round 1.

    def quiet(self):
        f = open(os.devnull, "w")
        self.addCleanup(f.close)
        return f

    def test_remember_keeps_the_last_line_of_a_file_without_a_final_newline(self):  # I1
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"spine1 {ED}")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=self.quiet())
        self.assertEqual(hostkeys.lookup("spine1", "10.0.0.12", ssh_config=self.config()).keys, (ED,))
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config()).keys, (ED,))
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(f.read(), f"spine1 {ED}\nleaf1 {ED}\n")

    def test_remember_refuses_when_another_key_is_now_filed(self):  # M3: filed during the key exchange
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        real, _ = self.newkey("real")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {real}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=self.quiet())
        self.assertEqual(cm.exception.code, "host_key_changed")
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(f.read(), f"leaf1 {real}\n")

    def test_remember_checks_what_it_writes(self):  # M5
        for name, keytype, blob in (("a b", "ssh-ed25519", "AAAA"), ("leaf*", "ssh-ed25519", "AAAA"),
                                    ("leaf1", "ssh-ed25519 x", "AAAA"), ("leaf1", "ssh-ed25519", "AA\nBB")):
            kh = hostkeys.KnownHosts(name, (), (), (), "", False, False, self.kh)
            with self.assertRaises(HostKeyError, msg=repr((name, keytype, blob))):
                hostkeys.remember(kh, keytype, blob, stderr=self.quiet())
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(f.read(), "")

    def test_a_write_that_fails_is_a_host_key_error(self):  # M4
        kh = hostkeys.KnownHosts("leaf1", (), (), (), "", False, False, os.path.join(self.kh, "under_a_file"))
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=self.quiet())
        self.assertEqual(cm.exception.code, "host_keys_not_kept")

    def test_a_proxy_or_port_the_library_cannot_follow_is_refused(self):  # I2
        for setting, name in (("ProxyJump bastion-a", "ProxyJump"), ("ProxyCommand nc %h %p", "ProxyCommand")):
            e = self.refused("host_key_uncheckable", name, "leaf1", "10.0.0.11", ssh_config=self.config(setting))
            self.assertIn("port49 ssh", str(e))
            self.assertNotIn("ssh-keygen -R", str(e))
        e = self.refused("host_key_uncheckable", "Port", "leaf1", "10.0.0.11", ssh_config=self.config("Port 2222"))
        self.assertIn("2222", str(e))
        self.assertIn("22", str(e))
        self.assertNotIn("ssh-keygen -R", str(e))
        # the caller's own port, and `none`, stand
        hostkeys.lookup("leaf1", "10.0.0.11", port=2222, ssh_config=self.config("Port 2222"))
        hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("ProxyJump none", "ProxyCommand none"))

    # Fix round 2.

    def test_a_bind_setting_the_library_cannot_honour_is_refused(self):  # N2
        for setting, name in (("BindAddress 127.0.0.2", "BindAddress"), ("BindInterface lo", "BindInterface")):
            e = self.refused("host_key_uncheckable", name, "leaf1", "10.0.0.11", ssh_config=self.config(setting))
            self.assertIn("port49 ssh", str(e))
            self.assertNotIn("ssh-keygen -R", str(e))
        # ssh binds a literal "none" and fails to connect (10.2p1), so it is refused as well
        for setting, name in (("BindAddress none", "BindAddress"), ("BindInterface none", "BindInterface")):
            self.refused("host_key_uncheckable", name, "leaf1", "10.0.0.11", ssh_config=self.config(setting))

    def test_remember_is_rechecked_with_the_given_ssh_keygen(self):  # N4
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        fake = os.path.join(self.dir, "fakekeygen")
        with open(fake, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\nexit 2\n")
        os.chmod(fake, 0o755)
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"spine1 {ED}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=self.quiet(), ssh_keygen=fake)
        self.assertEqual(cm.exception.code, "known_hosts_unread")

    def test_remember_with_nowhere_to_write_is_refused(self):
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("StrictHostKeyChecking yes"))
        kh = hostkeys.KnownHosts(kh.name, (), (), (), "", True, False, "")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=open(os.devnull, "w"))
        self.assertEqual(cm.exception.code, "host_keys_not_kept")


@unittest.skipUnless(shutil.which("ssh") and shutil.which("ssh-keygen"), "needs OpenSSH's ssh and ssh-keygen")
class AddressHelpersTest(unittest.TestCase):
    """Plan 9f Task 1: reading and filing keys under an address."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.home = os.path.join(self.dir, "home")
        os.mkdir(self.home)
        old = os.environ.get("HOME")
        os.environ["HOME"] = self.home
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old) if old is not None else os.environ.pop("HOME"))
        self.kh = os.path.join(self.dir, "known_hosts")

    def put(self, path, text):
        with open(path, "w", encoding="ascii") as f:
            f.write(text)

    def newkey(self, name, keytype="ed25519"):
        path = os.path.join(self.dir, name)
        subprocess.run(["ssh-keygen", "-q", "-t", keytype, "-N", "", "-f", path], check=True)
        with open(path + ".pub", encoding="ascii") as f:
            return " ".join(f.read().split()[:2]), path + ".pub"

    def test_filed_reads_across_files_plain_and_hashed(self):
        other = os.path.join(self.dir, "other")
        k2, _ = self.newkey("k2")
        self.put(self.kh, f"{hostkeys.hashed('10.0.0.1')} {ED}\n")
        self.put(other, f"10.0.0.1 {k2}\n10.0.0.1 {ED}\nspine {k2}\n")
        keys, revoked = hostkeys.filed("10.0.0.1", [self.kh, other, os.path.join(self.dir, "missing")])
        self.assertEqual((keys, revoked), ([ED, k2], []))

    def test_filed_leaves_cert_authorities_out_and_returns_revoked(self):
        k2, _ = self.newkey("k2")
        self.put(self.kh, f"@cert-authority 10.0.0.* {ED}\n@revoked 10.0.0.1 {k2}\n")
        self.assertEqual(hostkeys.filed("10.0.0.1", [self.kh]), ([], [k2]))

    def test_filed_with_a_broken_ssh_keygen_is_refused(self):
        self.put(self.kh, f"10.0.0.1 {ED}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.filed("10.0.0.1", [self.kh], ssh_keygen="/nonexistent/ssh-keygen")
        self.assertEqual(cm.exception.code, "known_hosts_unread")

    def test_address_entry(self):
        self.assertEqual(hostkeys.address_entry("10.0.0.1", 22), "10.0.0.1")
        self.assertEqual(hostkeys.address_entry("10.0.0.1", 830), "[10.0.0.1]:830")
        self.assertEqual(hostkeys.address_entry("2001:db8::1", 830), "[2001:db8::1]:830")
        self.assertEqual(hostkeys.address_entry("2001:db8::1", 22), "2001:db8::1")
        for bad in ("", "a b", "a\nb", 'a"b', " "):
            with self.assertRaises(HostKeyError, msg=repr(bad)) as cm:
                hostkeys.address_entry(bad, 22)
            self.assertEqual(cm.exception.code, "address")

    def test_known_files_are_the_ones_ssh_g_names(self):
        cfg = os.path.join(self.dir, "ssh_config")
        self.put(cfg, f"UserKnownHostsFile ~/.ssh/a {self.dir}/b\nGlobalKnownHostsFile ~/g /dev/null\n"
                      "HashKnownHosts yes\n")
        paths, write_to, hash_names = hostkeys.known_files("leaf1", ssh_config=cfg)
        home = hostkeys._passwd_home()  # ssh's ~ is the passwd home, not $HOME
        self.assertEqual(paths, [f"{home}/.ssh/a", f"{self.dir}/b", f"{home}/g"])
        self.assertEqual((write_to, hash_names), (f"{home}/.ssh/a", True))

    def test_known_files_with_nowhere_to_write(self):
        cfg = os.path.join(self.dir, "ssh_config")
        self.put(cfg, "UserKnownHostsFile none\nGlobalKnownHostsFile /dev/null\n")
        self.assertEqual(hostkeys.known_files("leaf1", ssh_config=cfg), ([], "", False))

    def test_append_writes_plain_and_hashed(self):
        k2, _ = self.newkey("k2", "ecdsa")
        self.assertEqual(hostkeys.append(self.kh, "[10.0.0.1]:830", [ED], hash_names=False), [ED])
        hostkeys.append(self.kh, "10.0.0.2", [ED, k2], hash_names=True)
        with open(self.kh, encoding="ascii") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[0], f"[10.0.0.1]:830 {ED}")
        self.assertTrue(all(line.startswith("|1|") for line in lines[1:]))
        self.assertEqual(hostkeys.filed("[10.0.0.1]:830", [self.kh])[0], [ED])
        self.assertEqual(hostkeys.filed("10.0.0.2", [self.kh])[0], [ED, k2])
        self.assertEqual(os.stat(self.kh).st_mode & 0o777, 0o600)

    def test_append_adds_a_missing_final_newline(self):
        self.put(self.kh, f"spine1 {ED}")
        hostkeys.append(self.kh, "10.0.0.1", [ED], hash_names=False)
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(f.read(), f"spine1 {ED}\n10.0.0.1 {ED}\n")

    def test_append_skips_a_key_already_filed(self):
        k2, _ = self.newkey("k2", "ecdsa")
        self.put(self.kh, f"{hostkeys.hashed('10.0.0.1')} {ED}\n")
        self.assertEqual(hostkeys.append(self.kh, "10.0.0.1", [ED, k2], hash_names=False), [k2])
        self.assertEqual(hostkeys.append(self.kh, "10.0.0.1", [ED, k2], hash_names=False), [])
        self.assertEqual(hostkeys.filed("10.0.0.1", [self.kh])[0], [ED, k2])
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(len(f.read().splitlines()), 2)

    def test_append_writes_nothing_when_every_key_is_filed(self):
        self.put(self.kh, f"10.0.0.1 {ED}")  # no final newline: a skipped key adds no bare newline either
        self.assertEqual(hostkeys.append(self.kh, "10.0.0.1", [ED], hash_names=False), [])
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(f.read(), f"10.0.0.1 {ED}")

    def test_append_does_not_count_a_revoked_filed_key(self):
        old, _ = self.newkey("old")
        self.put(self.kh, f"10.0.0.1 {old}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.append(self.kh, "10.0.0.1", [ED], hash_names=False)
        self.assertEqual(cm.exception.code, "host_key_changed")
        self.assertEqual(hostkeys.append(self.kh, "10.0.0.1", [ED], hash_names=False, revoked=lambda k: k == old),
                         [ED])

    def test_append_refuses_a_different_key_of_the_same_type(self):
        k2, _ = self.newkey("k2")
        self.put(self.kh, f"10.0.0.1 {k2}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.append(self.kh, "10.0.0.1", [ED], hash_names=False)
        self.assertEqual(cm.exception.code, "host_key_changed")
        with open(self.kh, encoding="ascii") as f:
            self.assertEqual(f.read(), f"10.0.0.1 {k2}\n")

    def test_append_refuses_what_cannot_be_written(self):
        for host, key in (("a b", ED), ("10.0.0.1", "ssh-ed25519 AA\nBB"), ("10.0.0.1", "nokeyblob")):
            with self.assertRaises(HostKeyError, msg=repr((host, key))):
                hostkeys.append(self.kh, host, [key], hash_names=False)
        self.assertFalse(os.path.exists(self.kh))

    def test_fingerprint_matches_ssh_keygen(self):
        key, pub = self.newkey("fp")
        want = subprocess.run(["ssh-keygen", "-lf", pub], capture_output=True, text=True, check=True).stdout.split()[1]
        self.assertEqual(hostkeys.fingerprint(key), want)
        self.assertTrue(want.startswith("SHA256:") and "=" not in want)


if __name__ == "__main__":
    unittest.main()
