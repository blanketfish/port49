import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def have_real():
    # In a child: test_netmiko.py puts a stand-in `netmiko` into this process.
    r = subprocess.run([sys.executable, "-c", "import netmiko, paramiko"], capture_output=True)
    return r.returncode == 0


@unittest.skipUnless(shutil.which("ssh-keygen") and have_real(), "needs real Netmiko and Paramiko, and ssh-keygen")
class RealNetmikoTest(unittest.TestCase):
    def test_a_rebuild_negotiates_the_filed_key_type_and_refuses_another_key(self):  # fix round 2, N1
        r = subprocess.run([sys.executable, os.path.join(HERE, "real_netmiko_e2e.py")], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stdout + r.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
