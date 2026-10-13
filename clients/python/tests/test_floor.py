"""The floor is Python 3.10 (decision 46 ruling 14): every source parses as 3.10."""

import ast
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SOURCES = [os.path.join(ROOT, "python", "src", "port49"),
           os.path.join(ROOT, "ansible", "ansible_collections", "port49", "client", "plugins")]


class Floor(unittest.TestCase):
    def test_this_python_is_at_the_floor_or_later(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 10))

    def test_every_source_parses_as_3_10(self):
        n = 0
        for top in SOURCES:
            for d, _, files in os.walk(top):
                for name in files:
                    if name.endswith(".py"):
                        with open(os.path.join(d, name), encoding="utf-8") as f:
                            ast.parse(f.read(), filename=name, feature_version=(3, 10))
                        n += 1
        self.assertGreater(n, 0)
