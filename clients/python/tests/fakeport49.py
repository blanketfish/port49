"""A fake port49 for the library's tests: each run takes the next answer from
answers.json (stdout, stderr, code) and appends its argv to argv.jsonl."""

import json
import os
import stat
import sys

SCRIPT = """#!{python}
import json, os, sys, time
d =os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(d, "argv.jsonl"), "a", encoding="utf-8") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
with open(os.path.join(d, "answers.json"), encoding="utf-8") as f:
    answers = json.load(f)
n = sum(1 for _ in open(os.path.join(d, "argv.jsonl"), encoding="utf-8")) - 1
a = answers[min(n, len(answers) - 1)]
time.sleep(a.get("sleep", 0))
sys.stderr.write(a.get("stderr", ""))
sys.stdout.write(a.get("stdout", ""))
sys.exit(a.get("code", 0))
"""


def make(directory, answers):
    """A fake port49 in directory answering answers in turn, from the first; returns its path."""
    with open(os.path.join(directory, "answers.json"), "w", encoding="utf-8") as f:
        json.dump(answers, f)
    open(os.path.join(directory, "argv.jsonl"), "w").close()  # a new fake starts at its first answer
    path = os.path.join(directory, "port49")
    with open(path, "w", encoding="utf-8") as f:
        f.write(SCRIPT.format(python=sys.executable))
    os.chmod(path, stat.S_IRWXU)
    return path


def argvs(directory):
    """Every run's argv, in order."""
    with open(os.path.join(directory, "argv.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def item(**kw):
    """One JSON line, as port49 prints it."""
    return json.dumps(kw) + "\n"
