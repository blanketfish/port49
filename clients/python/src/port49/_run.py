"""Running the port49 CLI (decision 46 rulings 8 and 12).

stdout is read whole and never logged: on success it holds a token. stderr is
the person's: it is written to the caller's stderr as it comes, a byte at a
time if need be, so "touch your key now" or a sign-in prompt with no newline
is seen at once; its last 2 KiB are kept for an error's words."""

import os
import subprocess
import sys
import threading

from .errors import NotInstalled, Port49Error

TAIL = 2048


class Ran:
    __slots__ = ("code", "stdout", "stderr_tail")

    def __init__(self, code, stdout, stderr_tail):
        self.code, self.stdout, self.stderr_tail = code, stdout, stderr_tail

    def __repr__(self):
        return f"Ran(code={self.code})"  # never stdout


def printable(text, limit=512):
    """text with control characters but newline made '?', at most limit characters."""
    return "".join(c if c == "\n" or (c.isprintable()) else "?" for c in text)[:limit]


def run(argv, *, stdin=None, timeout=None, stderr=None):
    out = stderr if stderr is not None else sys.stderr
    try:
        p = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise NotInstalled("not_installed", f"{argv[0]} is not on PATH: install port49, or pass port49=<path>") from None
    tail = bytearray()
    chunks = []

    def pump():
        while True:
            chunk = os.read(p.stderr.fileno(), 4096)
            if not chunk:
                return
            try:
                out.write(chunk.decode("utf-8", "replace"))
                out.flush()
            except (OSError, ValueError):
                pass
            tail.extend(chunk)
            del tail[:-TAIL]

    def drain():
        chunks.append(p.stdout.read())

    threads = [threading.Thread(target=pump, daemon=True), threading.Thread(target=drain, daemon=True)]
    for t in threads:
        t.start()
    try:
        code = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        for t in threads:
            t.join()
        p.stdout.close()
        p.stderr.close()
        raise Port49Error("timeout", f"{argv[0]} {argv[1]} did not finish within {timeout}s and was ended") from None
    for t in threads:
        t.join()
    p.stdout.close()
    p.stderr.close()
    return Ran(code, b"".join(chunks), printable(tail.decode("utf-8", "replace"), TAIL))
