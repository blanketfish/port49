"""Running the port49 CLI (decision 46 rulings 8 and 12).

stdout is read whole and never logged: on success it holds a token. Once run returns or raises, the drain thread
holds none of it, though a grandchild keeps the pipe open (#62). stderr is
the person's: it is written to the caller's stderr as it comes, a byte at a
time if need be, so "touch your key now" or a sign-in prompt with no newline
is seen at once; its last 2 KiB are kept for an error's words."""

import codecs
import os
import subprocess
import sys
import threading

from .errors import NotInstalled, Port49Error

TAIL = 2048
# A fleet's answer grows with the fleet (a 6000-device sweep is 1.3 MB): 64 MiB holds some 200,000
# devices. An answer over it is an error of its own, never read as "no answer".
MAX_STDOUT = 64 << 20
REAP = 1.0# how long to wait for the readers once the child is killed


class Ran:
    __slots__ = ("code", "stdout", "stderr_tail")

    def __init__(self, code, stdout, stderr_tail):
        self.code, self.stdout, self.stderr_tail = code, stdout, stderr_tail

    def __repr__(self):
        return f"Ran(code={self.code})"  # never stdout


def printable(text, limit=512):
    """text with control characters but newline made '?', at most limit characters."""
    return "".join(c if c == "\n" or (c.isprintable()) else "?" for c in text)[:limit]


def run(argv, *, stdin=None, timeout=None, stderr=None, oversize_hint=""):
    out = stderr if stderr is not None else sys.stderr
    try:
        p = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise NotInstalled("not_installed", f"{argv[0]} is not on PATH: install port49, or pass port49=<path>") from None
    tail = bytearray()
    lock = threading.Lock()
    held = [bytearray()]  # the answer: the drain's until take() hands it to run, then [None] (#62)
    size = [0]
    decoder = codecs.getincrementaldecoder("utf-8")("replace")  # a character may span two reads

    def pump():
        writing = True
        while True:
            chunk = os.read(p.stderr.fileno(), 4096)
            if not chunk:
                return
            if writing:
                try:
                    out.write(decoder.decode(chunk))
                    out.flush()
                except Exception:  # a sink that cannot take text: stop writing, keep draining
                    writing = False
            tail.extend(chunk)
            del tail[:-TAIL]

    def drain():
        while True:
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                return
            with lock:
                if held[0] is not None:  # once run has the answer, a grandchild's writes are read and dropped
                    size[0] += len(chunk)
                    if size[0] <= MAX_STDOUT:
                        held[0].extend(chunk)
                    else:
                        held[0].clear()  # over the cap: keep draining, hold nothing
            del chunk  # blocked in the next read, this frame holds no part of the answer

    def take():
        """The answer, handed from the drain to run: the drain keeps no reference to it after. One copy:
        the answer is parsed from it as it is."""
        with lock:
            answer, held[0] = held[0], None
        return answer

    threads = [threading.Thread(target=pump, daemon=True), threading.Thread(target=drain, daemon=True)]
    for t in threads:
        t.start()

    def reap():
        """Join the readers, boundedly: a wrapper's grandchild may still hold the pipes. The
        pipes are closed only if the readers are done (a reader mid-read must not see its
        descriptor reused)."""
        for t in threads:
            t.join(REAP)
        if not any(t.is_alive() for t in threads):
            p.stdout.close()
            p.stderr.close()

    try:
        code = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        reap()
        take()  # what the ended run printed goes with no one: this frame is in the traceback
        raise Port49Error("timeout", f"{argv[0]} {argv[1]} did not finish within {timeout}s and was ended") from None
    except BaseException:  # an interrupt mid-wait: its traceback holds this frame, never the answer
        take()
        raise
    reap()
    answer = take()  # after reap: the drain has had its REAP to read the CLI's last bytes
    if size[0] > MAX_STDOUT:  # the drain cleared the answer at the cap: answer is empty
        raise Port49Error("answer_too_large", f"{argv[0]} {argv[1]} printed more than {MAX_STDOUT} bytes and the "
                          f"answer was dropped (it exited {code}, and may have minted){oversize_hint}")
    return Ran(code, answer,printable(tail.decode("utf-8", "replace"), TAIL))
