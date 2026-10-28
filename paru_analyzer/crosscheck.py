"""Cross-check the preprocessor against bash's own parser.

`bash --pretty-print` parses a script without running it and prints it back with comments removed
and one command per line. If our scanner and bash disagree about where a comment, string or
here-document starts or ends, one of them sees words the other does not. That is the gap an attacker
would use to hide code from the scanner, so any difference is reported instead of trusted.

The comparison is on the multiset of words (`\\w+` runs): it ignores layout, quoting and
punctuation, which bash rewrites freely, but notices code that went missing or comments that were
kept.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections import Counter
from typing import Callable

from .models import Finding
from .preprocess import Preprocessed

ENABLED = True   # tests switch this off so they do not depend on the machine's bash
STRUCTURAL = frozenset({"if", "then", "elif", "else", "fi", "while", "until", "do", "done", "case", "esac", "in",
                        "for", "select", "function"})
WORD = re.compile(r"\w+")

Runner = Callable[[str], tuple[int, str, str]]


def run_bash(text: str, timeout: float = 15.0) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) of `bash --pretty-print`. Never runs the script: it only parses it."""
    with tempfile.TemporaryDirectory(prefix="paru-analyzer-bash-") as cwd:
        done = subprocess.run(
            ["bash", "--noprofile", "--norc", "--pretty-print"],
            input=text.encode("utf-8", "surrogateescape"), capture_output=True, timeout=timeout, cwd=cwd,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"},
        )
    return done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace")


QUOTES = re.compile(r"['\"\\]")
# bash prints `$'a\nb'` and `"\x7fELF"` with the escape already turned into a character, the scanner keeps the
# escape as written; both become a space here so that neither leaves a stray `n` or `x7fELF` behind
ESCAPES = re.compile(r"\\(?:x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|[abefnrtv])")


def words(text: str) -> Counter:
    """Words of a script, insensitive to what bash rewrites when it prints a script back: quoting,
    layout, and the fd numbers it adds to redirections (`>&1` becomes `1>&1`). Words that are only
    digits are ignored for that reason; a number cannot hide a command."""
    return Counter(w for w in WORD.findall(QUOTES.sub("", ESCAPES.sub(" ", text))) if w not in STRUCTURAL and not w.isdigit())


def our_words(pre: Preprocessed) -> Counter:
    return words("\n".join(line.text for line in pre.lines))


def crosscheck(name: str, text: str, pre: Preprocessed, run: Runner = run_bash) -> list[Finding]:
    if not ENABLED:
        return []
    try:
        code, out, err = run(text)
    except (OSError, subprocess.SubprocessError) as exc:
        return [Finding("caution", f"Could not cross-check the parse with bash ({type(exc).__name__}); is bash 4.4 or newer installed?",
                        name, None, "crosscheck-unavailable")]
    if code != 0:
        message = (err.strip().splitlines() or ["syntax error"])[0][:160]
        return [Finding("caution", f"bash cannot parse this file, so it was not cross-checked: {message}", name, None, "bash-syntax-error")]
    ours, theirs = our_words(pre), words(out)
    if ours == theirs:
        return []
    only_ours = sorted((ours - theirs).elements())[:5]
    only_bash = sorted((theirs - ours).elements())[:5]
    detail = []
    if only_bash:
        detail.append("bash sees " + ", ".join(only_bash) + " that the scanner dropped")
    if only_ours:
        detail.append("the scanner kept " + ", ".join(only_ours) + " that bash does not")
    return [Finding("caution", f"The scanner and bash read this file differently ({'; '.join(detail)}); code may be hidden from the review",
                    name, None, "parser-mismatch")]
