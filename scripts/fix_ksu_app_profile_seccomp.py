#!/usr/bin/env python3
"""Keep an app's seccomp filter intact when KSU grants it root.

usage: fix_ksu_app_profile_seccomp.py <ksu-dir>

MUST RUN AFTER the SUSFS enable patch and its fix set. SUSFS rewrites both files
this touches, so running before it makes app_profile.c reject against
10_enable_susfs_for_ksu.patch, which has no fix_app_profile.c.patch by design.

WHY THIS EXISTS. An app granted root ends up with

    Seccomp:        0

in /proc/self/status while every sibling app reports 2. Android installs a filter
on every app during zygote specialisation and offers no legitimate route back to
mode 0, so that one field is a permissionless self-detection oracle -- measured on
an OP15 (CPH2747): 3 of 116 app processes at 0, and those 3 were exactly the
root-using ones.

WHO BREAKS IT. Upstream KernelSU-Next is fine: kernel/hook/setuid_hook.c keeps the
filter and whitelists only the syscall su needs, via ksu_seccomp_allow_cache().
The SUSFS enable patch *reverts* that -- it strips those calls, un-statics
disable_seccomp() in kernel/policy/app_profile.c, declares it extern in
setuid_hook.c, and plants five calls across the two files. Its only protection is

    if (likely(test_thread_flag(TIF_SECCOMP)))
        disable_seccomp();

which is no protection at all: TIF_SECCOMP is set precisely *because* a filter
exists, so the guard passes and the teardown proceeds. It merely skips a pointless
call on unfiltered tasks.

WHAT THIS DOES. Restores KSUN's own approach at all five sites, then removes the
helper and its extern so nothing can reach it again. The replacement block is
copied from upstream setuid_hook.c, not invented.

Idempotent and self-retiring: a tree with no disable_seccomp() left is untouched,
so this no-ops the day SUSFS stops reverting the fix.
"""
import io
import os
import re
import sys

FILES = ("kernel/hook/setuid_hook.c", "kernel/policy/app_profile.c")
INCLUDE = '#include "infra/seccomp_cache.h"\n'

BLOCK = """{i}if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
{i}    current->seccomp.filter) {{
{i}    spin_lock_irq(&current->sighand->siglock);
{i}    ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
{i}    spin_unlock_irq(&current->sighand->siglock);
{i}}}"""

# SUSFS's useless guard, which the replacement block supersedes.
GUARDED = re.compile(
    r"^([ \t]*)if \(likely\(test_thread_flag\(TIF_SECCOMP\)\)\)\n"
    r"[ \t]*disable_seccomp\(\);[ \t]*$", re.M)
BARE = re.compile(r"^([ \t]*)disable_seccomp\(\);[ \t]*$", re.M)
EXTERN = re.compile(r"^extern void disable_seccomp\(void\);\n", re.M)
DEFN = re.compile(r"^(?:static )?void disable_seccomp\(void\)\s*\n\{", re.M)


def die(msg):
    print("::error::fix_ksu_app_profile_seccomp: %s" % msg)
    raise SystemExit(1)


def drop_defn(text):
    """Remove the disable_seccomp() body by brace matching; static or not."""
    m = DEFN.search(text)
    if not m:
        return text, False
    depth = 0
    start = text.index("{", m.start())
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                end = j + 1
                while end < len(text) and text[end] == "\n":
                    end += 1
                return text[:m.start()] + text[end:], True
    die("could not brace-match the disable_seccomp() body")


def ensure_include(text, path):
    if INCLUDE in text:
        return text
    for anchor in ('#include "infra/symbol_resolver.h"\n',
                   '#include "infra/ksu_hook.h"\n'):
        if anchor in text:
            return text.replace(anchor, anchor + INCLUDE, 1)
    m = re.search(r"^#include [^\n]*\n", text, re.M)
    if not m:
        die("no #include to anchor seccomp_cache.h after, in %s" % path)
    return text[:m.end()] + INCLUDE + text[m.end():]


def main():
    if len(sys.argv) != 2:
        die("usage: fix_ksu_app_profile_seccomp.py <ksu-dir>")
    root = sys.argv[1]

    present = [p for p in FILES if os.path.isfile(os.path.join(root, p))]
    if not present:
        print("   no KSU seccomp call sites present, nothing to do")
        return

    total = 0
    for rel in present:
        path = os.path.join(root, rel)
        s = io.open(path, encoding="utf-8", newline="").read()

        n = len(BARE.findall(s))   # every site has a disable_seccomp(); line
        if n == 0:
            print("   %s: no disable_seccomp() call, nothing to do" % rel)
            continue

        s = GUARDED.sub(lambda m: BLOCK.format(i=m.group(1)), s)
        s = BARE.sub(lambda m: BLOCK.format(i=m.group(1)), s)
        s = EXTERN.sub("", s)
        s, _ = drop_defn(s)
        s = ensure_include(s, rel)

        if re.search(r"\bdisable_seccomp\b", s):
            die("disable_seccomp still referenced in %s after the rewrite" % rel)
        if "ksu_seccomp_allow_cache" not in s:
            die("the rewrite did not land in %s" % rel)

        io.open(path, "w", encoding="utf-8", newline="").write(s)
        print("   %s: %d call site(s) now preserve the filter" % (rel, n))
        total += n

    if total:
        print("   seccomp filters preserved at %d site(s)" % total)


if __name__ == "__main__":
    main()
