#!/usr/bin/env python3
"""Keep an app's seccomp filter intact when app_profile grants it root.

usage: fix_ksu_app_profile_seccomp.py <ksu-dir>

WHY THIS EXISTS. kernel/policy/app_profile.c calls disable_seccomp() straight
after commit_creds(). That helper sets current->seccomp.mode = 0 and releases
the filter outright, so every app that takes root through a profile reports

    Seccomp:        0

in /proc/self/status while all its siblings report 2. Android installs a filter
on every app during zygote specialisation and offers no legitimate route back to
mode 0, so that single field is a permissionless self-detection oracle --
measured on an OP15 (CPH2747): 3 of 116 app processes at 0, and those 3 were
exactly the root-using ones.

kernel/hook/setuid_hook.c already does the right thing on its own path: keep the
filter and whitelist only the syscall su needs, through ksu_seccomp_allow_cache().
This rewrites the app_profile call site to that same pattern, copied rather than
invented, and drops the orphaned helper.

Idempotent and self-retiring: a tree whose app_profile.c already calls
ksu_seccomp_allow_cache() is left untouched, so this no-ops the day upstream
fixes the ordering itself.
"""
import io
import os
import re
import sys

GUARD = """{i}if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
{i}    current->seccomp.filter) {{
{i}    spin_lock_irq(&current->sighand->siglock);
{i}    ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
{i}    spin_unlock_irq(&current->sighand->siglock);
{i}}}"""


def die(msg):
    print("::error::fix_ksu_app_profile_seccomp: %s" % msg)
    raise SystemExit(1)


def drop_helper(text):
    """Remove `static void disable_seccomp(void) { ... }` by brace matching."""
    m = re.search(r"^static void disable_seccomp\(void\)\s*\n\{", text, re.M)
    if not m:
        return text, False
    i = text.index("{", m.start())
    depth = 0
    for j in range(i, len(text)):
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


def main():
    if len(sys.argv) != 2:
        die("usage: fix_ksu_app_profile_seccomp.py <ksu-dir>")
    target = os.path.join(sys.argv[1], "kernel/policy/app_profile.c")
    if not os.path.isfile(target):
        print("   app_profile.c not present, nothing to do")
        return

    s = io.open(target, encoding="utf-8", newline="").read()

    if "ksu_seccomp_allow_cache" in s:
        print("   app_profile.c already preserves the filter, nothing to do")
        return

    calls = re.findall(r"^([ \t]*)disable_seccomp\(\);[ \t]*$", s, re.M)
    if not calls:
        print("   app_profile.c does not call disable_seccomp(), nothing to do")
        return
    if len(calls) != 1:
        die("expected one disable_seccomp() call, found %d" % len(calls))

    s = re.sub(r"^([ \t]*)disable_seccomp\(\);[ \t]*$",
               lambda m: GUARD.format(i=m.group(1)), s, count=1, flags=re.M)

    inc = '#include "infra/seccomp_cache.h"\n'
    if inc not in s:
        anchor = '#include "infra/symbol_resolver.h"\n'
        if anchor not in s:
            die("no infra/ include to anchor seccomp_cache.h after")
        s = s.replace(anchor, anchor + inc, 1)

    s, dropped = drop_helper(s)

    if re.search(r"\bdisable_seccomp\b", s):
        die("disable_seccomp still referenced after the rewrite")
    if "ksu_seccomp_allow_cache" not in s:
        die("the rewrite did not land")

    io.open(target, "w", encoding="utf-8", newline="").write(s)
    print("   app_profile.c: filter preserved via ksu_seccomp_allow_cache"
          + (", helper removed" if dropped else ""))


if __name__ == "__main__":
    main()
