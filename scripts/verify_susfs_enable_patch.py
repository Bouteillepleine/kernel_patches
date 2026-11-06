#!/usr/bin/env python3
"""Fail when susfs4ksu changes how its own enable patch rewrites rules.c.

verify_ksu_fork_shapes.py watches the KernelSU forks. This watches the other
moving input: susfs4ksu's kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch,
which our fix set is cut against.

Why this exists: on 2026-11-06 susfs4ksu pushed 48b83803 ("KernelSU: Sync with
upstream") to every gki-* branch at ~16:18Z. The sync absorbed
tiann/KernelSU#3969, so the enable patch began deleting both latest_granting
bumps itself -- work next/susfs_fix_patches/v2.3.0/fix_rules.c.patch was already
doing. Two of its three hunks collided and all 81 KernelSU-Next targets failed.
The fork shapes had NOT moved, so `shapes` passed 19 minutes earlier and said
nothing. Only ksun-fixset would have caught it, and that is daily.

This check is three HTTP fetches and a diff, so it belongs in the cheap job.
"""
import difflib
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(HERE, "susfs_enable_rules_c.expected")

# Byte-identical on every branch as of 2026-11-06; a divergence BETWEEN branches
# is itself worth failing on, since it decides which targets break.
BRANCHES = [
    "gki-android12-5.10",
    "gki-android13-5.15",
    "gki-android14-6.1",
    "gki-android15-6.6",
    "gki-android16-6.12",
]
URL = ("https://gitlab.com/api/v4/projects/simonpunk%2Fsusfs4ksu/repository/"
       "files/kernel_patches%2FKernelSU%2F10_enable_susfs_for_ksu.patch/raw?ref={ref}")
MARKER = "diff --git a/kernel/selinux/rules.c"


def fetch(ref):
    req = urllib.request.Request(URL.format(ref=ref),
                                 headers={"User-Agent": "kernel_patches-susfs-check"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def rules_section(patch, ref):
    """The patch's kernel/selinux/rules.c file section, verbatim."""
    lines = patch.split("\n")
    start = None
    end = len(lines)
    for i, line in enumerate(lines):
        if line.startswith(MARKER):
            start = i
            continue
        if start is not None and line.startswith("diff --git "):
            end = i
            break
    if start is None:
        return None
    return "\n".join(lines[start:end])


def main():
    with open(EXPECTED, encoding="utf-8") as fh:
        want = fh.read()

    bad = 0
    for ref in BRANCHES:
        try:
            patch = fetch(ref)
        except Exception as exc:  # noqa: BLE001 - a fetch failure must not read as a pass
            print("::error::%s: could not fetch 10_enable_susfs_for_ksu.patch: %s" % (ref, exc))
            bad += 1
            continue

        got = rules_section(patch, ref)
        if got is None:
            bad += 1
            print("::error::%s: the enable patch no longer touches kernel/selinux/rules.c "
                  "at all. fix_rules.c.patch reconciles a reject that will not happen; "
                  "check whether susfs_set_batch_sid() still gets injected anywhere." % ref)
            continue

        if got == want:
            print("ok  %-20s rules.c section unchanged (%d bytes)" % (ref, len(got)))
            continue

        bad += 1
        print("::error::%s: susfs changed how its enable patch rewrites "
              "kernel/selinux/rules.c" % ref)
        for line in difflib.unified_diff(want.split("\n"), got.split("\n"),
                                         fromfile="scripts/susfs_enable_rules_c.expected",
                                         tofile="susfs4ksu@%s" % ref, lineterm=""):
            print("   %s" % line)

    if bad:
        print("::error::%d branch(es) moved. The enable patch is what "
              "next/susfs_fix_patches/*/fix_rules.c.patch and the SukiSu builder's "
              "rules.c recovery are cut against, so re-fit those FIRST, then "
              "re-record scripts/susfs_enable_rules_c.expected in the same commit." % bad)
        print("::error::Dry-run the fix set with the ksun-fixset job "
              "(workflow_dispatch) before trusting a green build.")
        return 1

    print("all %d branch(es) match the recorded enable-patch section" % len(BRANCHES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
