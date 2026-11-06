#!/usr/bin/env python3
"""Fail when a KernelSU fork's kernel/selinux/rules.c drifts out of the shape our
SUSFS reconciliations are written against.

The forks live at moving refs, so this breaks with nothing of ours pushed: on
2026-11-06 tiann/KernelSU#3969 reached SukiSU-Ultra@main and KernelSU-Next@dev
and moved the policy-generation bump, which rejected both the KernelSU-Next fix
set and SukiSU's enable-patch reconciliation and took out every build target.
Expectations live in ksu_fork_shapes.tsv beside this file.
"""
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TSV = os.path.join(HERE, "ksu_fork_shapes.tsv")
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/kernel/selinux/rules.c"

COUNTS = {
    "anchor": re.compile(r"reset_avc_cache\(pol->latest_granting\);\n[ \t]*out_unlock:"),
    "bumps": re.compile(r"latest_granting = old_pol->latest_granting \+ 1"),
    "seqno_calls": re.compile(r"reset_avc_cache\(pol->latest_granting\);"),
    "legacy_calls": re.compile(r"reset_avc_cache\(\);"),
}
FIELDS = list(COUNTS)


def fetch(repo, ref):
    url = RAW.format(repo=repo, ref=ref)
    req = urllib.request.Request(url, headers={"User-Agent": "kernel_patches-shape-check"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def main():
    rows = []
    with open(TSV) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 + len(FIELDS):
                sys.exit("::error::malformed row in ksu_fork_shapes.tsv: %r" % line)
            rows.append(parts)
    if not rows:
        sys.exit("::error::ksu_fork_shapes.tsv lists no forks, so this gate checks nothing")

    bad = 0
    for fork, repo, ref, *want in rows:
        want = dict(zip(FIELDS, (int(x) for x in want)))
        try:
            src = fetch(repo, ref)
        except Exception as exc:  # noqa: BLE001 - a fetch failure must not read as a pass
            print("::error::%s: could not fetch %s@%s kernel/selinux/rules.c: %s"
                  % (fork, repo, ref, exc))
            bad += 1
            continue
        got = {k: len(p.findall(src)) for k, p in COUNTS.items()}
        diff = [k for k in FIELDS if got[k] != want[k]]
        shape = "  ".join("%s=%d" % (k, got[k]) for k in FIELDS)
        if diff:
            bad += 1
            print("::error::%s (%s@%s) drifted: %s" % (fork, repo, ref,
                  ", ".join("%s want %d got %d" % (k, want[k], got[k]) for k in diff)))
            print("   full shape: %s" % shape)
            if "anchor" in diff and got["anchor"] == 0:
                print("   The susfs_set_batch_sid() insertion point is gone. "
                      "next/susfs_fix_patches/*/fix_rules.c.patch and the SukiSu builder's "
                      "rules.c recovery both anchor on it, so both will reject.")
            if "bumps" in diff:
                print("   The policy-generation plumbing moved. apply_nomount_stack.sh's "
                      "ksu_seqno_form() keys fix_selinux_seqno off this, so the "
                      "/sys/fs/selinux/status policyload decision changes with it.")
        else:
            print("ok  %-14s %s@%-6s %s" % (fork, repo, ref, shape))

    if bad:
        print("::error::%d fork(s) drifted. Re-fit the affected patch FIRST, then update "
              "scripts/ksu_fork_shapes.tsv in the same commit." % bad)
        return 1
    print("all %d fork(s) match the recorded shape" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
