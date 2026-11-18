#!/usr/bin/env python3
"""Find cloak hunks that make a SUSFS hunk reject that would otherwise apply.

WHY THIS EXISTS
---------------
This stack applies its cloaks in `do_ghost`/`do_hook`/`do_pathhide`, and SUSFS's
`50_add_susfs_in_gki-*.patch` lands AFTER them. Both edit the same VFS. When the
two want the same junction -- the gap between the same two lines of the same
function -- whoever goes first wins the pre-image and the other rejects at fuzz 0.

Nothing we had could see that coming. `check_preimages.py` proves a hunk is
unambiguous in its target file; `assert_guard_sites.py` and the `infn` assertions
prove a guard landed in the right function. Both ran green. The conflict is with
a patch applied two stages later, against a tree neither check has in hand.

Measured: run 44303124210, 2026-11-18. `ghost_statfs.patch` guarded
`vfs_statfs()` by inserting between `int error;` and the `statfs_by_dentry()`
call. SUSFS puts its `sus_kstat` and `sus_mount` arms in that exact gap. All five
build jobs died in the SUSFS stage on `fs/statfs.c` hunk #3, after ~4 minutes of
runner time each. The fix was to defer the guard to `do_postsusfs()`; this gate
is so the next one is caught in seconds instead.

HOW IT DECIDES
--------------
By cross-applying, not by comparing patch text. A junction is NOT identified by
the two lines around it: `int error;` followed by a blank line occurs in a dozen
functions per file, so a textual rule flags `ghost_statx` against a SUSFS hunk in
an unrelated function and buries the one real hit in 77 false ones. That version
of this script was written and thrown away.

So, per kernel version and per file, it measures:

    baseline  = SUSFS hunks that reject on the pristine file
    with-ours = SUSFS hunks that reject after one of our patches is applied

Anything in with-ours that is not in baseline is a reject WE caused. SUSFS has
its own standing rejects -- `kernel/sys.c` hunk #5 fails on 5.10/5.15/6.1 with or
without us, and `apply_susfs_kernel.sh` already carries that in
`expected_rejects()` -- so the baseline is what keeps those from being blamed on
a cloak.

Patches are applied ONE AT A TIME, which is not how a build applies them, and is
deliberate: it names the single patch responsible instead of reporting that the
stack as a whole conflicts somewhere.

Patches applied after SUSFS are exempt, and the exempt set is READ OUT OF
`apply_nomount_stack.sh`'s `do_postsusfs()` rather than listed here -- a patch
moved into or out of that stage changes this gate with it, and a hand-kept list
would go stale the first time someone deferred something.

USAGE
-----
    check_susfs_collisions.py --trees <dir> --susfs <dir> [--stack <script>] <patch>...
    check_susfs_collisions.py --fetch-susfs <dir>     # the five gki patches

<trees> holds one subdirectory per kernel version (5.10, 5.15, 6.1, 6.6, 6.12),
each laid out like a kernel source root -- the same layout check_preimages.py
takes, so a CI job that builds one can hand it to both.

Exit 1 if any non-deferred patch newly breaks a SUSFS hunk.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

VERSIONS = ["5.10", "5.15", "6.1", "6.6", "6.12"]
BRANCH = {
    "5.10": "android12-5.10",
    "5.15": "android13-5.15",
    "6.1": "android14-6.1",
    "6.6": "android15-6.6",
    "6.12": "android16-6.12",
}
RAW = ("https://gitlab.com/simonpunk/susfs4ksu/-/raw/gki-{b}"
       "/kernel_patches/50_add_susfs_in_gki-{b}.patch")


def split_by_file(patch_path):
    """-> {filename: diff-text}, one self-contained single-file diff each."""
    out, cur, buf = {}, None, []
    with open(patch_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("--- "):
                if cur and buf:
                    out[cur] = "".join(buf)
                m = re.match(r"--- (?:a/)?(\S+)", line)
                cur, buf = (m.group(1) if m else None), [line]
                continue
            if cur is None:
                continue
            if line.startswith("diff ") or line.startswith("index "):
                # start of the next file's header block
                if line.startswith("diff "):
                    out[cur] = "".join(buf)
                    cur, buf = None, []
                continue
            buf.append(line)
    if cur and buf:
        out[cur] = "".join(buf)
    return out


def failed_hunks(src_file, target_rel, diff_text, workdir):
    """Apply diff_text to a fresh copy of src_file; -> set of failed hunk numbers."""
    root = tempfile.mkdtemp(dir=workdir)
    dest = os.path.join(root, target_rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copyfile(src_file, dest)
    p = subprocess.run(["patch", "-p1", "-F0", "--forward", "-d", root],
                       input=diff_text, capture_output=True, text=True)
    out = p.stdout + p.stderr
    return set(re.findall(r"Hunk #(\d+) FAILED", out)), root


def expected_rejects(susfs_script, version):
    """The file:hunk specs apply_susfs_kernel.sh already records for this KMI.

    Some of our guards take a junction SUSFS wants ON PURPOSE -- ghost_o_path
    and SUSFS's OPEN_REDIRECT both guard do_o_path()'s `if (!error) {`, and
    susfs_patch_surgery.py re-places the SUSFS hunk by content afterwards. Those
    are registered, with a reason, and must not be reported here: a gate that
    cried wolf on four long-standing entries would be turned off within a week.

    An unregistered new reject is the bug. That is the whole difference between
    ghost_o_path, which has shipped for months, and ghost_statfs, which did not.
    """
    if not susfs_script or not os.path.exists(susfs_script):
        return None
    src = open(susfs_script, encoding="utf-8", errors="replace").read()
    m = re.search(r"^expected_rejects\(\)\s*\{(.*?)^\}", src, re.S | re.M)
    if not m:
        return None
    body, key = m.group(1), BRANCH[version]
    specs, arm = set(), None
    for block in re.finditer(r"(?:(android\d+-[\d.]+)\)\s*)?cat <<'EOT'\n(.*?)\nEOT",
                             body, re.S):
        arm, text = block.group(1), block.group(2)
        if arm is not None and arm != key:
            continue
        for line in text.splitlines():
            tok = line.split()
            if tok and ":" in tok[0]:
                specs.add(tok[0])
    return specs


def deferred_patches(stack_path):
    if not stack_path or not os.path.exists(stack_path):
        return set()
    src = open(stack_path, encoding="utf-8", errors="replace").read()
    m = re.search(r"^do_postsusfs\(\)\s*\{(.*?)^\}", src, re.S | re.M)
    return set(re.findall(r"([A-Za-z0-9_.-]+\.patch)", m.group(1))) if m else set()


def fetch(dest):
    os.makedirs(dest, exist_ok=True)
    for b in BRANCH.values():
        out = os.path.join(dest, "50_add_susfs_in_gki-%s.patch" % b)
        with urllib.request.urlopen(RAW.format(b=b), timeout=90) as r:
            data = r.read()
        open(out, "wb").write(data)
        print("fetched %s (%d bytes)" % (os.path.basename(out), len(data)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trees")
    ap.add_argument("--susfs")
    ap.add_argument("--fetch-susfs", dest="fetch_susfs")
    ap.add_argument("--stack", default="scripts/apply_nomount_stack.sh")
    ap.add_argument("--susfs-script", default="scripts/apply_susfs_kernel.sh",
                    help="apply_susfs_kernel.sh, read for expected_rejects()")
    ap.add_argument("patches", nargs="*")
    args = ap.parse_args()

    if args.fetch_susfs:
        fetch(args.fetch_susfs)
        return 0
    if not (args.trees and args.susfs and args.patches):
        ap.error("--trees, --susfs and at least one patch are required")

    skip = deferred_patches(args.stack)
    if skip:
        print("deferred past SUSFS (exempt, from %s): %s"
              % (args.stack, ", ".join(sorted(skip))))

    susfs_by_ver = {}
    for v in VERSIONS:
        p = os.path.join(args.susfs, "50_add_susfs_in_gki-%s.patch" % BRANCH[v])
        if os.path.exists(p):
            susfs_by_ver[v] = split_by_file(p)

    ours = {p: split_by_file(p) for p in args.patches
            if os.path.basename(p) not in skip}

    work = tempfile.mkdtemp(prefix="susfs-collide-")
    hits, registered, pairs, skipped_missing = [], [], 0, set()
    try:
        for v, sfiles in sorted(susfs_by_ver.items()):
            tree = os.path.join(args.trees, v)
            if not os.path.isdir(tree):
                continue
            allowed = expected_rejects(args.susfs_script, v)
            if allowed is None:
                sys.exit(
                    "cannot read expected_rejects() from %s -- refusing to "
                    "report.\nWithout it every deliberate collision reads as "
                    "new (22 of them on the current tree), so the gate would "
                    "fail the build on patches that are correct. Pass "
                    "--susfs-script an ABSOLUTE path: callers that cd into "
                    "the kernel tree do not resolve the relative default."
                    % args.susfs_script)
            baseline = {}
            for fname, sdiff in sfiles.items():
                src = os.path.join(tree, fname)
                if not os.path.exists(src):
                    continue
                fails, root = failed_hunks(src, fname, sdiff, work)
                baseline[fname] = fails
                shutil.rmtree(root, ignore_errors=True)

            for ppath, ofiles in ours.items():
                for fname, odiff in ofiles.items():
                    if fname not in baseline:
                        src = os.path.join(tree, fname)
                        if fname in sfiles and not os.path.exists(src):
                            skipped_missing.add((v, fname))
                        continue
                    src = os.path.join(tree, fname)
                    # our patch first; a variant that does not fit this tree is
                    # not an error -- apply_first_of decides which one is wanted
                    root = tempfile.mkdtemp(dir=work)
                    dest = os.path.join(root, fname)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copyfile(src, dest)
                    pre = subprocess.run(
                        ["patch", "-p1", "-F0", "--forward", "-d", root],
                        input=odiff, capture_output=True, text=True)
                    if pre.returncode != 0:
                        shutil.rmtree(root, ignore_errors=True)
                        continue
                    pairs += 1
                    after = subprocess.run(
                        ["patch", "-p1", "-F0", "--forward", "-d", root],
                        input=sfiles[fname], capture_output=True, text=True)
                    now = set(re.findall(r"Hunk #(\d+) FAILED",
                                         after.stdout + after.stderr))
                    shutil.rmtree(root, ignore_errors=True)
                    caused = now - baseline[fname]
                    reg = {h for h in caused if "%s:%s" % (fname, h) in allowed}
                    new = sorted(caused - reg, key=int)
                    if reg:
                        registered.append((os.path.basename(ppath), v, fname,
                                           sorted(reg, key=int)))
                    if new:
                        hits.append((os.path.basename(ppath), v, fname, new,
                                     sorted(baseline[fname], key=int)))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("cross-applied %d (patch, file, version) pairs" % pairs)
    for v, fname in sorted(skipped_missing):
        print("  note: %s not in trees/%s, not checked" % (fname, v))

    if registered:
        print("\nregistered in expected_rejects() -- deliberate, re-placed by "
              "susfs_patch_surgery.py:")
        for base, v, fname, hs in sorted(registered):
            print("  %-42s %-5s %s:%s" % (base, v, fname,
                                          ",".join(hs)))

    if not hits:
        print("\nno UNREGISTERED collisions: every SUSFS hunk our patches break "
              "is one expected_rejects() already accounts for")
        return 0

    for base, v, fname, new, pre_existing in hits:
        print("\nCOLLISION  %s  on  %s" % (base, v))
        print("  %s: SUSFS hunk(s) %s reject only after this patch applies,"
              % (fname, ", ".join("#" + h for h in new)))
        print("  and %s is not in expected_rejects()"
              % ", ".join("%s:%s" % (fname, h) for h in new))
        if pre_existing:
            print("  (hunk(s) %s already rejected without it -- not ours)"
                  % ", ".join("#" + h for h in pre_existing))
    print("\n%d new reject(s)." % len(hits))
    print("""
This stack applies first, so SUSFS is the one that rejects -- the build dies in
the SUSFS stage naming a file our patch touched, which reads like SUSFS drift and
is not. Pick one:

  * Defer the guard to do_postsusfs() and cut a variant against the shape SUSFS
    produces, probing the tree for it rather than trusting susfs_ref. That is
    what ghost_statfs does; the deferral has to be stamped so the pre-SUSFS
    verify reports it instead of reporting a missing guard.
  * Move the guard to a different function that reaches the same syscalls and
    that SUSFS does not touch.

Do NOT register the SUSFS hunk as an expected reject: that silently drops the
SUSFS behaviour it carries, which on fs/statfs.c would be its whole sus_kstat
and sus_mount handling.""")
    return 1


if __name__ == "__main__":
    sys.exit(main())
