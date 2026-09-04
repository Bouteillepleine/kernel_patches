#!/usr/bin/env python3
"""Count each hunk's pre-image in its target file, per kernel tree.

WHY THIS EXISTS
---------------
`patch -F0` proves a hunk MATCHES somewhere. It does not prove there is only one
somewhere. When a pre-image occurs more than once in the target file, `patch`
resolves the ambiguity by proximity to the `@@` line number -- which is pinned to
whichever tree the patch was generated against -- so the same file lands its
guard in a different function on every other tree, at fuzz 0, with nothing
reported by anything.

That is not hypothetical. `common/_ghost/ghost_notdir.patch` used three lines of
leading context starting at `nd->path.mnt = NULL;`. `path_lookupat()` and
`path_parentat()` end with the same five lines, so that pre-image occurred TWICE
in `fs/namei.c` on every tree in the fleet, and the guard landed in
`path_parentat()` on 5.10, 5.15, 6.1 and 6.6 -- four of the five kernels the
builders ship -- leaving the whole ENOTDIR oracle family open there. Every
existing assertion stayed green the entire time.

Fuzz 0 is necessary and not sufficient. This is the other half.

USAGE
-----
    check_preimages.py --trees <dir> <patch>...

<dir> holds one subdirectory per kernel version (5.10, 5.15, 6.1, 6.6, 6.12),
each laid out like a kernel source root -- at minimum the files the patches name.
A patch that does not match a tree is NOT an error: that is how per-version
variants are supposed to behave, and `apply_first_of` is what decides which one
is wanted. Only AMBIGUITY fails.

Exit 1 if any hunk's pre-image occurs more than once in any tree.
"""
import argparse
import os
import sys

VERSIONS = ["5.10", "5.15", "6.1", "6.6", "6.12"]


def hunks(path, want_added=False):
    """Yield (target_relpath, preimage_text) for every hunk in a unified diff.

    The pre-image is the context lines plus the removed lines, in order, with the
    diff's leading marker column stripped -- i.e. exactly the bytes `patch` has
    to find in the target file.

    With want_added=True, yields (target, preimage, added_text) instead.
    """
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
        lines = f.read().replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # trailing-newline artefact, not a blank context line

    target, cur, add = None, None, None

    def emit():
        if want_added:
            return (target, "".join(cur), "".join(add))
        return (target, "".join(cur))

    for ln in lines:
        if ln.startswith("--- a/"):
            if cur is not None:
                yield emit()
                cur = add = None
            target = ln[6:].strip()
        elif ln.startswith("+++ "):
            continue
        elif ln.startswith("@@"):
            if cur is not None:
                yield emit()
            cur, add = [], []
        elif cur is not None:
            if ln.startswith((" ", "-")):
                cur.append(ln[1:] + "\n")
            elif ln.startswith("+"):
                add.append(ln[1:] + "\n")
            elif ln == "":
                # A context line that is genuinely blank; some editors drop the
                # leading space. Treat it as context rather than as the end.
                cur.append("\n")
            else:
                yield emit()
                cur = add = None
    if cur is not None:
        yield emit()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trees", required=True,
                    help="directory holding one kernel source tree per version")
    ap.add_argument("--quiet", action="store_true",
                    help="print only ambiguous hunks")
    ap.add_argument("patches", nargs="+")
    args = ap.parse_args()

    bad = 0
    for patch in args.patches:
        name = os.path.basename(patch)
        hs = list(hunks(patch, want_added=True))
        # How many hunks in THIS patch share an identical (pre-image, insertion)
        # pair? That is what makes an ambiguity benign -- see below.
        twins = {}
        for tgt, pre, add in hs:
            twins[(tgt, pre, add)] = twins.get((tgt, pre, add), 0) + 1

        for i, (target, pre, add) in enumerate(hs, 1):
            if not target or not pre.strip():
                continue
            counts = []
            for v in VERSIONS:
                src = os.path.join(args.trees, v, target)
                if not os.path.exists(src):
                    continue
                body = open(src, encoding="utf-8", errors="surrogateescape").read()
                counts.append((v, body.count(pre)))
            if not counts:
                continue
            amb = [(v, c) for v, c in counts if c > 1]
            if not amb:
                if not args.quiet:
                    seen = " ".join(f"{v}:{c}" for v, c in counts)
                    where = "unique" if any(c == 1 for _, c in counts) else "no match"
                    print(f"  {where:9s} {name} hunk {i} ({target}): {seen}")
                continue

            # BENIGN AMBIGUITY, computed rather than allow-listed.
            #
            # If this patch carries exactly as many hunks with an IDENTICAL
            # (pre-image, insertion) pair as the pre-image has occurrences, the
            # outcome is fixed no matter which occurrence each hunk lands on:
            # every site gets a guard and the guards are the same bytes. Each
            # application also rewrites its site, so a later hunk cannot match it
            # again and the hunks necessarily spread across all the occurrences.
            #
            # That is the shape of three selinuxfs write handlers --
            # sel_write_access, sel_write_relabel and sel_write_member have
            # character-identical bodies and take a character-identical guard.
            # Disambiguating them by context IS possible (-U9 does it) and was
            # deliberately not done: it tightens the match against the 60-odd
            # (tree, revision) pairs in the fleet that cannot be dry-run here, to
            # buy a guarantee that verify_hook()'s per-handler assertions already
            # provide by checking each one by name.
            n = twins[(target, pre, add)]
            if all(c == n for _, c in amb):
                if not args.quiet:
                    seen = " ".join(f"{v}:{c}" for v, c in counts)
                    print(f"  benign    {name} hunk {i} ({target}): {seen}"
                          f" -- {n} identical hunks for {n} interchangeable sites")
                continue

            print(f"::error::AMBIGUOUS pre-image: {name} hunk {i} ({target}) "
                  f"occurs more than once -- "
                  f"{' '.join(f'{v}:{c}' for v, c in amb)}. `patch` will resolve "
                  f"it by line number, which is pinned to one tree, so this hunk "
                  f"can land in the wrong function at fuzz 0. Widen the context "
                  f"until it is unique, or -- if the sites really are "
                  f"interchangeable -- give every one of them an identical hunk.")
            bad = 1
    if bad:
        print("::error::at least one hunk has an ambiguous pre-image", file=sys.stderr)
    return bad


if __name__ == "__main__":
    sys.exit(main())
