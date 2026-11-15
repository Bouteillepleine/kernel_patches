#!/usr/bin/env python3
"""Post-patch surgery for experimental/bore_6.12.patch.

Three transforms that cannot live in the patch because their context varies
across the OnePlus 6.12 trees. Run from the kernel source root AFTER applying
bore_6.12.patch. Idempotent; exits non-zero if a transform cannot be placed.

  --dormant   additionally ship BORE compiled-in but inactive
"""
import argparse, re, sys, pathlib

FAIR = pathlib.Path("kernel/sched/fair.c")
BORE = pathlib.Path("kernel/sched/bore.c")

GUARD_BODY = """ {
#ifdef CONFIG_SCHED_BORE
\t\tif (static_branch_likely(&sched_bore_key)) {
\t\t\tif ((static_branch_likely(&sched_burst_protect_slice_cond_key) ||
\t\t\t     static_branch_unlikely(&sched_burst_protect_slice_prefer_key)) &&
\t\t\t    (!entity_is_task(curr) || !bore_futex_waiting(task_of(curr))))
\t\t\t\treturn curr;
\t\t} else
#endif /* CONFIG_SCHED_BORE */
\t\t\treturn curr;
\t}
"""

# Both EEVDF shapes present across the 11 trees. The newer trees carry GKI's
# run-to-parity rework (__pick_eevdf(cfs_rq, bool protect)); the older ones keep
# the guard inline in pick_eevdf(). Same replacement body either way.
GUARD_RE = re.compile(
    r"\n\tif \((?:sched_feat\(RUN_TO_PARITY\) && curr|curr && protect)"
    r" && protect_slice\(curr\)\)\n\t\treturn curr;\n")

def fail(msg):
    sys.stderr.write(f"bore-surgery: ERROR: {msg}\n"); sys.exit(1)

def protect_slice(text):
    """set_protect_slice() reads normalized_sysctl_sched_base_slice, which the
    patch #ifdefs away under CONFIG_SCHED_BORE. Without this the build dies in
    ~39s with 'use of undeclared identifier'. Only the trees carrying GKI's
    run-to-parity rework have set_protect_slice() at all."""
    live  = "\tu64 slice = normalized_sysctl_sched_base_slice;"
    fixed = "\tu64 slice = sysctl_sched_base_slice;"
    if fixed in text and live not in text:
        return text, "already applied"
    if live in text:
        if text.count(live) != 1:
            fail(f"set_protect_slice: {text.count(live)} base-slice reads, expected 1")
        return text.replace(live, fixed, 1), "applied"
    # Absent. Legitimate only when this tree has no set_protect_slice(), leaving
    # the identifier as the dead-branch declaration and nothing else.
    # The invariant that actually matters: no LIVE reference may survive, because
    # the declaration sits in the !CONFIG_SCHED_BORE branch. Older trees carry a
    # set_protect_slice(se) that only stashes vlag and never reads the base slice.
    refs = text.count("normalized_sysctl_sched_base_slice")
    decl = re.search(r"^static unsigned int normalized_sysctl_sched_base_slice\s*=",
                     text, re.M)
    if refs == 1 and decl:
        return text, "not needed (no base-slice read in this tree)"
    fail(f"{refs} reference(s) to normalized_sysctl_sched_base_slice and no "
         "recognised base-slice read - a live one will not compile under BORE")

def pick_guard(text):
    if "bore_futex_waiting(task_of(curr))" in text:
        return text, "already applied"
    n = len(GUARD_RE.findall(text))
    if n != 1:
        fail(f"pick guard: expected exactly 1 run-to-parity return site, found {n}")
    m = GUARD_RE.search(text)
    head = m.group(0).split("\n")[1].rstrip()      # the `if (...)` line itself
    return text[:m.start()] + "\n" + head + GUARD_BODY + text[m.end():], "applied"

def dormant(text):
    """sched_bore=0 alone is NOT enough: every hot path gates on the static key,
    which is DEFINE_STATIC_KEY_TRUE and only flipped by a sysctl write."""
    out, notes = text, []
    for old, new, what in (
        ("DEFINE_STATIC_KEY_TRUE(sched_bore_key);",
         "DEFINE_STATIC_KEY_FALSE(sched_bore_key);", "static key"),
        ("u8   __read_mostly sched_bore                   = 1;",
         "u8   __read_mostly sched_bore                   = 0;", "sched_bore"),
    ):
        if new in out and old not in out:
            notes.append(f"{what} already dormant"); continue
        if out.count(old) != 1:
            fail(f"dormant: expected 1 occurrence of the {what} initialiser, got {out.count(old)}")
        out = out.replace(old, new, 1); notes.append(f"{what} -> dormant")
    return out, "; ".join(notes)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dormant", action="store_true")
    a = ap.parse_args()
    for f in (FAIR, BORE):
        if not f.is_file():
            fail(f"{f} not found - run from the kernel source root")

    t = FAIR.read_text(encoding="utf-8")
    t, s1 = protect_slice(t)
    t, s2 = pick_guard(t)
    FAIR.write_text(t, encoding="utf-8")
    print(f"bore-surgery: set_protect_slice: {s1}")
    print(f"bore-surgery: pick-eevdf guard:  {s2}")

    if a.dormant:
        b = BORE.read_text(encoding="utf-8")
        b, s3 = dormant(b)
        BORE.write_text(b, encoding="utf-8")
        print(f"bore-surgery: dormant:           {s3}")

if __name__ == "__main__":
    main()
