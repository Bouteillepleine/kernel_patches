#!/usr/bin/env python3
"""Verify a bore_6.12.patch + bore_612_surgery.py application.

Two checks that matter, after the 5.10 lesson that `patch -F3` can apply a hunk
into the wrong place with zero rejects:

  1. every BORE hook sits inside the function that must call it
  2. no identifier declared ONLY in a !CONFIG_SCHED_BORE branch is referenced
     from live code (this is what catches the normalized_sysctl_sched_base_slice
     class of break, which costs a 39s build to discover otherwise)

usage: verify_bore_612.py <patched-tree-root>
"""
import re, sys, pathlib

root = pathlib.Path(sys.argv[1])
FUNC = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t\*\(\),]*\(")

# (file, hook text, one of the enclosing functions it is allowed to sit in)
SITES = [
    ("kernel/fork.c",            "task_fork_bore(p, current, clone_flags",   ["copy_process"]),
    ("kernel/fork.c",            "p_bore(tsk) = NULL;",                      ["dup_task_struct"]),
    ("kernel/fork.c",            "sched_bore_free(tsk);",                    ["free_task"]),
    ("kernel/exit.c",            "list_del_rcu(&p->sibling);",               ["__unhash_process"]),
    ("kernel/sched/core.c",      "sched_bore_init();",                       ["sched_init"]),
    ("kernel/sched/fair.c",      "update_curr_bore(",                        ["update_curr"]),
    ("kernel/sched/fair.c",      "bore_futex_waiting(task_of(curr))",        ["__pick_eevdf", "pick_eevdf"]),
    ("kernel/sched/fair.c",      "bore_futex_waiting(task_of(se))",          ["place_entity"]),
    ("kernel/sched/fair.c",      "u64 slice = sysctl_sched_base_slice;",     ["set_protect_slice"]),
    ("kernel/futex/waitwake.c",  "bctx->futex_waiting = true;",              ["futex_wait_queue"]),
]

def enclosing(lines, idx):
    depth = 0
    for i in range(idx, -1, -1):
        s = lines[i]
        if s.startswith("}"):
            depth += 1
        elif FUNC.match(s) and not s.rstrip().endswith(";") and not s.startswith("#"):
            if depth == 0:
                return s
            depth -= 1
    return None

problems, checked = [], 0
for rel, needle, allowed in SITES:
    fp = root / rel
    if not fp.is_file():
        problems.append(f"{rel}: missing"); continue
    lines = fp.read_text(encoding="utf-8", errors="replace").split("\n")
    hits = [i for i, l in enumerate(lines) if needle in l]
    if not hits:
        # set_protect_slice only exists on the run-to-parity trees
        if needle.startswith("u64 slice ="):
            print(f"  skip  {rel}: no set_protect_slice in this tree"); continue
        problems.append(f"{rel}: hook not found: {needle!r}"); continue
    ok = False
    for i in hits:
        enc = enclosing(lines, i) or ""
        if any(a + "(" in enc or enc.strip().startswith(a) for a in allowed):
            ok = True; break
    if ok:
        checked += 1
    else:
        problems.append(f"{rel}: {needle!r} is not inside {'/'.join(allowed)}() "
                        f"- found in {(enclosing(lines, hits[0]) or '<file scope>').strip()[:60]!r}")

# ---- dead-branch identifiers (CONFIG_SCHED_BORE taken as defined)
FDECL = re.compile(r"^(?:static\s+|extern\s+)?(?:__read_mostly\s+)?(?:const\s+)?"
                   r"(?:unsigned\s+|signed\s+)?(?:u8|u16|u32|u64|int|uint|long|bool|void|char)"
                   r"\s+\**([A-Za-z_][A-Za-z0-9_]*)\s*(?:[=;\[]|\()")
for rel in sorted({s[0] for s in SITES} | {"kernel/sched/sched.h", "kernel/sched/debug.c"}):
    fp = root / rel
    if not fp.is_file(): continue
    live, dead, stack = [], [], []
    for line in fp.read_text(encoding="utf-8", errors="replace").split("\n"):
        st = line.strip()
        if re.match(r"#\s*if(n?def)?\b", st):
            on = None
            if re.match(r"#\s*ifdef\s+CONFIG_SCHED_BORE\b", st): on = True
            elif re.match(r"#\s*ifndef\s+CONFIG_SCHED_BORE\b", st): on = False
            elif re.match(r"#\s*if\s*!\s*defined\s*\(\s*CONFIG_SCHED_BORE\s*\)", st): on = False
            elif re.match(r"#\s*if\s+defined\s*\(\s*CONFIG_SCHED_BORE\s*\)", st): on = True
            stack.append(on); continue
        if re.match(r"#\s*elif\b", st):
            continue
        if re.match(r"#\s*else\b", st):
            if stack and stack[-1] is not None: stack[-1] = not stack[-1]
            continue
        if re.match(r"#\s*endif\b", st):
            if stack: stack.pop()
            continue
        (dead if False in stack else live).append(line)
    def fdecls(ls):
        return {m.group(1) for l in ls for m in [FDECL.match(l)] if m}
    only_dead = fdecls(dead) - fdecls(live)
    live_txt = "\n".join(live)
    for ident in sorted(only_dead):
        if re.search(r"\b" + re.escape(ident) + r"\b", live_txt):
            problems.append(f"{rel}: {ident!r} is declared only in a "
                            "!CONFIG_SCHED_BORE branch but referenced from live code")

print(f"verify: {checked} hook sites confirmed")
if problems:
    print(f"verify: {len(problems)} PROBLEM(S)")
    for p in problems: print("  - " + p)
    sys.exit(1)
print("verify: OK")
