# `_ghost` — make a hidden NoMount path look *absent*, not merely inaccessible

NoMount injects files into read-only ROM partitions by hijacking per-inode
`inode_operations`/`file_operations`, and hides them per-uid: for a blocked uid
every op it controls answers `-ENOENT`, so the partition looks stock.

Four VFS surfaces have **no filesystem op to hijack**. The engine cannot answer
them, so on those four a hidden path is distinguishable from a genuinely absent
one. All four were measured on a live OP15 (Android 16, 6.12.23) against all 24
blocked uids, with a 7020-path genuinely-absent control that produced **zero**
false positives:

| probe | hidden injected path | truly absent path |
|---|---|---|
| `open(p, O_PATH)` + `readlink("/proc/self/fd/N")` | succeeds, returns the full path | `ENOENT` |
| `getxattr(p, "security.selinux")` | succeeds, returns the label | `ENOENT` |
| `stat(p "/zzz")` | `ENOTDIR` | `ENOENT` |
| `link(p, "/data/local/tmp/x")` | `EXDEV` | `ENOENT` |

This directory closes all four. `ghost.c` supplies one predicate,
`ghost_hidden_path()`; the per-version `ghost_*.patch` files place one guard per
oracle, each of which answers `-ENOENT`.

## Files

| file | what it is |
|---|---|
| `ghost.c` / `ghost.h` | the predicate and its control plane. Copy **both** into `fs/proc/`, next to `_pathhide`'s `pathhide.c`/`.h` |
| `ghost_build_integration.patch` | optional `obj-y += ghost.o` for the `fs/proc/` drop-in layout |
| `ghost_o_path*.patch` | guard in `do_o_path()`, `fs/namei.c` |
| `ghost_xattr*.patch` | guards in all four `path_*xattr()` wrappers, `fs/xattr.c` |
| `ghost_linkat*.patch` | guard in `do_linkat()`, `fs/namei.c` |
| `ghost_notdir*.patch` | guard in `link_path_walk()`, `fs/namei.c` |

Each family has variants; a builder applies the **first that dry-runs clean**,
newest-shape first, and fails the build if none does. See the coverage table.

## How the guard knows a path is hidden

The engine's own predicate, `nm_hidden_from_caller()`, lives in the nomount
driver in `kbuild@hookless` and is reachable only from the hijacked ops. A guard
in `fs/namei.c` or `fs/xattr.c` runs *before* any op dispatch and cannot call it
without making core VFS depend on the engine — which would stop these patches
applying to a tree that does not carry it, and would couple two patch sets that
are deliberately independent.

So `ghost.c` keeps its own copy of the decision, pushed down from userspace over
the control plane `_pathhide` already uses. **It is a replica**, and everything
about its shape follows from what happens when a replica drifts:

```
hidden(path, caller)  ==  path ∈ ghost path table  ∧  uid(caller) ∈ ghost uid table
```

Two tables, both global, because that is exactly the shape of the engine's own
state: one injected-path set, one blocked-uid set (`/data/adb/nomount/uidhide`,
resolved to uids in `uidhide.cache`). Nothing per-rule-per-uid is needed.

### Differences from `_pathhide`, and why each one exists

`_pathhide` was the model — same per-CPU `PATH_MAX` buffer, same `d_path()`
render, same plain `spin_lock`, same weak-extern control plane, same refusal to
own a `/proc` node. Three things are deliberately **not** copied:

* **Exact match, not substring.** A wrong match in `pathhide_match_file()` omits
  a `/proc/<pid>/maps` line. A wrong match here returns `-ENOENT` to a syscall.
  `pathhide.c`'s own header records the cost of substrings — measured against
  system_server's 5442 file-backed mappings on OP15, the needle `lib` matched
  2270 of them and `/system/` matched 1638. The same needle here would delete
  30% of `/system` from 24 apps. Compare the OxC bootloop, where one
  `nm add /product` rule on a partition **root** masked the overlays and took
  SystemUI down with `SIGABRT`. Rules are absolute paths matched whole; a
  trailing `/` makes a rule match the subtree strictly below it.
* **A uid table.** `_pathhide` hides from everyone; this hides per-uid, because
  a non-blocked uid must keep seeing the injected file.
* **`ghost_rule_sane()`.** Refuses a rule that is not absolute, contains `//`,
  or has fewer than two `/` (three for a subtree rule) — so `/system/build.prop`
  is accepted and a bare `/system`, `/vendor`, `/product` is not. A backstop for
  operator error, not a security boundary.

### The contract userspace must honour

**Only paths that exist *because* of injection and that the engine already
answers `-ENOENT` for.** Never a path that also exists on the stock partition.

NoMount both **adds** new paths and **overrides** existing ones. For an
override, a blocked uid must see the **stock** file — not nothing. Feeding an
override path to this table makes a real, shipped ROM file vanish for those
uids: a functional regression the engine would never produce on its own.

The failure directions are asymmetric on purpose, and that asymmetry is the
safety argument for the whole design:

| table state | consequence |
|---|---|
| **missing** an injected path | the four oracles stay open for it — i.e. exactly today's behaviour. Harmless. |
| **holding** a non-hidden path | a file the uid is entitled to see returns `-ENOENT` from `open(O_PATH)`, all four `*xattr(2)`, `link(2)`, and any lookup that walks *through* it. Apps break. |

`ghost.c` therefore fails **open** on every internal error — empty tables,
`d_path()` failure, buffer exhaustion — and never fails closed.

### Nothing here configures it

Same arrangement, and the same caveat, as `_pathhide`'s M-C8. The control plane
is nomount's private **CAP_NET_ADMIN** raw-netlink channel, which must forward
`NM_KNOB_GHOST → ghost_ctl()` and `NM_CMD_GET_GHOST → ghost_get_rule()` through
**weak** externs. That forwarder is supplied by the nomount engine repo, **not**
by `kernel_patches`.

A kernel built from `_ghost` alone links, boots, and matches correctly — but its
tables stay empty forever, so `ghost_hidden_path()` short-circuits to `false` on
its first line and every guard is dead code. That is a **safe** state, identical
to an unpatched kernel, not a broken one. Ship both, or ship neither.

There is deliberately **no** `/proc` node, not even an opt-in one.
`_pathhide` measured what such a node costs: on OP15 (2026-08-23), from a real
app domain, `untrusted_app`/`app_zygote`/`priv_app` all hold `proc:dir read`, so
a plain `readdir` of `/proc` listed the entry and announced the patch to
anything that looked. A file whose job is concealing the existence of files must
not own a name no stock kernel has.

## The placement rule — and why it *inverts* `_hook`'s

`common/_hook/README.md` states the rule that matters most in this repo:

> A guard must sit **after** the stock permission check, never before it.

That rule shipped broken once and turned the cloak into a one-syscall root
oracle on 5.10/5.15/6.1. **Every guard in `_ghost` sits before the file-level
permission check, and that is correct.** The two are not in conflict, because
they cloak different things:

* `_hook` cloaks a **string** (a SELinux type) inside a syscall that reaches the
  same code whether the string is hidden or not. A domain lacking the permission
  gets `EACCES` from stock for *any* string. A guard at function entry would
  answer `EINVAL`-for-hidden but `EACCES`-for-garbage — the cloak becomes the
  detector. So it must land after `avc_has_perm()`.
* `_ghost` cloaks the **existence of a path component**. For a name that
  genuinely does not exist, the kernel *never performs a file-level permission
  check at all* — the lookup fails first. So the faithful emulation is to fail
  at exactly the point the lookup would have failed, ahead of every file-level
  check. A guard placed *after* a permission check would answer `EACCES` where an
  absent name answers `ENOENT` — which is the same inversion, in the other
  direction.

The parent directory's permissions are still enforced in every case, because
every guard runs only *after* `path_lookupat()` / `user_path_at()` has returned
success, and that lookup already enforced parent search permission. A caller who
cannot search the parent gets `EACCES` out of the lookup and never reaches a
guard — exactly as it would for an absent name.

Anyone adding a fifth guard must satisfy both halves: **after the lookup
succeeds, before anything checks the file itself.**

## Ranking — severity × safety

Ordered as they should be adopted. If only some are shipped, ship a prefix of
this list.

| # | oracle | severity | risk | site |
|---|---|---|---|---|
| **1** | `O_PATH` | **highest** — returns the full path, one syscall pair, no privileges | **lowest** — `do_o_path()` is 10 lines, reached only by `O_PATH` opens, and is byte-identical v4.19→master | `fs/namei.c` `do_o_path()` |
| **2** | `getxattr` / `listxattr` / `setxattr` / `removexattr` | **high** — returns the SELinux label | **low** — cold syscall wrappers in `fs/xattr.c`, no in-kernel callers | `fs/xattr.c` `path_*xattr()` |
| **3** | `link()` `EXDEV` | low — one bit | **low** — `do_linkat()` is reached only by `link(2)`/`linkat(2)` | `fs/namei.c` `do_linkat()` |
| **4** | `stat(p "/zzz")` `ENOTDIR` | low — one bit | **moderate** — the guard is *cold* (inside an existing `unlikely()` error branch, evaluated only on a walk already failing) but it lives in `link_path_walk()`, the hottest function in the VFS. A misapplied hunk there is a bootloop | `fs/namei.c` `link_path_walk()` |

Two things about this ranking are worth spelling out, because both cut against
the obvious guess:

* **`ENOTDIR` is much cheaper than it looks.** The natural fear is "a guard in
  the hot lookup path". It is not on the hot path: the enclosing
  `if (unlikely(!d_can_lookup(...)))` branch is entered only when the walk is
  already returning an error. The common case never evaluates it. It ranks last
  on *blast radius if the hunk lands wrong*, not on cost.
* **The `*xattr` guard is worth doing on all four wrappers or none.** `getxattr`
  is the loud one, but `listxattr`, `setxattr` and `removexattr` are three
  independent one-syscall probes of the same bit (`setxattr` on a read-only ROM
  partition gives `EROFS` where an absent name gives `ENOENT`). Closing only
  `getxattr` carries all the risk of a cloak and buys nothing. Same logic as
  `_hook`'s rule that a hidden type has to be added at every call site.

## Coverage — which variant covers which tree

Every cell below was produced by `patch -p1 -F0 --dry-run` **and**
`git apply --check`, against real sources, and confirmed to apply with **zero
fuzz** (offsets only — line numbers are pinned to one tree). Each variant was
also confirmed to **fail** on the trees it does not claim, so a builder's
`apply_first_of` cannot silently pick the wrong one.

Vanilla sources: `https://raw.githubusercontent.com/torvalds/linux/<tag>/fs/…`
for `v4.9 v4.14 v4.19 v5.4 v5.10 v5.15 v6.1 v6.6 v6.12 master`.

Pinned OnePlus trees, resolved the way `.github/workflows/verify-hook-pathhide.yml`
resolves them (all 69 manifests in `Bouteillepleine/OnePlus-ReSukiSu_NMS@NoMount:manifests/a16`,
ranked branch-shaped-revision > raw SHA, then `*_common_oneplus_sm*`, tie-broken
on SoC descending):

| ver | `OnePlusOSS/<repo>@<revision>` |
|---|---|
| 5.10 | `android_kernel_common_oneplus_sm8475@oneplus/sm8475_b_16.0.0_ace_2` |
| 5.15 | `android_kernel_common_oneplus_sm8550@oneplus/sm8550_b_16.0.0_ace_2_pro` |
| 6.1 | `android_kernel_common_oneplus_sm8650@oneplus/sm8650_b_16.0.0_ace_3_pro` |
| 6.6 | `android_kernel_common_oneplus_sm8750@oneplus/sm8750_b_16.0.0_ace_6` |
| 6.12 | `android_kernel_common_oneplus_sm8850@oneplus/sm8850_b_16.0.0_oneplus_15` |

| family | variant | applies to |
|---|---|---|
| **o_path** | `ghost_o_path.patch` | v4.19 v5.4 v5.10 v5.15 v6.1 v6.6 v6.12 **master**, op-5.10 op-5.15 op-6.1 op-6.6 op-6.12 |
| | `ghost_o_path_legacy.patch` | v4.9 v4.14 (`vfs_open()` takes `current_cred()`) |
| **xattr** | `ghost_xattr_6_12.patch` | v6.12, **op-6.6**, op-6.12 |
| | `ghost_xattr_6_6.patch` | v6.6 only |
| | `ghost_xattr_5_15.patch` | v5.15 v6.1, op-5.15 op-6.1 |
| | `ghost_xattr.patch` | v4.9 v4.14 v4.19 v5.4 v5.10, op-5.10 |
| **linkat** | `ghost_linkat_5_15.patch` | v5.15 v6.1 v6.6 v6.12, op-5.15 op-6.1 op-6.6 op-6.12 |
| | `ghost_linkat.patch` | v4.9 v4.14 v4.19 v5.4 v5.10, op-5.10 |
| **notdir** | `ghost_notdir.patch` | v5.15 v6.1 v6.6 v6.12 **master**, **all five** op trees |
| | `ghost_notdir_5_10.patch` | v5.10 only |
| **build** | `ghost_build_integration.patch` | every tree above, v4.9 → master |

Apply order for each family: **newest variant first**, fallback last — the same
ordering `_hook`'s builder uses for `hide_selinux_attr*`.

### Version-specific shapes worth knowing before editing these

* **`do_o_path()` is byte-identical v4.19 → torvalds/master**, and on all five
  pinned OnePlus trees (verified by md5 of the extracted function body). One
  hunk covers 13 of the 15 trees tested. Only v4.9/v4.14 differ, and only in the
  `vfs_open()` argument list.
* **OnePlus's android15-6.6 tree carries the 6.12-era `fs/xattr.c` restructure**
  (`setxattr_copy()`/`xattr_ctx`, `do_setxattr()`, the `kname` buffer in
  `path_removexattr()`), so it groups with 6.12, **not** with vanilla v6.6. That
  is the entire reason `ghost_xattr_6_6.patch` exists as a separate file — it
  covers a shape no tree in the fleet actually has, and would be dead weight if
  the fleet were the only consumer. Do not "simplify" by merging them.
* **OnePlus's android12-5.10 tree carries `try_to_unlazy()`** in
  `link_path_walk()` where vanilla v5.10 still has `unlazy_walk()`. So
  `ghost_notdir.patch` covers all five OnePlus trees despite being labelled for
  5.15+, and `ghost_notdir_5_10.patch` exists only for a build from AOSP common
  android12-5.10.
* **`path_listxattr()` is byte-identical on all 14 trees** that have it — the
  only one of the four xattr wrappers that never changed shape.
* **Hand-writing these hunks does not work.** Every patch here was generated by
  editing a real source file and running `diff -u`, then dry-run against all 15
  trees. Hand-written hunks with correct pre-image text and correct `@@` counts
  were rejected by both `patch` and `git apply`; the generated ones are correct
  by construction. If you regenerate, do it the same way, and re-check at `-F0`:
  a hunk that only applies *with fuzz* can land a guard in the wrong function
  silently — three of the four `path_*xattr()` wrappers have bodies that are
  character-for-character identical below `retry:`.

### Compile verification

Not just dry-run. On the **real OP15 tree** (`android_kernel_common_oneplus_sm8850`,
6.12.23, the kernel this phone runs), with `ARCH=arm64 LLVM=1 LLVM_IAS=1`:

* `ghost.c` compiles clean — no errors, no warnings.
* With `ghost_o_path` + `ghost_xattr_6_12` + `ghost_linkat_5_15` +
  `ghost_notdir` + `ghost_build_integration` all applied, `fs/namei.o` and
  `fs/xattr.o` compile clean.
* Building the whole `fs/` directory pulls `ghost.o` in through the `obj-y`
  wiring and it lands in `fs/proc/built-in.a` exporting `ghost_hidden_path` and
  `ghost_ctl`. This matters because `make fs/proc/ghost.o` on its own proves
  nothing about wiring — kbuild will build a single object that is not in
  `obj-y` at all.

The tree was restored to its prior state afterwards.

**Not boot-tested.** Nothing here has run on a device.

### Co-existence with `_pathhide`

Both patch sets add a line to `fs/proc/Makefile`. They are anchored at different
places on purpose — `_pathhide` at `obj-y += proc.o` (lines 6–7), `_ghost` after
`proc-$(CONFIG_MMU) := task_mmu.o` (lines 9–10) — so they never overlap and
apply in **either order**, the second picking up an offset of 1. Verified both
orders on all five OnePlus trees.

Applying the full `_ghost` set together was verified end to end on all five
OnePlus trees and on vanilla v5.10 → v6.12: three of the patches touch
`fs/namei.c` and none of them conflicts.

## CI wiring this would need (not done here — do not wire it yourself)

`_ghost` is invisible to CI as it stands. Both existing workflows filter on
paths:

* `.github/workflows/verify-patches-oneplus.yml` — dry-runs every patch against
  every `(tree, revision)` in the fleet. Broad, no compile. `_ghost` needs to be
  added to whatever it enumerates, **and** it needs the `apply_first_of`
  semantics: a `_ghost` family is green when *exactly one* variant applies, not
  when all do. A naive "every patch must apply to every tree" assertion will
  fail this directory by design.
* `.github/workflows/verify-hook-pathhide.yml` — compiles the objects the
  patches touch, on one representative OnePlus tree per version. `_ghost` needs
  `fs/namei.o`, `fs/xattr.o` and `fs/proc/ghost.o` added to its object list, and
  `common/_ghost/**` added to the `on: push/pull_request` `paths:` filters.
  Note the lesson recorded in that file's own header: a workflow that only fires
  on `ci/verify-patches` lets a break sit unnoticed for days.

One assertion worth adding while doing it, in the spirit of that workflow's
`selnl_notify_policyload` check: assert that `ghost.c` contains **no**
`proc_create` call. The absence of a `/proc` node is a measured stealth
property, and it should not be possible to reintroduce one casually.

## What is deliberately NOT implemented

* **A single choke-point guard in `path_lookupat()`.** This was designed and
  costed, then rejected. The tail of `path_lookupat()` — after `complete_walk()`
  (which guarantees ref-walk, so `d_path()` is safe) and before
  `*path = nd->path` — is one insertion point that would close `O_PATH`, all
  four `*xattr`, `link()`, and **every other path-resolving syscall at once**,
  in one hunk with two version variants (5.10 orders the `LOOKUP_MOUNTPOINT` and
  `LOOKUP_DIRECTORY` blocks differently from 6.12).

  It is more complete than four guards, and that is a real argument for it: the
  four measured oracles are members of a **class** — "a syscall that resolves a
  path and then does something no hijacked op sees" — and enumerating members
  one at a time cannot be proven exhaustive. `readlink(2)` (`EINVAL` for a
  non-symlink vs `ENOENT`), `inotify_add_watch(2)`, `name_to_handle_at(2)`,
  `truncate(2)`/`utimensat(2)`/`chmod(2)` (`EROFS` vs `ENOENT`) are all
  candidates that the four guards do not touch.

  It was rejected anyway, on the instruction that a bootloop is worse than an
  open oracle. `path_lookupat()` is on the path of `stat()`, `access()`,
  `chdir()`, `readlink()`, `statfs()` and more — every path-based syscall that
  is not an `open()`. That means (a) `ghost_hidden_path()` would run on a large
  fraction of all syscalls, gated only by the uid check; (b) a wrong table entry
  would break every syscall for that path at once rather than four cold ones;
  and (c) it creates a second source of truth for `stat()`, which the engine
  already answers correctly through its hijacked `->getattr`. If those trade-offs
  are ever acceptable, that is the site — and it should replace the four guards,
  not join them.

  I attempted to *measure* the wider class read-only on the OP15 and could not
  settle it: `toybox stat -f` returned `ENOENT` for a hidden path
  (`/product/etc/permissions/privapp-permissions-oplus-product.xml`, confirmed
  hidden from uid 10438 and visible to root), but toybox `lstat()`s the path
  first, so that result says nothing about `statfs(2)` itself, and `readlink -f`
  canonicalises without requiring existence. Settling it needs a compiled probe
  like `/data/local/tmp/leakprobe`, extended with the extra syscalls. **Treat
  the wider class as open and unquantified**, not as disproven.

* **`f*xattr(2)`** (the fd forms). They need a descriptor for the hidden path,
  and every route to one is closed: the engine's hijacked `->open` answers
  `-ENOENT`, and `ghost_o_path.patch` closes the `O_PATH` route. Guarding them
  would mean touching `file_getxattr()` paths that in-kernel callers share, for
  a case that cannot be reached.

* **6.13+ / torvalds/master for `xattr` and `linkat`.** Both sites were
  restructured: `path_getxattr()` became `path_getxattrat()` delegating to
  `filename_getxattr()` with a `kernel_xattr_ctx`, and `do_linkat()` no longer
  exists. The equivalent sites are `filename_{get,list,set,remove}xattr()` and
  whatever replaced `do_linkat()`. Not written, because the builder fleet pins
  nothing above 6.12 and an unverifiable hunk is worse than none. `o_path` and
  `notdir` **do** already cover master.

* **`ENOTDIR` on 4.9 / 4.14 / 4.19 / 5.4.** Three further shapes of the
  `unlazy_walk()` call (`unlazy_walk(nd, NULL, 0)` on 4.9). Nothing in the fleet
  is older than 5.10, there is no OEM tree to verify against, and an
  unverifiable hunk in `link_path_walk()` is the single worst place in this
  patch set to guess. `o_path`, `xattr` and `linkat` all cover 4.9+.

* **The accounting/consistency question `_pathhide` calls H8.** Not applicable
  here — these guards remove no entry from any listing, so nothing goes out of
  balance.

## Checking it on a device

The tables are empty until the engine's netlink forwarder exists, so on a
kernel built from `_ghost` alone every probe below must answer **exactly as an
unpatched kernel does**. That is the first thing to verify: this patch set must
be a no-op before it is configured.

Once configured, for a path `$H` that the engine hides from uid `$U`, and a
control path `$A` that genuinely does not exist in the same directory, every
probe must give the **same** answer for `$H` as for `$A`:

```sh
# run each as the blocked uid
su $U -c '...'
```

| probe | required answer for both `$H` and `$A` |
|---|---|
| `open(p, O_PATH)` | `ENOENT` |
| `getxattr(p, "security.selinux")` | `ENOENT` |
| `listxattr(p, ...)` | `ENOENT` |
| `setxattr(p, "user.x", ...)` | `ENOENT` |
| `stat(p "/zzz")` | `ENOENT` |
| `link(p, "/data/local/tmp/x")` | `ENOENT` |

Use the compiled `/data/local/tmp/leakprobe`, not shell tools: `toybox stat`
`lstat()`s before it does anything else and `toybox readlink -f` canonicalises
without touching the filesystem, so both report the wrong thing here. This is
the same trap `_hook`'s README documents for `echo` versus `dd`.

And verify from a **real app domain**, not `su <uid> -c`: that runs in the `ksu`
domain, which is not what a detector runs in. `_pathhide` recorded getting the
wrong answer exactly this way.

Finally, run the whole thing again for a uid that is **not** blocked, and for a
path that is injected but **not** hidden (`nm l` marks these `(public)`). Both
must be completely unaffected. A cloak that also hides from the wrong caller is
the failure mode this design is built to avoid.
