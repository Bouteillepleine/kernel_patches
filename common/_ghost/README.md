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
| `stat(p "/zzz")`, and every other way of asking for a directory — `stat(p "/")`, `chdir(p)`, `open(p, O_DIRECTORY)`, `open(p, O_PATH\|O_DIRECTORY)`, `inotify_add_watch(p, IN_ONLYDIR)` | `ENOTDIR` | `ENOENT` |
| `link(p, "/data/local/tmp/x")` | `EXDEV` | `ENOENT` |

A **second mechanism** was found later, by probing the wider class rather than
reasoning about it. `mnt_want_write()` answers before existence is re-validated,
so on a read-only ROM mount these three report `EROFS` — the same answer a stock
*visible* file gives — where an absent path gives `ENOENT`:

| probe | hidden | absent | stock visible |
|---|---|---|---|
| `truncate(p, 0)` | `EROFS` | `ENOENT` | `EROFS` |
| `utimensat(AT_FDCWD, p, …, 0)` | `EROFS` | `ENOENT` | `EROFS` |
| `chmod(p, 0644)` | `EROFS` | `ENOENT` | `EROFS` |

Measured the same way (OP15, blocked uid 10438, engine v25), with both an absent
and a stock-visible control.

A **third** was found by walking the create path rather than the read path:
`filename_create()` decides existence before `err2` is consulted, so
`mkdirat(AT_FDCWD, p, 0700)` and `mknodat()` answer `EEXIST` on a hidden name
where an absent one answers `EROFS` on a read-only ROM mount. Shared by
`mkdirat`, `mknodat`, `symlinkat` and `linkat`.

| probe | hidden | absent |
|---|---|---|
| `mkdirat(AT_FDCWD, p, 0700)` | `EEXIST` | `EROFS` |
| `mknodat(AT_FDCWD, p, …)` | `EEXIST` | `EROFS` |

A **fourth** was found by reading `inode_permission()` rather than by probing the
syscalls above it. `sb_permission()` runs **first** and short-circuits the whole
call on a read-only superblock, so every `MAY_WRITE` query on a ROM partition is
answered before `do_inode_permission()` ever dispatches to the engine's hijacked
`->permission`:

```c
int inode_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
{
        retval = sb_permission(inode->i_sb, inode, mask);
        if (retval)
                return retval;                      /* -EROFS */
        ...
        retval = do_inode_permission(idmap, inode, mask);   /* the engine */
```

| probe | hidden | absent | stock visible |
|---|---|---|---|
| `access(p, W_OK)` | `EROFS` | `ENOENT` | `EROFS` |
| `open(p, O_WRONLY)` / `O_RDWR` | `EROFS` | `ENOENT` | `EROFS` |
| `open(p, O_WRONLY\|O_TRUNC)` | `EROFS` | `ENOENT` | `EROFS` |
| `open(p, O_CREAT\|O_EXCL, 0600)` | `EEXIST` | `EROFS` | `EEXIST` |
| `open(p, O_CREAT\|O_RDONLY, 0600)` | `ENOENT` | `EROFS` | succeeds |
| `chown(p, -1, -1)` | `EROFS` | `ENOENT` | `EROFS` |

`access(p, W_OK)` is the cheapest probe this directory closes: one syscall, no
control path, no privilege, and it answers exactly as a stock *visible* file
does. The `O_CREAT|O_EXCL` form is the `filename_create()` signature reached by
the one create path that does **not** route through `filename_create()` —
`path_openat()` runs `link_path_walk()` and `open_last_lookups()` itself, and
`do_open()` returns `-EEXIST` ahead of `may_open()`.

These six were derived from `torvalds/linux` v6.12 `fs/namei.c` and `fs/open.c`
and are **not** device-measured, unlike the tables above. The mechanism is the
same one the `truncate`/`utimensat`/`chmod` row was measured for; those three
were simply the members that got probed first.

Cleared by the same measurement, and deliberately NOT patched: plain
`inotify_add_watch` (no `IN_ONLYDIR`) and `name_to_handle_at` answer identically
for hidden and absent (`n2h` is `ENOSYS` — the fs exports no `->fh_to_dentry`).
`IN_ONLYDIR` is a different question and *is* a leak — it sets
`LOOKUP_DIRECTORY`, so it lands on the `-ENOTDIR` oracle above and is closed
with it. `readlink` and `statfs` were leaks until engine v21/v25 added
`.readlink` to both iops and a `->statfs` on the hijacked `s_op`; they are closed
in the engine, not here.

⚠️ The class is **not proven exhaustive**. Anything that resolves a path and then
acts without consulting a hijacked op is a candidate. `classprobe.c` is the
harness — extend it rather than reasoning. Reading the source found family 4
after three rounds of probing had not, so do both.

This directory closes all of them — **eleven** families of guard. `ghost.c`
supplies one predicate, `ghost_hidden_path()`; the `ghost_*.patch` files place
the guards. Most answer `-ENOENT`; `ghost_create.patch` and `ghost_open.patch`
answer what an **absent** name would have got instead, which on a read-only
mount is `-EROFS` — see their headers for why a uniform `-ENOENT` would be a new
oracle rather than a closed one.

## Files

| file | what it is |
|---|---|
| `ghost.c` / `ghost.h` | the predicate and its control plane. Copy **both** into `fs/proc/`, next to `_pathhide`'s `pathhide.c`/`.h` |
| `ghost_build_integration.patch` | optional `obj-y += ghost.o` for the `fs/proc/` drop-in layout |
| `ghost_o_path*.patch` | guard in `do_o_path()`, `fs/namei.c` |
| `ghost_xattr*.patch` | guards in all four `path_*xattr()` wrappers, `fs/xattr.c` |
| `ghost_linkat*.patch` | guard in `do_linkat()`, `fs/namei.c` |
| `ghost_notdir.patch` | guards in `path_lookupat()` and `do_open()`, `fs/namei.c` |
| `ghost_truncate.patch` | guard in `do_sys_truncate()`, `fs/open.c` |
| `ghost_utimes.patch` | guard in `do_utimes_path()`, `fs/utimes.c` |
| `ghost_chmod*.patch` | guard in `do_fchmodat()`, `fs/open.c` |
| `ghost_chown.patch` | guard in `do_fchownat()`, `fs/open.c` — one file, 5.10→6.12 |
| `ghost_access.patch` | guard in `do_faccessat()`, `fs/open.c` — `access(W_OK)` only |
| `ghost_open.patch` | guard in `do_open()`, `fs/namei.c` — write-intent and `O_CREAT` opens |
| `ghost_create.patch` | guard in `filename_create()`, `fs/namei.c` — `mkdirat`/`mknodat`/`symlinkat`/`linkat` |

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
is nomount's private **CAP_SYS_ADMIN** raw-netlink channel (it was CAP_NET_ADMIN
until the engine tightened it — one `ADD_RULE` redirects any ROM path at any
file, which is root-equivalent, and CAP_NET_ADMIN is held on Android by domains
that are not), which must forward
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
| **4** | `ENOTDIR` — `stat(p "/zzz")`, `stat(p "/")`, `chdir(p)`, `open(O_DIRECTORY)`, `open(O_PATH\|O_DIRECTORY)`, `inotify IN_ONLYDIR` | low per probe — one bit — but there are six of them and any one is a complete substitute for the other three guards | **low** — both guards sit on error paths that are only reached by a lookup already failing, and neither is in `link_path_walk()` any more | `fs/namei.c` `path_lookupat()` + `do_open()` |

| **5** | `access(p, W_OK)` and `open(p, O_WRONLY\|O_RDWR\|O_TRUNC)` | **highest of the later families** — one syscall, no control path, and the answer is identical to a stock visible file | **low** for `access` (`do_faccessat()` is a cold wrapper and the guard is gated on `MAY_WRITE`); **moderate** for `open` — `do_open()` runs on every open(2), which is why that guard is gated on write intent and never evaluates the predicate for a plain read | `fs/open.c` `do_faccessat()`, `fs/namei.c` `do_open()` |
| **6** | `open(p, O_CREAT\|O_EXCL)` / `open(p, O_CREAT\|O_RDONLY)` | high — the `mkdirat` signature on the path `filename_create()` does not cover | low — same guard as #5, same gate | `fs/namei.c` `do_open()` |
| **7** | `truncate` / `utimensat` / `chmod` / `chown` | low per probe, four of them | **lowest** — four cold syscall wrappers, each guarded immediately after its own `user_path_at()` | `fs/open.c`, `fs/utimes.c` |
| **8** | `mkdirat` / `mknodat` / `symlinkat` / `linkat` target | high — one syscall, no control needed | low — the guard sits on an arm that already ends in `goto fail` | `fs/namei.c` `filename_create()` |

Two things about this ranking are worth spelling out, because both cut against
the obvious guess:

* **`ENOTDIR` is much cheaper than it looks, and it used to be much narrower
  than it looked.** Both guards test `err` on a path the lookup is already
  failing down, so the common case never evaluates the predicate. And the
  earlier form — one guard inside `link_path_walk()`'s non-final-component bail
  — closed `stat(p "/zzz")` and *nothing else*: `stat(p "/")`, `chdir(p)`,
  `open(O_DIRECTORY)`, `open(O_PATH|O_DIRECTORY)` and `inotify IN_ONLYDIR` all
  reach `-ENOTDIR` through the `LOOKUP_DIRECTORY` test that `link_path_walk()`
  never sees. Each of those is a one-syscall substitute for every oracle this
  directory closes, so the family ranked last was in fact the widest one open.
  It also no longer touches `link_path_walk()`, which removes the only
  documented bootloop-risk hunk in the set.
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

`aosp-N` below is AOSP common `android*-N` (5.10.264, 5.15.211, 6.1.176,
6.6.142, 6.12.90); `op-N` is the pinned OnePlus tree from the table above. Both
columns were re-measured at `-F0`.

| family | variant | applies to |
|---|---|---|
| **o_path** | `ghost_o_path.patch` | v4.19 v5.4 v5.10 v5.15 v6.1 v6.6 v6.12 **master**, aosp-5.10…6.12, op-5.10…op-6.12 |
| **xattr** | `ghost_xattr_6_12.patch` | v6.12, **aosp-6.6**, **op-6.6**, aosp-6.12 op-6.12 |
| | `ghost_xattr_5_15.patch` | v5.15 v6.1, aosp-5.15 aosp-6.1, op-5.15 op-6.1 |
| | `ghost_xattr.patch` | v4.9 v4.14 v4.19 v5.4 v5.10, aosp-5.10, op-5.10 |
| **linkat** | `ghost_linkat_5_15.patch` | v5.15 v6.1 v6.6 v6.12, aosp-5.15…6.12, op-5.15…op-6.12 |
| | `ghost_linkat.patch` | v4.9 v4.14 v4.19 v5.4 v5.10, aosp-5.10, op-5.10 |
| **notdir** | `ghost_notdir.patch` | **one file**: aosp-5.10…6.12 and op-5.10…op-6.12 |
| **truncate** | `ghost_truncate.patch` | one file: 5.10…6.12 (`do_sys_truncate()` is byte-identical across them), aosp and op |
| **utimes** | `ghost_utimes.patch` | one file: 5.10…6.12 (`do_utimes_path()` is byte-identical across them), aosp and op |
| **chmod** | `ghost_chmod.patch` | 6.6 6.12, aosp and op |
| | `ghost_chmod_5_10.patch` | 5.10 5.15 6.1, aosp and op |
| **create** | `ghost_create.patch` | one file: 5.10…6.12 (`filename_create()`'s `-EEXIST` block is byte-identical), aosp and op |
| **chown** | `ghost_chown.patch` | one file: 5.10…6.12 (`do_fchownat()` is byte-identical across all five), op |
| **access** | `ghost_access.patch` | one file: 5.10…6.12 (the `retry:` → `d_backing_inode()` region is byte-identical even though `inode_permission()`'s signature is not), op |
| **open** | `ghost_open.patch` | one file: 5.10…6.12, generated at `-U2` because the line below `audit_inode()` differs per version, op |
| **build** | `ghost_build_integration.patch` | every tree above, v4.9 → master |

### Three variants were deleted

* `ghost_o_path_legacy.patch` (v4.9/v4.14 `vfs_open()` signature),
  `ghost_xattr_6_6.patch` (the vanilla-v6.6 `fs/xattr.c` shape) and
  `ghost_notdir_5_10.patch` (vanilla v5.10's `unlazy_walk()`).
* None of the three was reachable. `scripts/apply_nomount_stack.sh` does not
  merely never select them: its `apply_first_of` pins the required variant per
  kernel version, and on every version those three files could have won, the pin
  names a different file — so the build **aborts** rather than falling back.
  Confirmed in the script before deleting.
* Two of them were also empty sets. AOSP common android15-6.6 carries the same
  6.12-era `fs/xattr.c` restructure the OnePlus 6.6 tree does, so
  `ghost_xattr_6_6.patch` matched no tree in either fleet; and the new
  `ghost_notdir.patch` covers vanilla-shaped 5.10 as well, because its guards do
  not sit next to the `unlazy_walk()`/`try_to_unlazy()` split that forced the
  variant in the first place.

Variant selection is by **pinned name per kernel version**, not by "first that
dry-runs clean" — `scripts/apply_nomount_stack.sh` names the required variant for
each of 5.10/5.15/6.1/6.6/6.12 and fails loudly if that one does not apply. Same
arrangement as `_hook`'s builder, and for the same reason: three of the four
`path_*xattr()` bodies are character-identical below `retry:`, so "first that
applies" is how a `-ENOENT` guard lands in the wrong wrapper.

### Version-specific shapes worth knowing before editing these

* **`do_o_path()` is byte-identical v4.19 → torvalds/master**, and on all five
  pinned OnePlus trees (verified by md5 of the extracted function body). One
  hunk covers 13 of the 15 trees tested. Only v4.9/v4.14 differ, and only in the
  `vfs_open()` argument list.
* **Every android15-6.6 tree measured carries the 6.12-era `fs/xattr.c`
  restructure** (`setxattr_copy()`/`xattr_ctx`, `do_setxattr()`, the `kname`
  buffer in `path_removexattr()`) — OnePlus's and AOSP common's alike — so 6.6
  groups with 6.12, **not** with vanilla v6.6. `ghost_xattr_6_6.patch` covered
  the vanilla shape and matched nothing either fleet resolves to; it is gone.
* **The `unlazy_walk()` / `try_to_unlazy()` split no longer matters here.**
  OnePlus's android12-5.10 carries `try_to_unlazy()` where vanilla v5.10 has
  `unlazy_walk()`, and that split is why `notdir` needed two variants while its
  guard lived in `link_path_walk()`. The guard now sits in `path_lookupat()` and
  `do_open()`, neither of which mentions either helper, so one file covers 5.10
  through 6.12 with hunks that are byte-identical when generated independently
  against each of the ten trees.
* **`path_listxattr()` is byte-identical on all 14 trees** that have it — the
  only one of the four xattr wrappers that never changed shape.
* **FUZZ 0 IS NECESSARY AND NOT SUFFICIENT. Count your pre-image.** `patch -F0`
  proves a hunk matches *somewhere*; it says nothing about whether it matches in
  **one** place. When a pre-image occurs twice, `patch` resolves it by proximity
  to the `@@` line number — which is pinned to whichever tree the patch was cut
  against — so the same file lands the guard in a different function on every
  other tree, at fuzz 0, silently.

  That is not hypothetical. `ghost_notdir.patch` used three lines of leading
  context starting at `nd->path.mnt = NULL;`. `path_lookupat()` and
  `path_parentat()` end with the **same five lines**, so that pre-image occurs
  **twice** in `fs/namei.c` on every one of the five trees, and the guard landed
  in `path_parentat()` on 5.10, 5.15, 6.1 and 6.6 — four of the five kernels the
  fleet builds — leaving the whole `ENOTDIR` family open there while every
  assertion in the repo stayed green. Only 6.12, the tree the hunk was generated
  against, was correct.

  The fix was one extra line of context: `*path = nd->path;`, which is what
  `path_lookupat()` writes where `path_parentat()` writes `*parent = nd->path;`.
  Pre-image occurrences went from 2 to 1 on all five. `apply_nomount_stack.sh`
  and both workflows now assert the containing FUNCTION by name, so this cannot
  recur silently.

  Before you trust a dry-run: `grep -c` your hunk's pre-image in the target file,
  on every tree. `scripts/` has no helper for this yet; the audit used a
  throwaway that walks each `@@` block, reassembles the context and `-` lines,
  and counts occurrences.
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

Repeated for the whole set on **AOSP common** android12-5.10 (5.10.264),
android13-5.15 (5.15.211), android14-6.1 (6.1.176), android15-6.6 (6.6.142) and
android16-6.12 (6.12.90): all nine files apply at `-F0`, `fs/namei.o`,
`fs/xattr.o`, `fs/open.o`, `fs/utimes.o` and the whole `fs/proc/` directory
compile clean, and `nm fs/proc/built-in.a` shows `T ghost_hidden_path` on every
one of the five. `scripts/apply_nomount_stack.sh verify ghost` asserts the same
facts at build time.

The trees were restored to their prior state afterwards.

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

## CI wiring — done

This section used to read *"CI wiring this would need (not done here — do not
wire it yourself)"*. It is wired. Both workflows carry `common/_ghost/**` in
their `paths:` filters, `verify-hook-pathhide.yml` compiles `fs/proc/ghost.o`,
`fs/namei.o`, `fs/xattr.o`, `fs/open.o` and `fs/utimes.o`, asserts
`ghost_hidden_path` is exported from `fs/proc/built-in.a`, and asserts the
`proc_create` absence this section asked for by name.

Two things were added on top of what it asked for, and both exist because of a
bug this directory shipped for four kernel versions:

* **Every guard is asserted by FUNCTION NAME**, not by "the file mentions
  `ghost_hidden_path`". `fs/namei.c` is touched by five families, so one
  occurrence satisfied the old assertion even when four guards were missing.
* **`verify-patches-oneplus.yml` now checks all eleven families.** It checked
  five — `o_path`, `xattr`, `linkat`, `notdir`, `build` — and skipped
  `truncate`, `utimes`, `chmod` and `create`, which is the *same four* whose
  absence `scripts/apply_nomount_stack.sh`'s header cites as the reason that
  script exists. It had drifted straight back.

For the record, the original text, which is still accurate about the trap:

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

* **A single choke-point guard on `path_lookupat()`'s SUCCESS path.** Still
  rejected, and the distinction between that and what `ghost_notdir.patch` now
  does is the whole of this entry — do not read one as having become the other.

  The rejected design puts the guard after `complete_walk()` and before
  `*path = nd->path`, i.e. on **every successful lookup**. It would close
  `O_PATH`, all four `*xattr`, `link()` and every other path-resolving syscall in
  one hunk. It is more complete, and that is a real argument for it: the measured
  oracles are members of a **class** — "a syscall that resolves a path and then
  does something no hijacked op sees" — and enumerating members one at a time
  cannot be proven exhaustive.

  It stays rejected, on the instruction that a bootloop is worse than an open
  oracle. `path_lookupat()` is on the path of `stat()`, `access()`, `chdir()`,
  `readlink()`, `statfs()` and more, so (a) `ghost_hidden_path()` would run on a
  large fraction of all syscalls, gated only by the uid check; (b) a wrong table
  entry would break every syscall for that path at once rather than a few cold
  ones; and (c) it creates a second source of truth for `stat()`, which the
  engine already answers correctly through its hijacked `->getattr`.

  **What `ghost_notdir.patch` does instead** is the same function and none of
  that cost: it tests `err == -ENOTDIR` on the **error** path, so the predicate
  is evaluated only on a lookup that is already failing, and it can only ever
  rewrite one errno into another. Nothing on the success path changes, so a wrong
  table entry cannot make a working `stat()` fail. That is why it is in and the
  success-path guard is out, and why the two must not be conflated when someone
  next reads this file.

  One piece of design work it does need: `-ENOTDIR` can reach the end of
  `path_lookupat()` from `path_init()`, which rejects a non-directory dfd or
  preset root with `nd->flags` already carrying `LOOKUP_RCU`, before
  `rcu_read_lock()` and before `nd->path` is assigned. `ghost_hidden_path()`
  renders `d_path()` and needs a reference-counted path, so the guard tests
  `!(nd->flags & LOOKUP_RCU)` **and** `nd->path.dentry` before touching the
  predicate. Nothing is lost by that: `link_path_walk()`'s site unlazies (or
  returns `-ECHILD`), and `complete_walk()` runs ahead of the `LOOKUP_DIRECTORY`
  test, so every probe listed in the ranking table arrives in ref-walk mode.

  The class stays open in the direction the guard does not cover. I attempted to
  *measure* it read-only on the OP15 and could not
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

* **`ENOTDIR` on 4.9 / 4.14 / 4.19 / 5.4.** Not covered, and no longer for the
  old reason: the guards left `link_path_walk()` and the `unlazy_walk()` shapes
  stopped mattering. They are simply unverified — nothing in the fleet is older
  than 5.10 and there is no tree here to test against. `o_path`, `xattr` and
  `linkat` all cover 4.9+.

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
| `stat(p "/")` | `ENOENT` |
| `chdir(p)` | `ENOENT` |
| `open(p, O_DIRECTORY)` | `ENOENT` |
| `open(p, O_PATH\|O_DIRECTORY)` | `ENOENT` |
| `inotify_add_watch(p, IN_ONLYDIR)` | `ENOENT` |
| `link(p, "/data/local/tmp/x")` | `ENOENT` |
| `access(p, W_OK)` | `ENOENT` |
| `open(p, O_WRONLY)` | `ENOENT` |
| `open(p, O_WRONLY\|O_TRUNC)` | `ENOENT` |
| `chown(p, -1, -1)` | `ENOENT` |

Two probes are the exception and must **not** answer `ENOENT` — they answer what
an absent name answers on a read-only mount, which is `EROFS`:

| probe | required answer for both `$H` and `$A` |
|---|---|
| `mkdirat(AT_FDCWD, p, 0700)` | `EROFS` |
| `open(p, O_CREAT\|O_EXCL, 0600)` | `EROFS` |

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
