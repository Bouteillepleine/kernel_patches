# `_pathhide` — hide selected file-backed entries from `/proc/<pid>/*`

`pathhide.c` / `pathhide.h` provide `pathhide_match_file()`, a substring match
against the *displayed* path of a VMA's or fd's backing file. The per-kernel
`*_integration.patch` files call it from the `/proc` readers so matched entries
(injected hook-framework module APKs, `/data/adb/lspd`, …) disappear. Inert until
the first rule is written, so a no-op on stock configurations.

## What each patch covers

| patch | sites |
|---|---|
| `pathhide_<ver>_integration.patch` | `maps`, `smaps`, `smaps_rollup`, the `fd` readdir, and (6.12) `numa_maps` + the `PROCMAP_QUERY` ioctl + `fd` lookup/readlink/count |
| `pathhide_mapfiles_<ver>_integration.patch` | `/proc/<pid>/map_files/` readdir, name lookup, symlink resolve — **mandatory**, see that file's header |
| `pathhide_build_integration.patch` | optional `obj-y += pathhide.o` for the `fs/proc/` drop-in layout |

## Coverage is complete only on 6.12 right now

The audit fixes (fd readlink/lookup/count via `tid_fd_mode`, the `PROCMAP_QUERY`
ioctl, `smaps_rollup`, and the maps-vs-pad decision point) were implemented and
**compile-verified against 6.12.23** (`fs/proc/fd.o` and `fs/proc/task_mmu.o`
build clean with the patch applied).

**The 5.10 / 5.15 / 6.1 / 6.6 integration patches still carry only the original
`maps` + `smaps` + `fd`-readdir filters.** They were NOT extended, because their
`fs/proc/fd.c` and `fs/proc/task_mmu.c` differ from 6.12 (e.g. 5.10 has no
`tid_fd_mode()`; `fd` lookup runs through `fcheck_files`/`tid_fd_revalidate`
instead) and no source for those versions was available here to verify the hunks
apply. The builders are fail-closed (`apply_or_die`), so shipping unverified
context would break those builds rather than silently under-cover.

To close the same gap on an older kernel, regenerate against *that* version's
source, mirroring the 6.12 changes:

* **`fs/proc/fd.c`**
  * make the fd lookup helper (`tid_fd_mode()` on 6.x, else the body of
    `proc_lookupfd_common()` / `tid_fd_revalidate()`) report "not present" when
    `pathhide_match_file()` matches — this covers `readlink`, `fdinfo`, and
    dentry revalidation in one place;
  * guard `proc_fd_link()` for a cached dentry read through `proc_get_link`;
  * rewrite `proc_readfd_count()` to iterate fds and *deduct* matched ones
    instead of `bitmap_weight(open_fds)`, so `stat(/proc/<pid>/fd).st_size`
    equals what readdir emits (**H6 / M-C7**).
* **`fs/proc/task_mmu.c`**
  * move the `maps` guard out of `show_map_vma()` into `show_map()`, before both
    the `show_map_vma()` and `show_map_pad_vma()` calls, so a hidden padded `.so`
    does not leave an orphan `[page size compat]` line that `smaps` drops
    (**M-C5**, only where `show_map_pad_vma`/`pgsize_migration` exists — 6.1/6.6);
  * add `if (vma->vm_file && pathhide_match_file(vma->vm_file)) continue;` to the
    `show_smaps_rollup()` accumulation loop (**H8 contained part**).

## H8 — the accounting leak is only partly closed (STAGED, needs a decision)

Deleting a VMA's `maps` line hides the name but leaves the *accounting*
inconsistent, and each inconsistency is a zero-privilege existence tell:

* `sum(maps ranges) < VmSize` (from `/proc/<pid>/status` / `statm`);
* `smaps_rollup` totals diverge from `VmRSS` — the contained fix above makes
  rollup skip matched VMAs, which removes the smaps-vs-rollup mismatch but
  *deepens* the rollup-vs-`VmRSS` one;
* an address hole where the VMA used to be.

`smaps_rollup`'s contended-lock slow path (`mmap_lock_is_contended`) re-gathers a
re-fetched VMA without re-checking `pathhide_match_file()`; the contained fix only
covers the common path. Left as-is deliberately.

Closing this properly is a design change, not a patch tweak, and must not ship
half-done (a half version makes the tells *worse*). Two candidate approaches:

1. **Substitute, don't delete** — emit a benign anonymous line with the same
   address range in `maps`/`smaps` instead of dropping it, so ranges still sum to
   `VmSize` and there is no hole. More faithful, more code, per-reader.
2. **Deduct at the source** — patch `task_mem()` / `proc_pid_statm()` to subtract
   matched VMAs from `total_vm` / `RssFile` etc., so the totals agree with the
   thinned `maps`. Fewer sites, but changes reported process memory.

Pick one before extending H8; do not mix.

## M-C8 — the control-plane forwarder lives in the nomount engine, not here

`pathhide.c` exposes `pathhide_ctl()` (apply one `+needle` / `~needle` / `-`
command) and `pathhide_get_rule()` (dump), but **nothing in *this* patch set
wires them to a control channel.** Applying `_pathhide` alone yields an
`pathhide.o` that matches correctly but can never be configured (its rule set
stays empty, so `pathhide_match_file()` short-circuits to `false` forever) unless
you compile the opt-in `PH_ENABLE_PROC` fallback node.

The real control plane is nomount's private raw-netlink channel: `nomount.c`
forwards `NM_KNOB_PATHHIDE → pathhide_ctl()` and `NM_CMD_GET_PATHHIDE →
pathhide_get_rule()` through **weak** externs (so the two patch sets stay
independently applicable), behind nomount's existing **CAP_NET_ADMIN** check.
That forwarder is supplied by the nomount engine repo, not by kernel_patches — a
kernel built from `_pathhide` **without** that nomount commit has a dead feature.
Ship both together, or enable `PH_ENABLE_PROC` for a standalone build.

## Leak paths — one closed, one out of reach

* **`/proc/<pid>/numa_maps`** — `show_numa_map()` prints the backing file path
  (`file_user_path`), unfiltered. This was assumed inert (`CONFIG_NUMA=n`) but the
  6.12 tree config actually has **`CONFIG_NUMA=y`**, so the node is live and was a
  real open oracle. The 6.12 integration patch now guards `show_numa_map()` the
  same way as `show_map()`; the guard is compiled only under `CONFIG_NUMA`, so it
  is a strict no-op where NUMA is off. The older-kernel patches still need the
  same guard added (see the coverage-gap section).
* **`dl_iterate_phdr()` / the dynamic linker's `link_map`** — userspace bookkeeping
  in the process's own address space, populated by the loader, not by the kernel.
  The kernel cannot filter it; a file-backed mapping hidden from `maps` is still
  listed by the app's own linker. Out of scope for a `/proc` cloak.
