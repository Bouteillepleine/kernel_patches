# `_pathhide` — hide selected file-backed entries from `/proc/<pid>/*`

`pathhide.c` / `pathhide.h` provide `pathhide_match_file()`, a substring match
against the *displayed* path of a VMA's or fd's backing file. The per-kernel
`*_integration.patch` files call it from the `/proc` readers so matched entries
(injected hook-framework module APKs, `/data/adb/lspd`, …) disappear. Inert until
the first rule is written, so a no-op on stock configurations.

## What each patch covers

| patch | sites |
|---|---|
| `pathhide_<ver>_integration.patch` | `maps`, `smaps`, `smaps_rollup`, `numa_maps`, the `fd` readdir *and* `fd` lookup/readlink/fdinfo — plus `stat(fd).st_size` on 6.6/6.12 and the `PROCMAP_QUERY` ioctl on 6.12 |
| `pathhide_mapfiles_<ver>_integration.patch` | `/proc/<pid>/map_files/` readdir, name lookup, symlink resolve — **mandatory**, see that file's header |
| `pathhide_build_integration.patch` | optional `obj-y += pathhide.o` for the `fs/proc/` drop-in layout |

## Coverage per kernel version

The audit fixes now exist on every version the fleet builds. Each older-kernel
patch was regenerated hunk by hunk against the real OnePlus tree its manifests
pin, then dry-run at **fuzz 0** against every distinct `fs/proc` variant those
manifests resolve to (13 distinct `fd.c`/`task_mmu.c`/`base.c` combinations
across 69 `(tree, revision)` pairs).

| fix | 5.10 | 5.15 | 6.1 | 6.6 | 6.12 |
|---|---|---|---|---|---|
| `maps` / `smaps` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `fd` readdir | ✓ | ✓ | ✓ | ✓ | ✓ |
| **H6** `fd` lookup / readlink / fdinfo (`tid_fd_mode` + `proc_fd_link`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| **M-C7** `stat(/proc/<pid>/fd).st_size` | n/a | n/a | n/a | ✓ | ✓ |
| **M-C5** orphan `[page size compat]` pad VMA | ✓ | ✓ | ✓ | ✓ | ✓ |
| `numa_maps` (under `CONFIG_NUMA`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `smaps_rollup` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `PROCMAP_QUERY` ioctl | n/a | n/a | n/a | n/a | ✓ |

`n/a` means the kernel has no such code, not that the fix was skipped:
`proc_readfd_count()`/`proc_fd_getattr()` first appear in 6.6, and the
`PROCMAP_QUERY` ioctl (`query_matching_vma()`) first appears in 6.12 — neither
exists in the older trees, so there is nothing to leak through.

### Version-specific shapes worth knowing before editing these

* `tid_fd_mode()` **does** exist on 5.10 (it takes a `files_struct` reference and
  uses `fcheck_files()`), so H6 has one decision point on every version. An
  earlier note here claiming otherwise was wrong.
* On 5.10, 5.15 and *some* 6.1 trees, `show_map()`/`show_smap()` open with
  `get_pad_vma()` / `get_data_vma()`, which return **kzalloc'd copies that only
  `show_map_pad_vma()` frees**. A guard placed after those declarations would
  leak two `struct vm_area_struct` per hidden padded mapping on every read of
  `maps`. Those versions therefore wrap the function — `show_map()` becomes a
  thin guard that tail-calls `ph_show_map()` — so the decision happens before
  anything is allocated. 6.1 needs the wrapper for a second reason: its trees
  carry **both** shapes (`vma = v` and the pad-copy form), and the wrapper is the
  only form that compiles against both.
* 6.6 and 6.12 take `@v` as the VMA directly, so their guard sits inline.
* `smaps_rollup` is a `for (vma = priv->mm->mmap; vma;)` loop on 5.10/5.15 with
  the advance at the *bottom* of the body — `continue` there would hang. Those
  versions suppress the accumulation instead; 6.1/6.6/6.12 are `do`/`while` and
  use `continue`.
* GNU `patch` reports fuzz when a hunk's trailing context is shorter than its
  leading context, even when every line matches. The wrapper hunks therefore
  carry 1 line of context on each side (the declarations below the opening brace
  are the part that differs between trees). If you regenerate, re-check at
  `-F0`: a hunk that only applies "with fuzz" can land a guard in the wrong
  function silently.

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
covers the common path. Left as-is deliberately, and identically on every version
so the five patches stay comparable.

One further per-version nuance: on 6.1/6.6/6.12 the `continue` also skips
`last_vma_end = vma->vm_end`, so a hidden *trailing* VMA shortens the `[rollup]`
header range; on 5.10/5.15 the range is left intact and only the accounting is
suppressed. Both close the smaps-vs-rollup mismatch, which is the oracle that
mattered.

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
  real open oracle. **Every** integration patch now guards `show_numa_map()` the
  same way as `show_map()`; `show_numa_map()` lives inside `#ifdef CONFIG_NUMA`
  on all five versions, so the guard is a strict no-op where NUMA is off.
* **`dl_iterate_phdr()` / the dynamic linker's `link_map`** — userspace bookkeeping
  in the process's own address space, populated by the loader, not by the kernel.
  The kernel cannot filter it; a file-backed mapping hidden from `maps` is still
  listed by the app's own linker. Out of scope for a `/proc` cloak.
