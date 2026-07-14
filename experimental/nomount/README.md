# NoMount — kernel VFS path-redirection patches (de-branded ZeroMount)

Mountless, systemless module loading via VFS-layer path redirection and virtual
dirent injection — no entries in `/proc/mounts`. This is a **de-branded** build of
Enginex0's **ZeroMount** driver (`Super-Builders`), **rebased onto pristine GKI**
so each patch applies to a clean kernel tree with **no SUSFS prerequisite**.

## Files

| Patch | Android | Kernel | GKI base branch |
|-------|---------|--------|-----------------|
| `nomount-android12-5.10.patch` | 12 | 5.10 | `common/android12-5.10` |
| `nomount-android13-5.15.patch` | 13 | 5.15 | `common/android13-5.15` |
| `nomount-android14-6.1.patch`  | 14 | 6.1  | `common/android14-6.1`  |
| `nomount-android15-6.6.patch`  | 15 | 6.6  | `common/android15-6.6`  |
| `nomount-android16-6.12.patch` | 16 | 6.12 | `common/android16-6.12` |

Each patch touches 10 core VFS files (`fs/Kconfig`, `fs/Makefile`, `fs/d_path.c`,
`fs/namei.c`, `fs/readdir.c`, `fs/stat.c`, `fs/statfs.c`, `fs/xattr.c`,
`fs/proc/base.c`, `fs/proc/task_mmu.c`) and adds two new files
(`fs/nomount.c`, `include/linux/nomount.h`).

## Apply

From the kernel source root:

```sh
patch -p1 < nomount-android16-6.12.patch      # pick the matching kernel version
```

Then enable the config (NOT bundled in the patch — see below):

```sh
echo 'CONFIG_NOMOUNT=y' >> arch/arm64/configs/gki_defconfig
# or add it to your build's defconfig.fragment
```

The driver registers `/dev/nomount` (root-only, 0600) and `/sys/kernel/nomount/`,
and defaults **disabled** until userspace enables it via ioctl.

## What "de-branded" changed

Pure identifier/string rename vs. upstream ZeroMount — the **code is byte-identical**:

| ZeroMount | NoMount |
|-----------|---------|
| `CONFIG_ZEROMOUNT` | `CONFIG_NOMOUNT` |
| `zeromount_*` / `ZEROMOUNT_*` / `ZM_*` / `zm_*` | `nomount_*` / `NOMOUNT_*` / `NM_*` / `nm_*` |
| `/dev/zeromount`, `/sys/kernel/zeromount` | `/dev/nomount`, `/sys/kernel/nomount` |
| `fs/zeromount.c`, `linux/zeromount.h` | `fs/nomount.c`, `linux/nomount.h` |
| `"ZeroMount:"` log prefix | `"NoMount:"` |

**Wire ABI is unchanged on purpose**: the ioctl magic value (`0x5A`), ioctl numbers,
and `struct` layouts are identical to ZeroMount. Only the *names* differ. Because
the device node moved to `/dev/nomount`, you need a **matching de-branded userspace
manager** (a stock ZeroMount manager looks for `/dev/zeromount`). If you want to also
change the magic value (`0x5A` = `'Z'`), do it in both the kernel header and userspace.

## Relationship to SUSFS

Upstream, ZeroMount is diffed against a tree that **already has SUSFS applied**
(`50_add_susfs` → `60_zeromount`). These patches were rebased off that dependency
so they stand alone on clean GKI. The driver still *cooperates* with SUSFS when
present (calls under `#ifdef CONFIG_KSU_SUSFS` compile out cleanly without it).

If you apply **both** SUSFS and NoMount to one tree: apply **NoMount first**, then
SUSFS. Both insert into overlapping functions (`getdents*`, `generic_permission`,
`inode_permission`, `d_path`, …), so expect to reconcile a hunk or two — this
combination is untested here.

## Verification status — read before flashing

Verified:
- ✅ Each patch applies to a fresh GKI tree with **zero fuzz / zero offset**.
- ✅ Added code is **byte-identical** to the corresponding upstream ZeroMount patch
  (added-line parity checked; the only intentional difference is the omitted
  `CONFIG_ZEROMOUNT=y` defconfig line — enable `CONFIG_NOMOUNT` yourself).
- ✅ `#ifdef/#endif` balanced; no residual `zeromount`/`ZM_` tokens.

NOT done:
- ❌ **Not compile-tested.** No GKI toolchain was run.
- ❌ **Not boot-tested.** This is heavy VFS surgery on hot paths.

Given the OnePlus 15 recovery-bootloop history, treat the 6.12 patch as unproven
until you build it and test on a throwaway boot. `CONFIG_NOMOUNT` is off at boot by
default, and the driver self-disables on the reboot notifier, which reduces (not
eliminates) brick risk.

## Provenance
- Upstream driver: `github.com/Enginex0/zeromount`
- Upstream builder / per-version patches: `github.com/Enginex0/Super-Builders`
  (`android*/*/patches/60_zeromount-*.patch`, variant-invariant)
- Raw GKI sources: `android.googlesource.com/kernel/common`
