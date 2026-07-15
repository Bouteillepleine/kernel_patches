# NoMount — SUSFS-compatible variant

Same de-branded NoMount (ZeroMount) VFS driver as the parent directory, but
diffed against a **SUSFS-applied** GKI tree (like upstream ZeroMount) instead of
raw GKI. Use these when you want **NoMount *and* SUSFS in the same kernel**.

| You want | Use |
|----------|-----|
| NoMount only | `../nomount-android*.patch` (parent — raw GKI, standalone) |
| NoMount **+ SUSFS** | these (`susfs/nomount-android*.patch`) |

The two sets are **not interchangeable** — the parent (raw-GKI) patches conflict
if SUSFS is also applied, and these conflict on a tree without SUSFS.

## Apply order (SUSFS first)

```sh
# 1. apply your SUSFS patch to the kernel source first
patch -p1 < 50_add_susfs_in_gki-<ver>.patch      # (your susfs4ksu patch)
# 2. then apply the matching NoMount patch
patch -p1 < nomount-android16-6.12.patch          # pick your kernel version
```

Then enable both configs (neither is bundled):

```
CONFIG_NOMOUNT=y
CONFIG_KSU_SUSFS=y
```

## Runtime

NoMount cooperates with SUSFS by design — the driver's hooks are guarded by
`#ifdef CONFIG_KSU_SUSFS` and defer to `susfs_is_current_proc_umounted()`, so the
mountless VFS injection and SUSFS's hiding run together without fighting.

## Notes / caveats

- These are diffed against the same post-SUSFS base as upstream ZeroMount
  (Super-Builders' `50_add_susfs` layer). A substantially different SUSFS patch
  may shift context; reconcile any `.rej` by hand if so.
- De-brand only: `zeromount→nomount`, config/symbols/device (`/dev/nomount`),
  ioctl magic value (`0x5A`) and wire ABI **unchanged** — pairs with the same
  `Bouteillepleine/nomount` userspace module.
- **Apply-aligned to upstream, but not compile- or boot-tested here.** Build on
  a throwaway first.
