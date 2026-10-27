#!/usr/bin/env bash
#
# Patch susfs4ksu's kernel side into a tree that may already carry NoMount.
# ONE copy, called by every builder -- same reasoning as apply_nomount_stack.sh.
#
# WHY THIS EXISTS. susfs4ksu rebases 50_add_susfs_in_gki-*.patch onto one GKI
# sublevel at a time, and OnePlus trees are not that sublevel. On top of that,
# NoMount has already inserted lines inside the very functions susfs patches --
# fs/namei.c, fs/open.c, fs/stat.c, fs/proc/base.c, fs/proc/task_mmu.c -- so a
# hunk's context no longer matches even though no line susfs anchors on has
# changed. Both are absorbed by susfs_patch_surgery.py, which re-anchors a
# rejected hunk by the content it ADDS rather than by its @@ line numbers.
#
# The alternative -- a hand-written kernel_fix variant per tree shape -- works
# but needs a new file for every sublevel and every manifest family. The
# variants still in next/susfs_fix_patches/*/kernel_fix_* predate this and are
# superseded by it.
#
# security/selinux/selinuxfs.c is dropped outright: the KSU side and NoMount's
# _hook family already own the hiding there, and letting susfs in as well means
# two implementations fighting over fake_status. That is asserted below, not
# assumed.
#
# A reject the surgery cannot resolve is a HARD FAILURE. Half-applied hiding
# compiles, boots, and lies about what it hides.
#
# ENV CONTRACT:
#   COMMON_KERNEL_FOLDER   kernel source root (fs/, security/, ...)   [required]
#   SUSFS_FOLDER           susfs4ksu checkout                        [required]
#   KSU_FOLDER             KernelSU tree (for the wiring assertions)  [required]
#   ANDROID_VER KERNEL_VER used to pick the patch when SUSFS_KERNEL_BRANCH is unset
#   SUSFS_KERNEL_BRANCH    overrides that, e.g. gki-android16-6.12
#   GITHUB_ENV             optional; SUSVER is exported there when set
set -euo pipefail

die() { echo "::error::apply_susfs_kernel: $*" >&2; exit 1; }
note() { echo "   $*"; }

for v in COMMON_KERNEL_FOLDER SUSFS_FOLDER KSU_FOLDER; do
    [ -n "${!v:-}" ] || die "$v is not set"
done
[ -d "$COMMON_KERNEL_FOLDER/fs" ] || die "COMMON_KERNEL_FOLDER=$COMMON_KERNEL_FOLDER has no fs/"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SURGERY="$HERE/susfs_patch_surgery.py"
[ -f "$SURGERY" ] || die "$SURGERY is missing"

BRANCH="${SUSFS_KERNEL_BRANCH:-gki-${ANDROID_VER:?}-${KERNEL_VER:?}}"
PATCH="$SUSFS_FOLDER/kernel_patches/50_add_susfs_in_${BRANCH}.patch"
[ -f "$PATCH" ] || {
    echo "::error::apply_susfs_kernel: no kernel patch for $BRANCH"
    find "$SUSFS_FOLDER/kernel_patches" -maxdepth 1 -name '50_add_susfs_in_*.patch' | sort
    exit 1
}

# Work on a copy: the surgery rewrites the patch, and the checkout is shared.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$PATCH" "$WORK/50_add.patch"
PATCH="$WORK/50_add.patch"

cd "$COMMON_KERNEL_FOLDER"

cp "$SUSFS_FOLDER/kernel_patches/fs/"*.c fs/
cp "$SUSFS_FOLDER/kernel_patches/include/linux/"*.h include/linux/

SUBLEVEL="$(grep -m1 '^SUBLEVEL' Makefile | tr -d ' ' || true)"
note "tree: ${ANDROID_VER:-?}-${KERNEL_VER:-?} ${SUBLEVEL:-SUBLEVEL=?}  patch: $(basename "$PATCH") ($BRANCH)"

rejects="$(patch -p1 -F0 --forward --dry-run < "$PATCH" 2>&1 |
    awk '/^checking file/{f=$3} /Hunk #[0-9]+ FAILED/{n=$2; gsub("#","",n); print f":"n}')" || true
if [ -n "$rejects" ]; then
    note "hunks that do not fit this tree:"
    printf '%s\n' "$rejects" | sed 's/^/     /'
else
    note "the patch fits as-is; nothing to reconcile"
fi

python3 -I "$SURGERY" --drop security/selinux/selinuxfs.c "$PATCH" . $rejects

if ! patch -p1 -F0 --forward --dry-run < "$PATCH" >/dev/null 2>&1; then
    echo "::error::apply_susfs_kernel: the patch still rejects after reconciliation"
    patch -p1 -F0 --forward --dry-run < "$PATCH" 2>&1 | grep -E '^(checking file|Hunk .*FAILED)' || true
    exit 1
fi
patch -p1 -F0 --forward < "$PATCH" >/dev/null
find . -name '*.orig' -delete
left="$(find . -name '*.rej' | sort)"
[ -z "$left" ] || { echo "::error::apply_susfs_kernel: rejects left: $(echo "$left" | tr '\n' ' ')"; exit 1; }

# OPEN_REDIRECT calls VMA_PAD_START() and __fold_filemap_fixup_entry(), which
# only exist on GKI branches carrying Google's page-size-migration work.
tm=fs/proc/task_mmu.c
before="$(md5sum "$tm" | cut -d' ' -f1)"
sed -i -E 's@^([[:blank:]]{3,})end = VMA_PAD_START\(vma\);[[:blank:]]*$@\1end = vma->vm_end;@' "$tm"
sed -i -E '/^[[:blank:]]{3,}__fold_filemap_fixup_entry\(/d' "$tm"
[ "$before" = "$(md5sum "$tm" | cut -d' ' -f1)" ] ||
    note "neutralised OPEN_REDIRECT VMA_PAD_START/__fold references in $tm"

# The susfs preinit hooks in fs/exec.c are for KSU trees without their own.
if grep -q '#ifndef KSU_NO_PREINIT' fs/exec.c && ! grep -q '^#define KSU_NO_PREINIT' fs/exec.c; then
    if grep -rqs 'ksu_setup_preinit_file' "$KSU_FOLDER/kernel"; then
        note "the KSU tree provides preinit; leaving the susfs preinit hooks enabled"
    else
        sed -i '0,/^#ifdef CONFIG_KSU_SUSFS$/s//#ifndef KSU_NO_PREINIT\n#define KSU_NO_PREINIT\n#endif\n&/' fs/exec.c
        grep -q '^#define KSU_NO_PREINIT$' fs/exec.c || die "could not define KSU_NO_PREINIT in fs/exec.c"
        note "defined KSU_NO_PREINIT; this KSU tree has no preinit"
    fi
fi

# ---- assertions ---------------------------------------------------------
if grep -qE 'ksu_selinux_hide_enabled|fake_status|initialize_fake_status|my_sel_open_handle_status' security/selinux/selinuxfs.c; then
    die "susfs selinuxfs hunks reached security/selinux/selinuxfs.c, which the KSU side and _hook own"
fi
for sym in SUSFS_IS_INODE_SUS_MAP susfs_is_current_proc_umounted_app; do
    grep -rqs "$sym" fs include/linux || die "$sym never reached the tree"
done
grep -q 'obj-$(CONFIG_KSU_SUSFS) += susfs.o' fs/Makefile || die "fs/Makefile does not build susfs.o"
grep -q 'susfs_init[[:space:]]*();' "$KSU_FOLDER/kernel/core/init.c" || die "susfs_init() is not called from the KSU tree"
if awk '/^enum clear_refs_types \{/{f=1} f&&/CONFIG_KSU_SUSFS/{bad=1} f&&/^\};/{f=0} END{exit !bad}' "$tm"; then
    die "a susfs guard landed inside enum clear_refs_types in $tm"
fi

SUSVER="$(grep '#define SUSFS_VERSION' include/linux/susfs.h | awk -F'"' '{print $2}')"
[ -n "$SUSVER" ] || die "could not read SUSFS_VERSION from include/linux/susfs.h"
[ -z "${GITHUB_ENV:-}" ] || echo "SUSVER=$SUSVER" >> "$GITHUB_ENV"
echo "✅ SUSFS $SUSVER patched into ${ANDROID_VER:-?}-${KERNEL_VER:-?}"
