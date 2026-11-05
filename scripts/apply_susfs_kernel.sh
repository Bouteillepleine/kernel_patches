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
# but needs a new file for every sublevel and every manifest family. Those
# kernel_fix_* variants were superseded by this and have been deleted.
#
# security/selinux/selinuxfs.c is dropped outright: the KSU side and NoMount's
# _hook family already own the hiding there, and letting susfs in as well means
# two implementations fighting over fake_status. That is asserted below, not
# assumed.
#
# A reject the surgery cannot resolve is a HARD FAILURE. Half-applied hiding
# compiles, boots, and lies about what it hides.
#
# A hunk that is MISSING from the patch rejects nothing and so passes every
# check above. susfs regenerated the android16-6.12 patch against a mainline
# rollup loop and lost its Case 4 sus_map guard that way; the build stayed
# green and /proc/<pid>/smaps_rollup kept counting a hidden mapping on the
# contended path. Those are REPAIRS in susfs_patch_surgery.py: unconditional,
# printed as "repaired:", and each decides for itself whether this tree wants
# it, so it stands down again when upstream ships the hunk.
#
# WHICH REJECTS ARE EXPECTED is recorded here, per KMI, and a reject that is
# NOT on the list fails the build with the hunk printed. Without that the
# surgery runs on hunks nobody has looked at, and an upstream susfs change
# arriving as "7 hunks reconciled, build green" is indistinguishable from the
# state we are actually in. The KSU half of this stack already refuses that
# (EXPECTED_SUKISU_REJECTS in the SukiSu builder's configs/apply_susfs_patches.sh
# plus its "Unexpected KernelSU-side .rej" gate); the kernel half had none.
#
# The list is an ALLOWED SET, not an exact one: devices inside one KMI sit on
# different sublevels and reject slightly differently, so an entry that does not
# fire is reported as a plain line and never as a warning -- it fires on some
# other device of the same KMI. Seeded from the SukiSu builder's 26-job
# patch-matrix run against susfs v2.3.0, which covers 26 of its 82 configs; an
# unsampled sublevel that drifts now stops the build instead of being reconciled
# unseen, and the error says what to add.
#
# SUBCOMMANDS. The SukiSu builder cannot use one shot: its own
# configs/apply_susfs_patches.sh applies the kernel patch as part of doing the
# SukiSU-driver side, so the tree side has to run either side of it.
#   prepare   copy susfs's sources in, reconcile the patch, and write the
#             reconciled patch BACK over $SUSFS_FOLDER's copy, because the
#             caller that applies it re-derives that path for itself.
#   apply     apply the reconciled patch at fuzz 0.
#   verify    the post-apply fixups and every assertion, including that each
#             guard sits in the function it belongs to.
#   all       prepare + apply + verify in one process, on a PRIVATE copy of the
#             patch -- so a persistent susfs checkout is left pristine. This is
#             the default and what a builder with no fixer of its own wants.

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

CMD="${1:-all}"
case "$CMD" in
all | prepare | apply | verify) ;;
*) echo "usage: $0 [all|prepare|apply|verify]" >&2; exit 2 ;;
esac

for v in COMMON_KERNEL_FOLDER SUSFS_FOLDER KSU_FOLDER; do
    [ -n "${!v:-}" ] || die "$v is not set"
done
[ -d "$COMMON_KERNEL_FOLDER/fs" ] || die "COMMON_KERNEL_FOLDER=$COMMON_KERNEL_FOLDER has no fs/"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SURGERY="$HERE/susfs_patch_surgery.py"
GUARDS="$HERE/assert_guard_sites.py"
[ -f "$SURGERY" ] || die "$SURGERY is missing"
[ -f "$GUARDS" ] || die "$GUARDS is missing"

BRANCH="${SUSFS_KERNEL_BRANCH:-gki-${ANDROID_VER:?}-${KERNEL_VER:?}}"
SRC_PATCH="$SUSFS_FOLDER/kernel_patches/50_add_susfs_in_${BRANCH}.patch"
[ -f "$SRC_PATCH" ] || {
    echo "::error::apply_susfs_kernel: no kernel patch for $BRANCH"
    find "$SUSFS_FOLDER/kernel_patches" -maxdepth 1 -name '50_add_susfs_in_*.patch' | sort
    exit 1
}

cd "$COMMON_KERNEL_FOLDER"

# ---------------------------------------------------------------------------
# The expected-reject record. One line per hunk: <file:hunk> then why it
# rejects -- what the hunk IS and what it lands on top of, because that is what
# you need to know when one of them changes.
# ---------------------------------------------------------------------------
expected_rejects() {
    # Common to every KMI: susfs and NoMount guard the same statement here.
    cat <<'EOT'
fs/proc/base.c:4            the sus_map skip in proc_map_files_readdir(); pathhide_mapfiles skips at the same `if (!vma->vm_file) continue;`
fs/proc/task_mmu.c:3        the sus_kstat/OPEN_REDIRECT spoof in show_map_vma(); the hookless engine overrides dev/ino at the same statement
fs/proc/task_mmu.c:4        the sus_map guard at the head of show_smap(); pathhide renames that body to ph_show_smap() on 5.10-6.1, and Android's VMA-padding rework moved the statement susfs anchors on
fs/proc/task_mmu.c:5        the show_smaps_rollup() bypass; same loop pathhide walks, and the padding rework renamed its guard
EOT
    case "${ANDROID_VER}-${KERNEL_VER}" in
    android12-5.10) cat <<'EOT'
fs/namei.c:21               OPEN_REDIRECT in do_o_path(); ghost_o_path.patch guards the same `if (!error) {`
fs/stat.c:5                 the su-compat filename declaration in vfs_statx(); ghost_statx declares ghost_hidden_path() on the same anchor
fs/stat.c:6                 the su-compat preamble at vfs_statx()'s retry: label
EOT
        ;;
    android13-5.15) cat <<'EOT'
fs/Makefile:1               obj-$(CONFIG_KSU_SUSFS) += susfs.o; the hookless engine added its own obj line in the same region
fs/namei.c:18               OPEN_REDIRECT in do_o_path(); ghost_o_path.patch guards the same `if (!error) {`
fs/namespace.c:1            the susfs extern block; anchored on includes that move by sublevel
fs/open.c:1                 the susfs declarations; ghost_access/ghost_open/ghost_truncate sit in the same include region
fs/proc/task_mmu.c:1        the susfs extern block; anchored on includes that move by sublevel
fs/stat.c:4                 the su-compat preamble in vfs_statx(); ghost_statx declares ghost_hidden_path() on the same anchor
fs/stat.c:5                 the su-compat filename declaration in vfs_statx()
mm/memory.c:1               the SUS_MAP include; anchored on includes that move by sublevel
EOT
        ;;
    android14-6.1) cat <<'EOT'
fs/Makefile:1               obj-$(CONFIG_KSU_SUSFS) += susfs.o; the hookless engine added its own obj line in the same region
fs/exec.c:1                 the susfs_def.h include; anchored on #include <linux/dma-buf.h>, which older sublevels do not carry
fs/namei.c:18               OPEN_REDIRECT in do_o_path(); ghost_o_path.patch guards the same `if (!error) {`
fs/namespace.c:1            the susfs extern block; anchored on includes that move by sublevel
fs/proc/base.c:1            the susfs_def.h include; anchored on #include <uapi/linux/lsm.h>, which older sublevels do not carry
fs/stat.c:4                 the su-compat preamble in vfs_statx(); ghost_statx declares ghost_hidden_path() on the same anchor
EOT
        ;;
    android15-6.6) cat <<'EOT'
fs/exec.c:1                 the susfs_def.h include; anchored on #include <linux/dma-buf.h>, which older sublevels do not carry
fs/namei.c:18               OPEN_REDIRECT in do_o_path(); ghost_o_path.patch guards the same `if (!error) {`
fs/proc/base.c:1            the susfs_def.h include; anchored on #include <uapi/linux/lsm.h>, which older sublevels do not carry
fs/stat.c:4                 the su-compat preamble in vfs_statx(); ghost_statx declares ghost_hidden_path() on the same anchor
EOT
        ;;
    android16-6.12) cat <<'EOT'
fs/exec.c:1                 the susfs_def.h include; anchored on #include <linux/dma-buf.h>, which older sublevels do not carry
fs/namei.c:18               OPEN_REDIRECT in do_o_path(); ghost_o_path.patch guards the same `if (!error) {`
fs/proc/base.c:1            the susfs_def.h include; anchored on #include <uapi/linux/lsm.h>, which older sublevels do not carry
fs/proc/task_mmu.c:6        the show_smaps_rollup() bypass label; folded in with hunk #5
fs/stat.c:6                 the su-compat preamble in vfs_statx(); ghost_statx declares ghost_hidden_path() on the same anchor
security/selinux/hooks.c:1  the susfs extern block; anchored on #define SELINUX_INODE_INIT_XATTRS 1
EOT
        ;;
    *) die "no expected-reject record for ${ANDROID_VER:-?}-${KERNEL_VER:-?}" ;;
    esac
}

gate() { # gate <patch> <rejects...>
    local patch="$1" allowed unknown="" unused="" r spec
    shift
    allowed="$(expected_rejects | awk 'NF && $1 !~ /^#/ { print $1 }')"
    [ -n "$allowed" ] || die "the expected-reject record came back empty"
    for r in "$@"; do
        grep -qxF -- "$r" <<< "$allowed" || unknown="$unknown $r"
    done
    if [ -n "$unknown" ]; then
        echo "::error::apply_susfs_kernel: susfs hunks reject on ${ANDROID_VER}-${KERNEL_VER} that this stack has no record of:$unknown"
        echo "susfs4ksu has changed shape, or this tree has. Read the hunks below, decide where each"
        echo "one belongs, and add it to expected_rejects() in scripts/apply_susfs_kernel.sh with a"
        echo "reason -- or give it a named rule in scripts/susfs_patch_surgery.py if it needs placing"
        echo "by content rather than by context."
        python3 -I "$SURGERY" --show "$patch" . $unknown
        exit 1
    fi
    while read -r spec _; do
        [ -n "$spec" ] || continue
        printf '%s\n' "$@" | grep -qxF -- "$spec" || unused="$unused $spec"
    done <<< "$allowed"
    [ -z "$unused" ] || note "on record but clean here (another sublevel of this KMI rejects them):$unused"
}

do_prepare() { # do_prepare <patch-to-reconcile>
    local patch="$1" rejects sublevel
    sublevel="$(grep -m1 '^SUBLEVEL' Makefile | tr -d ' ' || true)"
    note "tree: ${ANDROID_VER:-?}-${KERNEL_VER:-?} ${sublevel:-SUBLEVEL=?}  patch: $(basename "$SRC_PATCH") ($BRANCH)"

    rejects="$(patch -p1 -F0 --forward --dry-run < "$patch" 2>&1 |
        awk '/^checking file/{f=$3} /Hunk #[0-9]+ FAILED/{n=$2; gsub("#","",n); print f":"n}')" || true
    if [ -n "$rejects" ]; then
        note "hunks that do not fit this tree:"
        printf '%s\n' "$rejects" | sed 's/^/     /'
    else
        note "the patch fits as-is; nothing to reconcile"
    fi

    gate "$patch" $rejects
    python3 -I "$SURGERY" --drop security/selinux/selinuxfs.c "$patch" . $rejects

    if ! patch -p1 -F0 --forward --dry-run < "$patch" >/dev/null 2>&1; then
        echo "::error::apply_susfs_kernel: the patch still rejects after reconciliation"
        echo "The hunk numbers below are positions in the RECONCILED patch, not in"
        echo "$(basename "$SRC_PATCH"): reconciliation drops hunks and that renumbers"
        echo "the rest, so #N here is the Nth surviving hunk of that file. Count @@"
        echo "headers in the original to find it."
        patch -p1 -F0 --forward --dry-run < "$patch" 2>&1 | grep -E '^(checking file|Hunk .*FAILED)' || true
        exit 1
    fi
}

do_apply() { # do_apply <reconciled-patch>
    local left
    # susfs's own sources go in with the patch, not before it: `prepare` has to
    # dry-run against the tree the caller will apply to, and a caller with its
    # own fixer copies them itself.
    cp "$SUSFS_FOLDER/kernel_patches/fs/"*.c fs/
    cp "$SUSFS_FOLDER/kernel_patches/include/linux/"*.h include/linux/
    patch -p1 -F0 --forward < "$1" >/dev/null
    find . -name '*.orig' -delete
    left="$(find . -name '*.rej' | sort)"
    [ -z "$left" ] || die "rejects left: $(echo "$left" | tr '\n' ' ')"
}

do_verify() {
    local tm=fs/proc/task_mmu.c before SUSVER SH

    # OPEN_REDIRECT calls VMA_PAD_START() and __fold_filemap_fixup_entry(), which
    # only exist on GKI branches carrying Google's page-size-migration work.
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

    # The enable patch rewrites my_setprocattr()'s signature in the KSU tree and
    # drops __nocfi from it. NoMount's _hook family put its timing probe in that
    # function and its verifier locates the function by `__nocfi .*setprocattr`, so
    # without this the probe is still there and still correct while `verify` reports
    # it as missing. Restoring the qualifier is also right on its own terms: the
    # function is reached through a patched LSM slot, which is an indirect call.
    SH="$KSU_FOLDER/kernel/feature/selinux_hide.c"
    if [ -f "$SH" ] && grep -q 'ksu_probe_ctx' "$SH" && ! grep -q '__nocfi .*setprocattr' "$SH"; then
        sed -i -E 's/^((static )?int )(my_setprocattr\(const char)/\1__nocfi \3/' "$SH"
        grep -q '__nocfi .*my_setprocattr' "$SH" ||
            die "could not restore __nocfi on my_setprocattr() in $SH"
        note "restored __nocfi on my_setprocattr(); the enable patch had rewritten its signature"
    fi

    # ---- assertions ---------------------------------------------------------
    if grep -qE 'ksu_selinux_hide_enabled|fake_status|initialize_fake_status|my_sel_open_handle_status' security/selinux/selinuxfs.c; then
        die "susfs selinuxfs hunks reached security/selinux/selinuxfs.c, which the KSU side and _hook own"
    fi
    # Every guard in the function it belongs to -- the symbol checks below prove a
    # hunk was not DROPPED, and cannot see one that was placed in the wrong body.
    python3 -I "$GUARDS" .
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
}

case "$CMD" in
prepare)
    # Reconcile in place: the caller applies the patch itself and re-derives
    # this path, so it has to see the reconciled version.
    do_prepare "$SRC_PATCH"
    note "reconciled patch written back to $SRC_PATCH"
    ;;
apply)
    do_apply "$SRC_PATCH"
    ;;
verify)
    do_verify
    ;;
all)
    # Private copy: a persistent susfs checkout stays pristine.
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    cp "$SRC_PATCH" "$WORK/50_add.patch"
    do_prepare "$WORK/50_add.patch"
    do_apply "$WORK/50_add.patch"
    do_verify
    ;;
esac
