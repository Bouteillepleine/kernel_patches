#!/usr/bin/env bash
#
# Apply the NoMount stack to a kernel tree. ONE copy, called by every builder.
#
# It used to be five steps duplicated in three builder repos, with a fourth
# near-copy in this repo's verify workflow. That is four places to edit for one
# patch, and the copies drift: the verifier spent a day applying four of the
# seven _ghost families while reporting on all of them, because ghost_truncate,
# ghost_utimes and ghost_chmod were added to the builders and not to it.
#
# Living in kernel_patches is deliberate -- the patches and the code that applies
# them now version together, so a new patch file and its apply line land in the
# same commit.
#
# EVERY family is applied at fuzz 0. A hunk that only lands "with fuzz" can put a
# guard in the wrong function silently: three of the four path_*xattr() bodies
# are character-identical below `retry:`, and hide_selinux_attr.patch used to go
# in at fuzz 2 against ONE line of trailing context, i.e. placed by line number.
# `-F0` is not the same as "no offset" -- offsets are fine and expected.
#
# EVERY family is verified after it is applied. The families join the kernel
# through weak externs and unconditional obj-y, so any subset of them links,
# boots, and silently does less than it says. `verify` asserts, per family, that
# the guard symbols reached the source AND that the object carrying them is
# wired into obj-y AND (where the family has one) that its CONFIG symbol is set.
#
# ENV CONTRACT:
#   COMMON_KERNEL_FOLDER          kernel source root (fs/, security/, ...)   [required]
#   BOUTEILLE_KERNEL_PATCHES_FOLDER  checkout of THIS repo   [required except hookless/record-version]
#   KSU_FOLDER                    KernelSU tree                    [hook, all]
#   GITHUB_WORKSPACE              scratch for the engine clone     [hookless, all]
#   GITHUB_ENV                    to export NMVER                  [record-version]
#   KERNEL_VER                    5.10|5.15|6.1|6.6|6.12  [optional; cross-checked
#                                 against COMMON_KERNEL_FOLDER/Makefile and, if it
#                                 disagrees, the run FAILS rather than guessing]
#   NOMOUNT_REF                   NoMount-Suite branch, default main [hookless]
#   NOMOUNT_DEFCONFIG             defconfig basename, default gki_defconfig
#   KERNEL_CONFIG_FILE            generated .config to assert against, if it
#                                 already exists (otherwise out/.config and
#                                 .config under the kernel root are tried)
#
# Usage: apply_nomount_stack.sh <all|hookless|record-version|hook|pathhide|ghost>
#        apply_nomount_stack.sh verify [hookless] [hook] [pathhide] [ghost]
#        apply_nomount_stack.sh assert-config      (after the defconfig step)
set -euo pipefail

usage() {
    echo "usage: $0 <all|hookless|record-version|hook|pathhide|ghost|assert-config>" >&2
    echo "       $0 verify [hookless] [hook] [pathhide] [ghost]   (default: all four)" >&2
    exit 2
}

die() { echo "::error::apply_nomount_stack: $*" >&2; exit 1; }

need() {
    local v
    for v in "$@"; do
        [ -n "${!v:-}" ] || die "$v is not set"
    done
}

[ $# -ge 1 ] || usage
CMD="$1"
shift

# ---------------------------------------------------------------------------
# Kernel version: taken from the tree, not from the environment.
#
# KERNEL_VER used to be trusted outright, and it decides which variant of five
# different families gets applied. Two of those families -- quiet_selinux_audit
# and its _legacy twin -- have BYTE-IDENTICAL patch context on all five kernel
# versions and differ only inside the added code, so a wrong KERNEL_VER selects
# a file that dry-runs perfectly and then fails to compile. Others are worse:
# they would apply and be wrong.
# ---------------------------------------------------------------------------
resolve_kv() {
    local mk="$COMMON_KERNEL_FOLDER/Makefile" v p
    [ -f "$mk" ] || die "no $mk -- COMMON_KERNEL_FOLDER is not a kernel tree"
    v="$(sed -n 's/^VERSION[[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' "$mk" | head -n1)"
    p="$(sed -n 's/^PATCHLEVEL[[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' "$mk" | head -n1)"
    [ -n "$v" ] && [ -n "$p" ] || die "cannot read VERSION/PATCHLEVEL from $mk"
    KV="$v.$p"
    case "$KV" in
    5.10 | 5.15 | 6.1 | 6.6 | 6.12) ;;
    *) die "kernel $KV is not one of 5.10 5.15 6.1 6.6 6.12 -- refusing to guess which variants it wants" ;;
    esac
    if [ -n "${KERNEL_VER:-}" ] && [ "$KERNEL_VER" != "$KV" ]; then
        die "KERNEL_VER='$KERNEL_VER' but $mk says '$KV'. One of them is wrong, and the variant tables below are keyed on it."
    fi
    KERNEL_VER="$KV"
    echo "kernel version: $KV (from $mk)"
}

# ---------------------------------------------------------------------------
# Patch application. Fuzz 0, always, everywhere.
# ---------------------------------------------------------------------------
apply_or_die() {
    local p="$1" root="${2:-$COMMON_KERNEL_FOLDER}"
    [ -f "$p" ] || die "missing patch: $p"
    if patch -p1 -F0 --forward --dry-run -d "$root" <"$p" >/dev/null 2>&1; then
        patch -p1 -F0 --forward -d "$root" <"$p" >/dev/null
        echo "  applied: $(basename "$p")"
    elif patch -p1 -F0 --reverse --dry-run -d "$root" <"$p" >/dev/null 2>&1; then
        echo "  already applied: $(basename "$p")"
    else
        die "$(basename "$p") neither applies at fuzz 0 nor is already present in $root"
    fi
}

# apply_first_of <family> <pinned-basename|-> <variant-path...>
#
# The variant is chosen BY NAME from the per-version table, not by taking the
# first that happens to dry-run clean. That distinction is not academic:
#
#   * quiet_selinux_audit.patch and quiet_selinux_audit_legacy.patch dry-run
#     clean on ALL FIVE kernel versions -- their insertion point is a
#     blank-line-delimited spot around `a->selinux_audit_data = &sad;` that never
#     changed -- and differ only in whether the added code passes `state` to
#     security_sid_to_context(). "First that applies" picks wrong on three.
#   * hide_selinux_attr.patch also applies on 6.12, where the richer
#     hide_selinux_attr_6_12.patch (which additionally guards
#     selinux_inode_setxattr) is the one that must win.
#
# So a multi-match is only an ERROR when nothing is pinned; when a pin exists it
# resolves the ambiguity and the others are merely reported.
apply_first_of() {
    local family="$1" want="$2"
    shift 2
    local p base hits="" nhits=0 sel="" root="$COMMON_KERNEL_FOLDER"
    for p in "$@"; do
        [ -f "$p" ] || die "$family: variant file is missing: $p"
        if patch -p1 -F0 --forward --dry-run -d "$root" <"$p" >/dev/null 2>&1 ||
            patch -p1 -F0 --reverse --dry-run -d "$root" <"$p" >/dev/null 2>&1; then
            base="$(basename "$p")"
            hits="$hits $base"
            nhits=$((nhits + 1))
            [ -n "$sel" ] || sel="$p"
            if [ "$base" = "$want" ]; then sel="$p"; fi
        fi
    done
    [ "$nhits" -gt 0 ] || die "$family: no variant applies at fuzz 0 on $KERNEL_VER (tried: $*)"
    if [ "$want" = "-" ]; then
        [ "$nhits" -eq 1 ] || die "$family: $nhits variants apply on $KERNEL_VER ($hits ) and the table pins none. Pin one, or refit them so exactly one claims this tree -- picking the first is how a guard lands in the wrong function."
    else
        case " $hits " in
        *" $want "*) ;;
        *) die "$family: pinned variant '$want' does not apply at fuzz 0 on $KERNEL_VER; these do:$hits. The variants do not carry the same hunks, so falling back would silently drop coverage. Refit '$want' to this tree instead." ;;
        esac
        # Plain log line, NOT ::warning::. The comment above this function says
        # why a multi-match is expected here: the variants deliberately overlap and
        # the pin is what resolves them. Annotating an outcome that is correct on
        # every build trains you to ignore the annotation list, which is where a
        # real warning has to be visible. The genuine failures are still fatal --
        # nothing pinned with several matches, or a pin that does not apply.
        [ "$nhits" -eq 1 ] || echo "  $family: '$want' pinned (also applicable:$hits )"
    fi
    apply_or_die "$sel" "$root"
}

# ---------------------------------------------------------------------------
# Post-apply verification.
#
# Every check here is on something the patches produce, never on something this
# script wrote a moment earlier. The old pathhide check greped fs/Makefile for a
# line the script itself had appended ten lines above, so it could not fail.
# ---------------------------------------------------------------------------
has() { # has <file> <fixed-string>
    grep -qF -- "$2" "$1" || die "$3"
}

hasnt() { # hasnt <file> <fixed-string>
    if grep -qF -- "$2" "$1" 2>/dev/null; then die "$3"; fi
    return 0
}

objy() { # objy <makefile> <object> <what>
    # Anchored, and the '.' is escaped: `make fs/proc/ghost.o` builds an object
    # that is not in obj-y at all, so "it compiled" proves nothing about whether
    # it reaches vmlinux. This is the check that does.
    local esc="${2//./\.}"
    grep -qE "^obj-y[[:space:]]*\+=[[:space:]]*$esc([[:space:]]|\$)" "$1" ||
        die "$3: no '^obj-y += $2' line in $1 -- the object would never be linked into the kernel"
}

find_config() {
    local c
    for c in "${KERNEL_CONFIG_FILE:-}" "$COMMON_KERNEL_FOLDER/out/.config" \
        "$COMMON_KERNEL_FOLDER/.config" "${OUT_DIR:-}/.config"; do
        if [ -n "$c" ] && [ -f "$c" ]; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

# assert_config <SYMBOL> <why> -- hard when a .config exists, and hard when
# `assert-config` was asked for explicitly. At apply time the tree is usually
# not configured yet, which is the one case that can only be reported.
CONFIG_STRICT=0
assert_config() {
    local sym="$1" why="$2" cfg
    if cfg="$(find_config)"; then
        grep -qx "$sym=y" "$cfg" ||
            die "$sym is not set in $cfg -- $why"
        echo "  config: $sym=y in $cfg"
    elif [ "$CONFIG_STRICT" = 1 ]; then
        die "no .config found (tried KERNEL_CONFIG_FILE, $COMMON_KERNEL_FOLDER/out/.config, $COMMON_KERNEL_FOLDER/.config) -- cannot assert $sym"
    else
        # Plain log line, NOT ::notice::. At apply time the tree is not configured
        # yet, and that is the normal case for every builder -- so this fired on
        # every build. It is also redundant for the symbol that matters:
        # verify_hookless() has already hard-failed unless CONFIG_NOMOUNT=y is in
        # the defconfig, which is the file the build actually reads. `assert-config`
        # stays available (and fatal, CONFIG_STRICT=1) for a caller that wants the
        # post-defconfig check against a generated .config.
        echo "  $sym: not verifiable yet (no .config at apply time; see assert-config)"
    fi
}

verify_hookless() {
    local d="$COMMON_KERNEL_FOLDER"
    [ -f "$d/fs/nomount.c" ] || die "_hookless: fs/nomount.c missing"
    [ -f "$d/fs/nomount.h" ] || die "_hookless: fs/nomount.h missing"
    has "$d/fs/Kconfig" 'config NOMOUNT' "_hookless: fs/Kconfig edit missing"
    has "$d/fs/Makefile" 'obj-$(CONFIG_NOMOUNT) += nomount.o' "_hookless: fs/Makefile edit missing"
    grep -qE 'vfs_map_meta_override|nomount_spoof_mmap_metadata' "$d/fs/proc/task_mmu.c" ||
        die "_hookless: task_mmu.c hook missing"
    grep -qx 'CONFIG_NOMOUNT=y' "$(defconfig_path)" ||
        die "_hookless: CONFIG_NOMOUNT=y is not in $(defconfig_path)"
    assert_config CONFIG_NOMOUNT "the engine is behind CONFIG_NOMOUNT; without it fs/nomount.o is not built at all and every hookless hook is absent"
    echo "_hookless: verified"
}

verify_hook() {
    local d="$COMMON_KERNEL_FOLDER"
    has "$d/security/selinux/selinuxfs.c" 'sel_ctx_hidden' "_hook: selinuxfs.c gate missing"
    has "$d/security/selinux/selinuxfs.c" 'sel_hidden_bytes' "_hook: selinuxfs.c reply filter missing"
    has "$d/security/selinux/hooks.c" ':ksu:' "_hook: hooks.c attr guard missing"
    has "$d/security/selinux/avc.c" ':ksu:' "_hook: avc.c denial filter missing"
    # The avc filter must stay uid-gated. Ungated it deletes the whole record
    # class, including the uid-1000 servicemanager denial that diagnosed the
    # uid-gate-widening incident in common/_hook/README.md.
    has "$d/security/selinux/avc.c" 'current_uid()' "_hook: avc.c filter has lost its uid gate"
    has "$d/security/selinux/Makefile" 'selinuxfs.o' "_hook: selinuxfs.o is not in security/selinux/Makefile"
    if [ -n "${KSU_FOLDER:-}" ]; then
        hasnt "$KSU_FOLDER/kernel/selinux/rules.c" 'selinux_status_update_policyload' \
            "_hook: fix_selinux_seqno did not land -- KSU still writes policyload=0 to /sys/fs/selinux/status"
        has "$KSU_FOLDER/kernel/selinux/rules.c" 'selnl_notify_policyload' \
            "_hook: selnl_notify_policyload was removed -- see README, gating it is a documented bootloop risk"
    fi
    assert_config CONFIG_SECURITY_SELINUX "every _hook guard lives in security/selinux/, which is built only under CONFIG_SECURITY_SELINUX -- without it the whole family is dead code"
    echo "_hook: verified"
}

verify_pathhide() {
    local d="$COMMON_KERNEL_FOLDER"
    [ -f "$d/fs/pathhide.c" ] || die "_pathhide: fs/pathhide.c missing"
    [ -f "$d/fs/pathhide.h" ] || die "_pathhide: fs/pathhide.h missing"
    objy "$d/fs/Makefile" 'pathhide.o' "_pathhide"
    has "$d/fs/proc/task_mmu.c" 'pathhide_match_file' "_pathhide: maps/smaps guards missing from task_mmu.c"
    has "$d/fs/proc/base.c" 'pathhide_match_file' "_pathhide: map_files guards missing from base.c"
    # The /proc/<pid>/fd half was removed on purpose: a hidden fd stays
    # allocated, so fcntl(N, F_GETFD) succeeds where /proc/self/fd/N is ENOENT.
    hasnt "$d/fs/proc/fd.c" 'pathhide' \
        "_pathhide: fs/proc/fd.c is patched again. The fd half was removed because a hidden fd stays allocated -- fcntl(N, F_GETFD) succeeds where /proc/self/fd/N answers ENOENT, which is unconditional and never true on stock."
    # No CONFIG symbol by design: a new entry in /proc/config.gz would announce
    # the patch to anything that reads it, which is what this file exists to
    # prevent. obj-y is therefore the whole of the build-side assertion.
    echo "_pathhide: verified (no CONFIG symbol by design -- see README)"
}

verify_ghost() {
    local d="$COMMON_KERNEL_FOLDER"
    [ -f "$d/fs/proc/ghost.c" ] || die "_ghost: fs/proc/ghost.c missing"
    [ -f "$d/fs/proc/ghost.h" ] || die "_ghost: fs/proc/ghost.h missing"
    objy "$d/fs/proc/Makefile" 'ghost.o' "_ghost"
    has "$d/fs/namei.c" 'ghost_hidden_path' "_ghost: fs/namei.c guards missing"
    has "$d/fs/xattr.c" 'ghost_hidden_path' "_ghost: fs/xattr.c guards missing"
    has "$d/fs/open.c" 'ghost_hidden_path' "_ghost: fs/open.c guards missing (truncate/chmod)"
    has "$d/fs/utimes.c" 'ghost_hidden_path' "_ghost: fs/utimes.c guard missing (utimensat)"
    has "$d/fs/namei.c" 'unlikely(err == -ENOTDIR)' "_ghost: path_lookupat ENOTDIR guard missing"
    has "$d/fs/namei.c" 'err2 && ghost_hidden_path' "_ghost: filename_create guard missing (mkdirat/mknodat)"
    if awk '/^int do_renameat2/,/^}/' "$d/fs/namei.c" | grep -q 'ghost_hidden_path'; then
        die "_ghost: the create guard landed in do_renameat2, not filename_create"
    fi
    hasnt "$d/fs/proc/ghost.c" 'proc_create' \
        "_ghost: ghost.c owns a /proc node -- a file whose job is concealing files must not own a name no stock kernel has"
    echo "_ghost: verified (no CONFIG symbol by design -- see README)"
}

defconfig_path() {
    echo "$COMMON_KERNEL_FOLDER/arch/arm64/configs/${NOMOUNT_DEFCONFIG:-gki_defconfig}"
}

# ---------------------------------------------------------------------------
# Families
# ---------------------------------------------------------------------------
do_hookless() {
    need GITHUB_WORKSPACE COMMON_KERNEL_FOLDER
    echo "::group::Apply NoMount (hookless VFS) patch"
    local NM_SRC="$GITHUB_WORKSPACE/nomount_hookless" NM_PATCH DEFCONFIG
    DEFCONFIG="$(defconfig_path)"
    # NOT `touch`ed into existence. A defconfig this script invents is not the
    # one the build reads, so CONFIG_NOMOUNT=y would land in a file nothing ever
    # opens and the engine would be quietly absent from the kernel.
    [ -f "$DEFCONFIG" ] || die "defconfig $DEFCONFIG does not exist. Refusing to create it -- a defconfig invented here is not the one the build reads. Set NOMOUNT_DEFCONFIG to the fragment this build actually uses."
    rm -rf "$NM_SRC"
    # The engine moved INTO the Suite repo. It is versioned and flashed with the
    # userspace that drives it -- the control plane is a private protocol between
    # the two, and a mismatched pair reads as "engine not responding" with nothing
    # to say why -- so keeping them in one tree is what makes a matched pair the
    # default instead of a thing to remember. The path INSIDE the tree is
    # unchanged (hookless/src, hookless/patches); only the repo and ref move.
    # Bouteillepleine/NoMount-Suite is the canonical repo: it is what publishes
    # the module releases, and its tree carries the engine under hookless/ --
    # byte-identical to what the development tree served, verified by digest
    # before this moved. Consuming the PUBLISHED tree rather than a development
    # branch is also the better arrangement: a kernel build now pins to what was
    # actually released, not to whatever landed on a working branch this morning.
    # Default ref is `main`, that repo's default branch.
    git clone --depth 1 -b "${NOMOUNT_REF:-main}" https://github.com/Bouteillepleine/NoMount-Suite.git "$NM_SRC" \
        || die "could not clone the NoMount engine at ref '${NOMOUNT_REF:-main}' from Bouteillepleine/NoMount-Suite. It was Bouteillepleine/nomount@suite before, and kbuild@hookless before that; if something still passes nomount_ref=suite or =hookless, neither exists in this repo -- use 'main'."
    # The engine collapsed the ten per-version integration patches into one that
    # applies across 4.9-6.18. Prefer it; fall back to the per-version name so
    # this script keeps working against an engine ref that still ships the ten
    # (nomount_ref and patches_ref are chosen independently, so either pairing
    # is a legitimate build).
    NM_PATCH="$NM_SRC/hookless/patches/nomount_kernel_integration.patch"
    if [ ! -f "$NM_PATCH" ]; then
        NM_PATCH="$NM_SRC/hookless/patches/nomount_${KERNEL_VER}_kernel_integration.patch"
        [ -f "$NM_PATCH" ] || die "no hookless NoMount patch for $KERNEL_VER: neither\
 $NM_SRC/hookless/patches/nomount_kernel_integration.patch nor $NM_PATCH exists"
    fi
    echo "hookless integration patch: ${NM_PATCH##*/}"
    rm -f "$COMMON_KERNEL_FOLDER/fs/nomount.c" "$COMMON_KERNEL_FOLDER/fs/nomount.h"
    cp "$NM_SRC/hookless/src/nomount.c" "$COMMON_KERNEL_FOLDER/fs/nomount.c"
    cp "$NM_SRC/hookless/src/nomount.h" "$COMMON_KERNEL_FOLDER/fs/nomount.h"
    # The one family still applied with fuzz: it is generated per kernel version
    # by the engine repo and carries no variant table here to pin.
    patch -p1 --forward --fuzz=1 -d "$COMMON_KERNEL_FOLDER" <"$NM_PATCH" ||
        die "NoMount hookless patch failed to apply for $KERNEL_VER"
    sed -i '/^CONFIG_NOMOUNT=/d' "$DEFCONFIG"
    echo "CONFIG_NOMOUNT=y" >>"$DEFCONFIG"
    verify_hookless
    echo "::endgroup::"
}

do_record_version() {
    need COMMON_KERNEL_FOLDER GITHUB_ENV
    local NM_HDR="$COMMON_KERNEL_FOLDER/fs/nomount.h" NMVER=""
    if [ -f "$NM_HDR" ]; then
        NMVER="$(sed -n 's/^#define[[:space:]]\+NM_MODULE_VERSION[[:space:]]\+"\([^"]*\)".*/\1/p' "$NM_HDR" | head -n1)"
    fi
    echo "NMVER=${NMVER:-unknown}" >>"$GITHUB_ENV"
    echo "NoMount version: ${NMVER:-unknown}"
}

do_hook() {
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KSU_FOLDER
    echo "::group::Apply SELinux oracle (_hook) patches"
    local HOOK="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_hook"
    dos2unix "$HOOK"/*.patch 2>/dev/null || true

    # Variant table. Every family is pinned on every supported version; see
    # apply_first_of() for why "first that applies" is not good enough here.
    local REQ_SFS REQ_ATTR REQ_AUDIT
    case "$KERNEL_VER" in
    6.6 | 6.12)
        REQ_SFS=hide_selinux_selinuxfs_6_12.patch
        REQ_AUDIT=quiet_selinux_audit.patch
        ;;
    5.10 | 5.15 | 6.1)
        REQ_SFS=hide_selinux_selinuxfs_5_10.patch
        REQ_AUDIT=quiet_selinux_audit_legacy.patch
        ;;
    esac
    case "$KERNEL_VER" in
    6.12) REQ_ATTR=hide_selinux_attr_6_12.patch ;;
    # 5.10/5.15/6.1/6.6 take the setprocattr-only fallback, so
    # setxattr(security.selinux) stays uncovered there -- see the README.
    *) REQ_ATTR=hide_selinux_attr.patch ;;
    esac

    apply_first_of selinuxfs "$REQ_SFS" \
        "$HOOK/hide_selinux_selinuxfs_6_12.patch" "$HOOK/hide_selinux_selinuxfs_5_10.patch"
    apply_first_of attr "$REQ_ATTR" \
        "$HOOK/hide_selinux_attr_6_12.patch" "$HOOK/hide_selinux_attr.patch"
    apply_first_of avc-audit "$REQ_AUDIT" \
        "$HOOK/quiet_selinux_audit.patch" "$HOOK/quiet_selinux_audit_legacy.patch"
    apply_or_die "$HOOK/fix_selinux_seqno.patch" "$KSU_FOLDER"
    verify_hook
    echo "::endgroup::"
}

do_pathhide() {
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER
    echo "::group::Apply pathhide (maps cloak)"
    local PH="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_pathhide" d="$COMMON_KERNEL_FOLDER"
    rm -f "$d/fs/pathhide.c" "$d/fs/pathhide.h"
    cp "$PH/pathhide.c" "$d/fs/pathhide.c"
    cp "$PH/pathhide.h" "$d/fs/pathhide.h"
    dos2unix "$d/fs/pathhide.c" "$d/fs/pathhide.h" 2>/dev/null || true
    dos2unix "$PH"/*.patch 2>/dev/null || true
    apply_or_die "$PH/pathhide_${KERNEL_VER}_integration.patch"
    apply_or_die "$PH/pathhide_mapfiles_${KERNEL_VER}_integration.patch"
    # pathhide.c/.h live in fs/, not fs/proc/, so this appends the obj-y line
    # rather than applying pathhide_build_integration.patch (which is the
    # fs/proc/ layout). verify_pathhide() asserts the RESULT, not this write.
    grep -qE '^obj-y[[:space:]]*\+=.*pathhide\.o' "$d/fs/Makefile" ||
        echo 'obj-y += pathhide.o' >>"$d/fs/Makefile"
    verify_pathhide
    echo "::endgroup::"
}

do_ghost() {
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER
    echo "::group::Apply _ghost (O_PATH / *xattr / link / ENOTDIR existence cloak)"
    local GH="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_ghost" d="$COMMON_KERNEL_FOLDER"
    rm -f "$d/fs/proc/ghost.c" "$d/fs/proc/ghost.h"
    cp "$GH/ghost.c" "$d/fs/proc/ghost.c"
    cp "$GH/ghost.h" "$d/fs/proc/ghost.h"
    dos2unix "$d/fs/proc/ghost.c" "$d/fs/proc/ghost.h" 2>/dev/null || true
    dos2unix "$GH"/*.patch 2>/dev/null || true

    local REQ_XATTR REQ_LINKAT REQ_CHMOD
    case "$KERNEL_VER" in
    6.12 | 6.6)
        REQ_XATTR=ghost_xattr_6_12.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod.patch
        ;;
    6.1 | 5.15)
        REQ_XATTR=ghost_xattr_5_15.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        ;;
    5.10)
        REQ_XATTR=ghost_xattr.patch
        REQ_LINKAT=ghost_linkat.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        ;;
    esac

    apply_or_die "$GH/ghost_o_path.patch"
    apply_first_of ghost-xattr "$REQ_XATTR" \
        "$GH/ghost_xattr_6_12.patch" "$GH/ghost_xattr_5_15.patch" "$GH/ghost_xattr.patch"
    apply_first_of ghost-linkat "$REQ_LINKAT" \
        "$GH/ghost_linkat_5_15.patch" "$GH/ghost_linkat.patch"
    # One file, 5.10 through 6.12: the guards sit in path_lookupat() and
    # do_open(), neither of which cares whether the tree spells the unlazy step
    # unlazy_walk() or try_to_unlazy(). That split is what needed two variants.
    apply_or_die "$GH/ghost_notdir.patch"
    apply_or_die "$GH/ghost_truncate.patch"
    apply_or_die "$GH/ghost_utimes.patch"
    apply_first_of ghost-chmod "$REQ_CHMOD" \
        "$GH/ghost_chmod.patch" "$GH/ghost_chmod_5_10.patch"
    apply_or_die "$GH/ghost_create.patch"
    apply_or_die "$GH/ghost_build_integration.patch"
    verify_ghost
    echo "::endgroup::"
}

# do_verify [family...] -- defaults to every family. `all` always verifies all
# four; a builder that ships only some of them can name the ones it applied.
do_verify() {
    need COMMON_KERNEL_FOLDER
    local f
    [ $# -gt 0 ] || set -- hookless hook pathhide ghost
    echo "::group::Verify the NoMount stack landed"
    for f in "$@"; do
        case "$f" in
        hookless) verify_hookless ;;
        hook) verify_hook ;;
        pathhide) verify_pathhide ;;
        ghost) verify_ghost ;;
        *) die "verify: unknown family '$f'" ;;
        esac
    done
    echo "verified: $*"
    echo "::endgroup::"
}

case "$CMD" in
all)
    need GITHUB_WORKSPACE BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KSU_FOLDER
    resolve_kv
    do_hookless
    if [ -n "${GITHUB_ENV:-}" ]; then do_record_version; fi
    do_hook
    do_pathhide
    do_ghost
    do_verify hookless hook pathhide ghost
    ;;
hookless)
    need GITHUB_WORKSPACE COMMON_KERNEL_FOLDER
    resolve_kv
    do_hookless
    ;;
record-version)
    do_record_version
    ;;
hook)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KSU_FOLDER
    resolve_kv
    do_hook
    ;;
pathhide)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER
    resolve_kv
    do_pathhide
    ;;
ghost)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER
    resolve_kv
    do_ghost
    ;;
verify)
    need COMMON_KERNEL_FOLDER
    resolve_kv
    do_verify "$@"
    ;;
assert-config)
    need COMMON_KERNEL_FOLDER
    CONFIG_STRICT=1
    assert_config CONFIG_NOMOUNT "the engine is behind CONFIG_NOMOUNT; without it fs/nomount.o is not built at all"
    assert_config CONFIG_SECURITY_SELINUX "every _hook guard is compiled only under CONFIG_SECURITY_SELINUX"
    ;;
*)
    usage
    ;;
esac
