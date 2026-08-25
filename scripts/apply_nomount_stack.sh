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
# ENV CONTRACT (all required unless noted):
#   COMMON_KERNEL_FOLDER          kernel source root (fs/, security/, ...)
#   KERNEL_VER                    5.10 | 5.15 | 6.1 | 6.6 | 6.12
#   BOUTEILLE_KERNEL_PATCHES_FOLDER  checkout of THIS repo
#   KSU_FOLDER                    KernelSU tree            (hook only)
#   GITHUB_WORKSPACE              scratch for the kbuild clone (hookless only)
#   GITHUB_ENV                    to export NMVER          (record-version only)
#   NOMOUNT_REF                   kbuild branch, default hookless (hookless only)
#
# Usage: apply_nomount_stack.sh <hookless|record-version|hook|pathhide|ghost>
set -euo pipefail

usage() {
    echo "usage: $0 <hookless|record-version|hook|pathhide|ghost>" >&2
    exit 2
}

need() {
    local v
    for v in "$@"; do
        if [ -z "${!v:-}" ]; then
            echo "::error::apply_nomount_stack: $v is not set" >&2
            exit 1
        fi
    done
}

[ $# -eq 1 ] || usage

case "$1" in
hookless)
    need GITHUB_WORKSPACE COMMON_KERNEL_FOLDER KERNEL_VER
    echo "::group::Apply NoMount (hookless VFS) patch"
    NM_SRC="$GITHUB_WORKSPACE/nomount_hookless"
    rm -rf "$NM_SRC"
    git clone --depth 1 -b "${NOMOUNT_REF:-hookless}" https://github.com/Bouteillepleine/kbuild.git "$NM_SRC"
    NM_PATCH="$NM_SRC/hookless/patches/nomount_${KERNEL_VER}_kernel_integration.patch"
    DEFCONFIG="$COMMON_KERNEL_FOLDER/arch/arm64/configs/gki_defconfig"
    if [ ! -f "$NM_PATCH" ]; then
      echo "::error::No hookless NoMount patch for KERNEL_VER=${KERNEL_VER} ($NM_PATCH)"
      exit 1
    else
      cd "$COMMON_KERNEL_FOLDER"
      rm -f fs/nomount.c fs/nomount.h
      cp "$NM_SRC/hookless/src/nomount.c" fs/nomount.c
      cp "$NM_SRC/hookless/src/nomount.h" fs/nomount.h
      if patch -p1 --forward --fuzz=1 < "$NM_PATCH"; then
        grep -q 'config NOMOUNT' fs/Kconfig \
          || { echo "::error::NoMount: fs/Kconfig edit missing"; exit 1; }
        grep -qF 'obj-$(CONFIG_NOMOUNT) += nomount.o' fs/Makefile \
          || { echo "::error::NoMount: fs/Makefile edit missing"; exit 1; }
        grep -qE 'vfs_map_meta_override|nomount_spoof_mmap_metadata' fs/proc/task_mmu.c \
          || { echo "::error::NoMount: task_mmu.c hook missing"; exit 1; }
        mkdir -p "$(dirname "$DEFCONFIG")"; touch "$DEFCONFIG"
        sed -i '/^CONFIG_NOMOUNT=/d' "$DEFCONFIG"
        echo "CONFIG_NOMOUNT=y" >> "$DEFCONFIG"
        echo "NoMount (hookless) applied + CONFIG_NOMOUNT=y for ${KERNEL_VER}"
      else
        echo "::error::NoMount hookless patch failed to apply for ${KERNEL_VER}"
        exit 1
      fi
    fi
    echo "::endgroup::"
    ;;
record-version)
    need COMMON_KERNEL_FOLDER GITHUB_ENV
    NM_HDR="$COMMON_KERNEL_FOLDER/fs/nomount.h"
    NMVER=""
    if [ -f "$NM_HDR" ]; then
      NMVER="$(sed -n 's/^#define[[:space:]]\+NM_MODULE_VERSION[[:space:]]\+"\([^"]*\)".*/\1/p' "$NM_HDR" | head -n1)"
    fi
    echo "NMVER=${NMVER:-unknown}" >> "$GITHUB_ENV"
    echo "NoMount version: ${NMVER:-unknown}"
    ;;
hook)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KERNEL_VER KSU_FOLDER
    echo "::group::Apply SELinux oracle (_hook) patches"
    HOOK="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_hook"
    KV="${KERNEL_VER}"
    dos2unix "$HOOK"/*.patch 2>/dev/null || true
    apply_or_die() {
      local p="$1"
      if patch -p1 --forward --dry-run < "$p" >/dev/null 2>&1; then
        patch -p1 --forward < "$p"
      elif patch -p1 --reverse --dry-run < "$p" >/dev/null 2>&1; then
        echo "already applied: $(basename "$p")"
      else
        echo "::error::oracle patch neither applied nor already present: $(basename "$p")"; exit 1
      fi
    }
    case "$KV" in
      6.12)
        REQ_SFS=hide_selinux_selinuxfs_6_12.patch
        REQ_ATTR=hide_selinux_attr_6_12.patch
        ;;
      5.10|5.15|6.1|6.6)
        REQ_SFS=-
        REQ_ATTR=-
        ;;
      *)
        echo "::error::unknown KERNEL_VER='$KV' - refusing to guess which _hook variant is required"; exit 1
        ;;
    esac
    require_variant() {
      local want="$1" got="$2"
      if [ "$want" = "-" ] || [ "$want" = "$got" ]; then
        return 0
      fi
      echo "::error::_hook variant downgrade on KERNEL_VER=$KV: '$want' is required on this kernel but did not apply, and '$got' did."
      echo "::error::These variants do not carry the same hunks, so falling back would silently drop SELinux oracle coverage (e.g. the selinux_inode_setxattr guard). Refit '$want' to this tree instead of falling back."
      exit 1
    }
    apply_first_of() {
      local want="$1"; shift
      local p sel
      for p in "$@"; do
        if patch -p1 --forward --dry-run < "$p" >/dev/null 2>&1; then
          sel="$(basename "$p")"
          require_variant "$want" "$sel"
          patch -p1 --forward < "$p"; echo "selected ($KV): $sel"; return 0
        elif patch -p1 --reverse --dry-run < "$p" >/dev/null 2>&1; then
          sel="$(basename "$p")"
          require_variant "$want" "$sel"
          echo "already applied ($KV): $sel"; return 0
        fi
      done
      echo "::error::no variant applied for: $*"; exit 1
    }
    cd "$COMMON_KERNEL_FOLDER"
    apply_first_of "$REQ_SFS" "$HOOK/hide_selinux_selinuxfs_6_12.patch" "$HOOK/hide_selinux_selinuxfs.patch"
    apply_first_of "$REQ_ATTR" "$HOOK/hide_selinux_attr_6_12.patch" "$HOOK/hide_selinux_attr.patch"
    apply_first_of - "$HOOK/quiet_selinux_audit.patch" "$HOOK/quiet_selinux_audit_legacy.patch"
    apply_or_die "$HOOK/quiet_selinux_audit_user.patch"
    cd "$KSU_FOLDER"
    apply_or_die "$HOOK/fix_selinux_seqno.patch"
    echo "SELinux oracle patches applied"
    echo "::endgroup::"
    ;;
pathhide)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KERNEL_VER
    echo "::group::Apply pathhide (maps/fd cloak)"
    PH="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_pathhide"
    KV="${KERNEL_VER}"
    cd "$COMMON_KERNEL_FOLDER"
    rm -f fs/pathhide.c fs/pathhide.h
    cp "$PH/pathhide.c" fs/pathhide.c
    cp "$PH/pathhide.h" fs/pathhide.h
    dos2unix fs/pathhide.c fs/pathhide.h 2>/dev/null || true
    dos2unix "$PH"/*.patch 2>/dev/null || true
    apply_or_die() {
      local p="$1"
      if [ ! -f "$p" ]; then
        echo "::error::missing pathhide patch: $(basename "$p")"; exit 1
      fi
      if patch -p1 --forward --dry-run < "$p" >/dev/null 2>&1; then
        patch -p1 --forward < "$p"
      elif patch -p1 --reverse --dry-run < "$p" >/dev/null 2>&1; then
        echo "already applied: $(basename "$p")"
      else
        echo "::error::pathhide patch neither applied nor already present: $(basename "$p")"; exit 1
      fi
    }
    apply_or_die "$PH/pathhide_${KV}_integration.patch"
    apply_or_die "$PH/pathhide_mapfiles_${KV}_integration.patch"
    grep -q 'obj-y += pathhide.o' fs/Makefile || echo 'obj-y += pathhide.o' >> fs/Makefile
    grep -q 'pathhide' fs/Makefile || { echo "::error::pathhide.o not wired into fs/Makefile"; exit 1; }
    echo "pathhide applied"
    echo "::endgroup::"
    ;;
ghost)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KERNEL_VER
    echo "::group::Apply _ghost (O_PATH / *xattr / link / ENOTDIR existence cloak)"
    GH="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_ghost"
    KV="${KERNEL_VER}"
    cd "$COMMON_KERNEL_FOLDER"
    rm -f fs/proc/ghost.c fs/proc/ghost.h
    cp "$GH/ghost.c" fs/proc/ghost.c
    cp "$GH/ghost.h" fs/proc/ghost.h
    dos2unix fs/proc/ghost.c fs/proc/ghost.h 2>/dev/null || true
    dos2unix "$GH"/*.patch 2>/dev/null || true
    apply_or_die() {
      local p="$1"
      if [ ! -f "$p" ]; then
        echo "::error::missing _ghost patch: $(basename "$p")"; exit 1
      fi
      if patch -p1 -F0 --forward --dry-run < "$p" >/dev/null 2>&1; then
        patch -p1 -F0 --forward < "$p"
      elif patch -p1 -F0 --reverse --dry-run < "$p" >/dev/null 2>&1; then
        echo "already applied: $(basename "$p")"
      else
        echo "::error::_ghost patch neither applied nor already present: $(basename "$p")"; exit 1
      fi
    }
    require_variant() {
      local want="$1" got="$2"
      if [ "$want" = "-" ] || [ "$want" = "$got" ]; then
        return 0
      fi
      echo "::error::_ghost variant mismatch on KERNEL_VER=$KV: '$want' is required on this kernel but did not apply, and '$got' did."
      echo "::error::The variants do not target the same function shapes, so falling back can place a -ENOENT guard in the wrong wrapper. Refit '$want' to this tree instead of falling back."
      exit 1
    }
    apply_first_of() {
      local want="$1"; shift
      local p sel
      for p in "$@"; do
        if patch -p1 -F0 --forward --dry-run < "$p" >/dev/null 2>&1; then
          sel="$(basename "$p")"
          require_variant "$want" "$sel"
          patch -p1 -F0 --forward < "$p"; echo "selected ($KV): $sel"; return 0
        elif patch -p1 -F0 --reverse --dry-run < "$p" >/dev/null 2>&1; then
          sel="$(basename "$p")"
          require_variant "$want" "$sel"
          echo "already applied ($KV): $sel"; return 0
        fi
      done
      echo "::error::no _ghost variant applied for: $*"; exit 1
    }
    case "$KV" in
      6.12|6.6)
        REQ_XATTR=ghost_xattr_6_12.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod.patch
        ;;
      6.1|5.15)
        REQ_XATTR=ghost_xattr_5_15.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        ;;
      5.10)
        REQ_XATTR=ghost_xattr.patch
        REQ_LINKAT=ghost_linkat.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        ;;
      *)
        echo "::error::unknown KERNEL_VER='$KV' - refusing to guess which _ghost variant is required"; exit 1
        ;;
    esac
    apply_first_of ghost_o_path.patch "$GH/ghost_o_path.patch" "$GH/ghost_o_path_legacy.patch"
    apply_first_of "$REQ_XATTR" "$GH/ghost_xattr_6_12.patch" "$GH/ghost_xattr_6_6.patch" "$GH/ghost_xattr_5_15.patch" "$GH/ghost_xattr.patch"
    apply_first_of "$REQ_LINKAT" "$GH/ghost_linkat_5_15.patch" "$GH/ghost_linkat.patch"
    apply_first_of ghost_notdir.patch "$GH/ghost_notdir.patch" "$GH/ghost_notdir_5_10.patch"
    apply_or_die "$GH/ghost_truncate.patch"
    apply_or_die "$GH/ghost_utimes.patch"
    apply_first_of "$REQ_CHMOD" "$GH/ghost_chmod.patch" "$GH/ghost_chmod_5_10.patch"
    apply_or_die "$GH/ghost_create.patch"
    apply_or_die "$GH/ghost_build_integration.patch"
    grep -q 'ghost.o' fs/proc/Makefile || { echo "::error::ghost.o not wired into fs/proc/Makefile"; exit 1; }
    grep -q 'ghost_hidden_path' fs/namei.c || { echo "::error::_ghost: fs/namei.c guards missing"; exit 1; }
    grep -q 'ghost_hidden_path' fs/xattr.c || { echo "::error::_ghost: fs/xattr.c guards missing"; exit 1; }
    grep -q 'err2 && ghost_hidden_path' fs/namei.c || { echo "::error::_ghost: filename_create guard missing"; exit 1; }
    if awk '/^int do_renameat2/,/^}/' fs/namei.c | grep -q 'ghost_hidden_path'; then
      echo "::error::_ghost: create guard landed in do_renameat2"; exit 1
    fi
    if grep -q 'proc_create' fs/proc/ghost.c; then
      echo "::error::_ghost: ghost.c owns a /proc node - that is a detection surface in its own right"; exit 1
    fi
    echo "_ghost applied for ${KV} - not optional; boot-verified on 6.12, 6.1 and 5.15"
    echo "::endgroup::"
    ;;
*)
    usage
    ;;
esac
