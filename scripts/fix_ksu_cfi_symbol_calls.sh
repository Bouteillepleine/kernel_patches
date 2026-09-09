#!/usr/bin/env bash
#
# Make KernelSU-Next's runtime-resolved SELinux helpers callable under legacy
# Clang CFI. Without this, every kernel below 6.1 panics during init.
#
# WHAT BROKE. KernelSU-Next commit 8b9d7a7a ("kernel: Support out-of-tree builds
# against generic Linux") stopped calling security_secctx_to_secid(),
# security_secid_to_secctx() and security_release_secctx() directly and started
# resolving them at runtime:
#
#     real_func = (void *)find_kernel_symbol_exact("security_secctx_to_secid");
#     ...
#     return real_func(secdata, seclen, secid);
#
# find_kernel_symbol_exact() returns the address kallsyms reports, which is the
# REAL function address. Under legacy Clang CFI (CONFIG_CFI_CLANG on < 6.1) the
# compiler rewrites every address-taken function to its `.cfi_jt` jump-table
# entry, and an indirect call to anything that is not a jump-table entry of the
# expected type traps: __cfi_slowpath -> cfi_check_fail -> panic. cache_sid()
# runs from init, so the panic is a bootloop with nothing on screen.
#
# KernelSU-Next already knows this. ksu_resolve_symbol_for_functable_hook()
# looks up "<name>.cfi_jt" FIRST under `#if !USE_KCFI`, and
# resolve_symbol_variant() is marked __nocfi. The three wrappers 8b9d7a7a added
# use neither.
#
# From 6.1 up, USE_KCFI and HAVE_ON_EACH_MATCH_SYMBOL are both set, the code
# takes a different path entirely, and nothing here changes behaviour -- which
# is why 6.1/6.6/6.12 boot on the same KernelSU-Next and 5.10/5.15 do not.
#
# THE FIX IS TWO EDITS, AND __nocfi IS THE LOAD-BEARING ONE.
#
#   1. __nocfi on the wrapper DEFINITIONS. This is what actually guarantees the
#      call. A `.cfi_jt` entry only exists for a function whose address is taken
#      somewhere in the kernel; security_secctx_to_secid() is only ever called
#      directly, so it may have no jump-table entry at all, and then NO resolver
#      can return a CFI-valid pointer for it. Suppressing the check in the
#      caller is the only thing that works in that case, and it is exactly what
#      resolve_symbol_variant() already does for the same reason.
#
#   2. ksu_resolve_symbol_for_functable_hook() instead of
#      find_kernel_symbol_exact(). Correctness polish: where a `.cfi_jt` entry
#      DOES exist this hands back the pointer the kernel itself would have used.
#      Behaviour-identical on >= 6.1, where that helper tries
#      find_kernel_symbol_exact() first anyway.
#
# Both edits are no-ops when CONFIG_CFI_CLANG is off.
#
# SCOPE. Only kernel/selinux/selinux.c. app_profile.c, lsm_hook.c,
# syscall_hook.c and selinux_hide.c also call find_kernel_symbol_exact(), but
# they predate 8b9d7a7a and the bisect cleared them: OP11 boots on 2482c569 and
# bootloops on 8b9d7a7a with everything else held constant.
#
# NO SILENT NO-OP. A KernelSU-Next that does not contain the defect is reported
# and skipped; a KernelSU-Next whose wrappers no longer have the shape this
# rewrites FAILS the build rather than passing an unpatched tree through.
#
# ENV CONTRACT:
#   KSU_FOLDER   KernelSU-Next tree (the dir holding kernel/)   [required]
#
# Usage: fix_ksu_cfi_symbol_calls.sh
set -euo pipefail

die() { echo "::error::$*" >&2; exit 1; }
note() { echo "  $*"; }

: "${KSU_FOLDER:?KSU_FOLDER is not set (KernelSU-Next tree)}"
[ -d "$KSU_FOLDER" ] || die "KSU_FOLDER='$KSU_FOLDER' is not a directory"

SRC="$KSU_FOLDER/kernel/selinux/selinux.c"
HDR="$KSU_FOLDER/kernel/infra/symbol_resolver.h"

echo "::group::KSU CFI symbol-call fix"
note "tree: $KSU_FOLDER"

[ -f "$SRC" ] || die "$SRC not found -- the KernelSU-Next layout changed; this fix needs re-targeting."

raw_before=$(grep -c 'find_kernel_symbol_exact(' "$SRC" || true)

if [ "$raw_before" -eq 0 ]; then
    if grep -q 'ksu_resolve_symbol_for_functable_hook(' "$SRC"; then
        note "already resolver-safe (no raw find_kernel_symbol_exact calls left)"
    else
        note "this KernelSU-Next predates 8b9d7a7a -- selinux.c calls the SELinux"
        note "helpers directly and there is nothing to fix. Skipping."
        echo "::endgroup::"
        exit 0
    fi
fi

# Every raw call must be the pointer-assignment shape we know how to rewrite.
# If upstream grows a use that is NOT assigned to a function pointer, a blind
# swap could change a value's type, so refuse instead.
if [ "$raw_before" -gt 0 ]; then
    shaped=$(grep -c '(void \*)find_kernel_symbol_exact("' "$SRC" || true)
    [ "$shaped" -eq "$raw_before" ] || \
        die "selinux.c has $raw_before find_kernel_symbol_exact() calls but only $shaped in the expected '(void *)find_kernel_symbol_exact(\"...\")' form. Upstream changed shape -- re-check this fix before shipping."

    [ -f "$HDR" ] || die "$HDR not found, but selinux.c still calls find_kernel_symbol_exact()"
    grep -q 'ksu_resolve_symbol_for_functable_hook' "$HDR" || \
        die "ksu_resolve_symbol_for_functable_hook() is not declared in $HDR -- cannot swap to a helper that does not exist."
fi

# Definitions we must annotate. Both the >= 6.14 and the < 6.14 arms are present
# in the file textually, whichever one the preprocessor keeps.
defs_re='^(static )?(int|void) (ksu_security_(secctx_to_secid|secid_to_secctx|release_secctx))\('
defs=$(grep -cE "$defs_re" "$SRC" || true)
# A re-run finds them already annotated, which is success, not absence.
nocfi_pre=$(grep -cE '^(static )?(int|void) __nocfi ksu_security_' "$SRC" || true)
[ $((defs + nocfi_pre)) -gt 0 ] || \
    die "no ksu_security_* wrapper definitions found in selinux.c -- upstream renamed them; re-check this fix."

# __nocfi comes from <linux/compiler.h>; it expands to nothing without
# CONFIG_CFI_CLANG. Include it explicitly rather than relying on a transitive
# include that could go away.
if ! grep -q 'linux/compiler.h' "$SRC"; then
    sed -i '0,\|#include "linux/version.h"|s||#include "linux/version.h"\n#include <linux/compiler.h>|' "$SRC"
    grep -q 'linux/compiler.h' "$SRC" || die "could not add #include <linux/compiler.h> to selinux.c"
    note "added #include <linux/compiler.h>"
fi

sed -i 's|(void \*)find_kernel_symbol_exact("|(void *)ksu_resolve_symbol_for_functable_hook("|g' "$SRC"
# '#' as the delimiter: $defs_re carries '|' alternations of its own.
sed -i -E "s#$defs_re#\1\2 __nocfi \3(#" "$SRC"

# ---- verify -------------------------------------------------------------
raw_after=$(grep -c 'find_kernel_symbol_exact(' "$SRC" || true)
[ "$raw_after" -eq 0 ] || \
    die "$raw_after raw find_kernel_symbol_exact() call(s) still in selinux.c after the rewrite"

swapped=$(grep -c 'ksu_resolve_symbol_for_functable_hook("' "$SRC" || true)
[ "$swapped" -ge "$raw_before" ] || \
    die "expected at least $raw_before resolver call(s) after the rewrite, found $swapped"

nocfi=$(grep -cE '^(static )?(int|void) __nocfi ksu_security_' "$SRC" || true)
[ "$nocfi" -eq $((defs + nocfi_pre)) ] || \
    die "expected __nocfi on $((defs + nocfi_pre)) ksu_security_* definition(s), found $nocfi"

left=$(grep -cE "$defs_re" "$SRC" || true)
[ "$left" -eq 0 ] || die "$left ksu_security_* definition(s) left without __nocfi"

note "selinux.c now: $swapped resolver call(s), $nocfi __nocfi wrapper definition(s)"
echo "✅ KSU SELinux helpers are CFI-safe"
echo "::endgroup::"
