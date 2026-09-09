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
# NO SILENT NO-OP, AND NO CREDIT FOR SOMEONE ELSE'S FIX. A KernelSU-Next that
# does not contain the defect is reported and skipped. A KernelSU-Next whose
# wrappers no longer have the shape this rewrites FAILS the build rather than
# passing an unpatched tree through -- unless upstream's CONFIG_ANDROID bypass
# (1b2316be) is in the tree, in which case the code is not compiled on Android,
# the assertions are downgraded to a skip, and the closing line says the bypass
# is what is protecting the build. See the bypass block below.
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
KSUH="$KSU_FOLDER/kernel/include/ksu.h"

echo "::group::KSU CFI symbol-call fix"
note "tree: $KSU_FOLDER"

[ -f "$SRC" ] || die "$SRC not found -- the KernelSU-Next layout changed; this fix needs re-targeting."

# Upstream's own fix, KernelSU-Next 1b2316be ("kernel: selinux: Bypass dynamic
# wrappers conditionally"): under CONFIG_ANDROID the wrappers become
# `#define ksu_security_* security_*` and the whole dynamic block moves into the
# `#else`. Every kernel these builders produce is CONFIG_ANDROID=y -- measured on
# the OP11 5.15.180 Image, where `ksu_security_secctx_to_secid` is present as a
# SYMBOL in the bootlooping 33264 build and absent in 33267.
#
# So when the bypass is in the tree, the edits below land in a preprocessor arm
# the compiler discards, and this script MUST NOT report that it made an Android
# build CFI-safe: upstream did. They are still applied, because they are the fix
# for the non-Android arm that survives, and because they are the guard if
# upstream ever drops the bypass -- but the shape assertions stop being fatal.
# Dead code must never be able to fail a build.
bypass=0
if grep -q '^#define ksu_security_secid_to_secctx security_secid_to_secctx' "$SRC" 2>/dev/null ||
   grep -q '^#define ksu_security_secctx_to_secid security_secctx_to_secid' "$KSUH" 2>/dev/null; then
    bypass=1
    note "upstream CONFIG_ANDROID bypass present (KernelSU-Next 1b2316be)"
    note "-> on an Android build the dynamic wrappers are NOT compiled and the"
    note "   edits below change nothing. Applying them for the non-Android arm."
fi

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
refuse() {
    if [ "$bypass" -eq 1 ]; then
        note "SKIPPING: $*"
        note "Not fatal: the bypass means this code is not compiled on Android."
        echo "::endgroup::"
        exit 0
    fi
    die "$*"
}

if [ "$raw_before" -gt 0 ]; then
    shaped=$(grep -c '(void \*)find_kernel_symbol_exact("' "$SRC" || true)
    [ "$shaped" -eq "$raw_before" ] || \
        refuse "selinux.c has $raw_before find_kernel_symbol_exact() calls but only $shaped in the expected '(void *)find_kernel_symbol_exact(\"...\")' form. Upstream changed shape -- re-check this fix before shipping."

    [ -f "$HDR" ] || refuse "$HDR not found, but selinux.c still calls find_kernel_symbol_exact()"
    grep -q 'ksu_resolve_symbol_for_functable_hook' "$HDR" || \
        refuse "ksu_resolve_symbol_for_functable_hook() is not declared in $HDR -- cannot swap to a helper that does not exist."
fi

# Definitions we must annotate. Both the >= 6.14 and the < 6.14 arms are present
# in the file textually, whichever one the preprocessor keeps.
defs_re='^(static )?(int|void) (ksu_security_(secctx_to_secid|secid_to_secctx|release_secctx))\('
defs=$(grep -cE "$defs_re" "$SRC" || true)
# A re-run finds them already annotated, which is success, not absence.
nocfi_pre=$(grep -cE '^(static )?(int|void) __nocfi ksu_security_' "$SRC" || true)
[ $((defs + nocfi_pre)) -gt 0 ] || \
    refuse "no ksu_security_* wrapper definitions found in selinux.c -- upstream renamed them; re-check this fix."

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
if [ "$bypass" -eq 1 ]; then
    echo "✅ upstream bypass in force -- Android builds never compile these wrappers;"
    echo "   the edits above harden the non-Android arm only"
else
    echo "✅ KSU SELinux helpers are CFI-safe"
fi
echo "::endgroup::"
