#!/usr/bin/env bash
#
# Drop kernel-side EXPORT_SYMBOL lines that a first-stage vendor module already
# owns. ONE copy, called by every builder -- same reasoning as
# apply_nomount_stack.sh.
#
# WHY THIS EXISTS. OnePlus' b_16.0.0 branches export symbols from the kernel
# that their own first-stage modules also export. The module is then refused for
# a duplicate export, every other module that resolves the symbol gets the
# kernel's CRC instead of the module's, and first stage init fails: the device
# bootloops before it ever reaches userspace. Production OTA kernels do not
# export these, so a kernel built from published source is the odd one out.
#
#   test_task_ux   block/blk-mq.c, added in the b_16.0.0 sync, owned by
#                  oplus_bsp_sched_assist.ko (sched_assist/sa_common.c). Breaks
#                  sched-walt.ko, oplus_bsp_schedinfo.ko, oplus_bsp_eas_opt.ko
#                  and oplus_bsp_qos_sched.ko on the CRC mismatch. f2fs calls it
#                  built-in, so nothing in-tree needs the export.
#                  OnePlusOSS/android_kernel_common_oneplus_sm8650#42
#
# WHAT IT DOES NOT DO. It never removes an export the modules do not also carry.
# Who owns a symbol is a fact about the synced trees, not an assumption, and
# both trees are right here: a manifest puts the kernel at
# kernel_platform/common and the modules at the config root. So:
#
#   kernel exports + module exports -> drop the kernel's, this is the bug
#   kernel exports, module does not -> leave it, the kernel owns the symbol
#   module exports, kernel does not -> already correct, nothing to do
#
# which also means this retires itself the day OnePlus drops the line, and does
# not fire on a tree where ownership has legitimately moved into the kernel.

set -euo pipefail

die() { echo "::error::fix_oplus_duplicate_exports: $*"; exit 1; }
note() { echo "   $*"; }

[ -n "${COMMON_KERNEL_FOLDER:-}" ] || die "COMMON_KERNEL_FOLDER is not set"
[ -d "$COMMON_KERNEL_FOLDER/block" ] || die "COMMON_KERNEL_FOLDER=$COMMON_KERNEL_FOLDER is not a kernel tree"

# The modules repo is checked out at the manifest root, which is the config
# folder; fall back to one level above kernel_platform when the caller has not
# exported it.
MODULES_ROOT="${CONFIG_FOLDER:-}"
if [ -z "$MODULES_ROOT" ] || [ ! -d "$MODULES_ROOT" ]; then
    MODULES_ROOT="$(cd "$COMMON_KERNEL_FOLDER/../.." && pwd)"
fi

# symbol|kernel file, relative to the common tree|where the module defines it
DUPLICATES=(
    'test_task_ux|block/blk-mq.c|vendor/oplus/kernel/cpu/sched/sched_assist/sa_common.c'
)

module_exports() { # module_exports <symbol> <hint path>
    local sym="$1" hint="$2"
    if [ -f "$MODULES_ROOT/$hint" ] \
       && grep -qE "EXPORT_SYMBOL(_GPL)?\($sym\)" "$MODULES_ROOT/$hint"; then
        echo "$hint"
        return 0
    fi
    # The vendor layout moves between releases, so fall back to a bounded search
    # rather than concluding the module does not own the symbol.
    local hit
    hit="$(grep -rlE "EXPORT_SYMBOL(_GPL)?\($sym\)" \
            "$MODULES_ROOT/vendor/oplus/kernel" 2>/dev/null | head -n1 || true)"
    [ -n "$hit" ] || return 1
    echo "${hit#"$MODULES_ROOT/"}"
}

echo "::group::Fix OPlus duplicate exports"
note "kernel:  $COMMON_KERNEL_FOLDER"
note "modules: $MODULES_ROOT"

dropped=0 left=0
for entry in "${DUPLICATES[@]}"; do
    IFS='|' read -r sym kfile hint <<< "$entry"
    target="$COMMON_KERNEL_FOLDER/$kfile"
    line="EXPORT_SYMBOL_GPL($sym);"

    if [ ! -f "$target" ]; then
        note "$sym: no $kfile in this tree, nothing to do"
        continue
    fi
    if ! grep -qxF "$line" "$target"; then
        note "$sym: $kfile does not export it, nothing to do"
        continue
    fi

    owner="$(module_exports "$sym" "$hint" || true)"
    if [ -z "$owner" ]; then
        note "$sym: exported by $kfile and by no module here -- the kernel owns it, left alone"
        left=$((left + 1))
        continue
    fi

    sed -i "/^EXPORT_SYMBOL_GPL($sym);$/d" "$target"
    grep -qxF "$line" "$target" && die "could not drop $line from $kfile"
    note "$sym: dropped the export from $kfile, $owner owns it"
    dropped=$((dropped + 1))
done

note "$dropped duplicate export(s) dropped, $left left with the kernel"
echo "::endgroup::"
