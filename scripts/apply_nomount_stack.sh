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
# EVERY family is applied at fuzz 0 -- including the hookless engine patch, which
# used to be the one exemption and is now a loudly-annotated fallback. A hunk
# that only lands "with fuzz" can put a guard in the wrong function silently:
# three of the four path_*xattr() bodies are character-identical below `retry:`,
# and hide_selinux_attr.patch used to go in at fuzz 2 against ONE line of
# trailing context, i.e. placed by line number.
# `-F0` is not the same as "no offset" -- offsets are fine and expected.
#
# AND FUZZ 0 IS NOT ENOUGH ON ITS OWN. It proves a hunk matches SOMEWHERE, not
# that it matches in one place. ghost_notdir.patch's pre-image occurred twice in
# fs/namei.c -- path_lookupat() and path_parentat() end with the same five lines
# -- so `patch` resolved it by proximity to the @@ line number, which is pinned
# to 6.12, and the guard landed in path_parentat() on 5.10/5.15/6.1/6.6 for four
# kernel versions with every check here green. That is why verify_* now asserts
# the FUNCTION each guard is in, by name, and not merely that the file mentions
# it.
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
    echo "usage: $0 <all|hookless|record-version|hook|seqno|postsusfs|pathhide|ghost|assert-config>" >&2
    echo "       $0 seqno-form <KernelSU tree>   (prints zero|upstream|split:N|none|missing)" >&2
    echo "       $0 setprocattr-form <KernelSU tree>   (prints '<form> <relpath> <patch>', or 'none')" >&2
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
# CRLF in a patch does not match an LF kernel source, and `patch -F0` reports
# that as "does not apply" rather than as a line-ending problem. dos2unix is not
# installed on every runner, so check for it ONCE and say what is missing rather
# than letting three families fail with the wrong diagnosis. .gitattributes now
# pins these files to LF, so this is a backstop for a checkout made before that
# landed -- not the primary defence it used to be.
normalise() {
    if command -v dos2unix >/dev/null 2>&1; then
        dos2unix "$@" >/dev/null 2>&1 || true
    else
        local f
        for f in "$@"; do
            [ -f "$f" ] || continue
            # A two-character backslash-r in the printf FORMAT, never a literal CR byte
            # in this file: a bare CR here would be invisible to review, and
            # `.gitattributes eol=lf` does not strip a CR that is not part of
            # a CRLF, so an editor that trims one would silently turn this
            # check into `grep ""` -- which matches every file.
            if grep -qU "$(printf '\r')" "$f" 2>/dev/null; then
                die "$f has CRLF line endings and dos2unix is not installed. It will not apply at -F0, and patch will blame the kernel tree rather than the line endings. Install dos2unix, or re-checkout with the repo's .gitattributes in effect."
            fi
        done
    fi
}

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

# apply_optional <patch> -- hardening that is allowed not to fit.
#
# The guards that close a detection oracle are anchored on code that moves
# between kernel versions, and writing a variant per tree is only worth it where
# the oracle is reachable. A tree the hunk does not fit still builds; it just
# builds without that guard, and says so.
apply_optional() {
    local p="$1" root="${2:-$COMMON_KERNEL_FOLDER}"
    [ -f "$p" ] || die "missing patch: $p"
    if patch -p1 -F0 --forward --dry-run -d "$root" <"$p" >/dev/null 2>&1; then
        patch -p1 -F0 --forward -d "$root" <"$p" >/dev/null
        echo "  applied: $(basename "$p")"
    elif patch -p1 -F0 --reverse --dry-run -d "$root" <"$p" >/dev/null 2>&1; then
        echo "  already applied: $(basename "$p")"
    else
        echo "  skipped: $(basename "$p") does not fit $KERNEL_VER"
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

# Which shape KernelSU's own kernel/selinux/rules.c is in. The one _hook patch
# that lives in the KSU tree rather than the kernel's turns on this, and the
# answer differs per fork and per week, so read the tree and never the fork name.
#
#   zero     reset_avc_cache() passes a literal 0 to avc_ss_reset(),
#            selnl_notify_policyload() and selinux_status_update_policyload().
#            That 0 reaches /sys/fs/selinux/status as policyload=0, which is the
#            tell fix_selinux_seqno.patch removes by dropping the status update.
#   upstream tiann/KernelSU#3964 (SukiSU 85d05cf 2026-10-31, KernelSU-Next@dev):
#            reset_avc_cache(u32 seqno) threads the real generation through all
#            three, and BOTH call sites bump pol->latest_granting first. The tell
#            is gone without us, and better -- the status page now carries the
#            true next generation rather than nothing at all.
#   split:N  the #3964 signature with N != 2 call sites bumped. Not a shape to
#            patch around: the unbumped path still writes a stale generation, and
#            which of apply_kernelsu_rules()/handle_sepolicy() is short matters.
ksu_seqno_form() { # ksu_seqno_form <rules.c>
    local f="$1" n
    [ -f "$f" ] || { echo missing; return 0; }
    if grep -qF 'reset_avc_cache(u32 seqno)' "$f"; then
        n="$(grep -cF 'latest_granting = old_pol->latest_granting + 1' "$f")"
        if [ "$n" = 2 ]; then echo upstream; else echo "split:$n"; fi
        return 0
    fi
    if grep -qF 'selinux_status_update_policyload' "$f"; then echo zero; else echo none; fi
}

# Where the seqno decision records itself.
#
# susfs regenerates 10_enable_susfs_for_ksu.patch against official KernelSU and
# REVERTS the generation tracking in kernel/selinux/rules.c: reset_avc_cache(u32
# seqno) goes back to reset_avc_cache(), the calls go back to a literal 0, and
# both pol->latest_granting bumps are deleted. susfs is therefore the last writer
# of that file on a SUSFS build and puts the policyload=0 tell back after _hook
# has run, so _hook defers the decision and the `seqno` step makes it afterwards.
#
# This used to be INFERRED from the tree, by grepping rules.c for the
# susfs_set_batch_sid() call susfs's own hunk adds. That was wrong, and measured
# wrong on 2026-11-01 against KernelSU-Next: susfs's call-site hunks reject on
# that fork's context, so the marker never appears, the probe concluded "susfs has
# not run yet" AFTER it had run, and `verify` reported success with both
# selinux_status_update_policyload() calls still live. A marker that a single
# rejected hunk can delete is not evidence about the step that carried it.
#
# So the state is written down instead, and assert-config refuses to end a build
# that is still 'deferred'. A forgotten seqno step is then an error rather than a
# silent pass, which is the only property that made deferring safe in the first
# place.
seqno_stamp() { printf '%s/.nomount_seqno_state' "${COMMON_KERNEL_FOLDER:-}"; }

seqno_state() {
    local f
    f="$(seqno_stamp)"
    if [ -f "$f" ]; then cat "$f"; else echo none; fi
}

seqno_mark() { # seqno_mark deferred|decided
    [ -n "${COMMON_KERNEL_FOLDER:-}" ] ||
        die "seqno: COMMON_KERNEL_FOLDER is not set, so the '$1' state cannot be recorded -- and an unrecorded deferral is how the policyload=0 tell ships unasserted"
    printf '%s\n' "$1" >"$(seqno_stamp)"
}

# The KernelSU-side setprocattr probe is deferred on SUSFS builds the same way
# fix_selinux_seqno is, and for a sharper reason. SUSFS reduces selinux_hide.c to
# a shell, deleting the very function this probe lives in -- do_postsusfs's own
# comment has said so since 9b0b13f. Applying it first does not merely get
# overwritten: its ~57 lines land INSIDE the span the reduction deletes, so that
# hunk rejects, the reduction never happens, and the callers of helpers the later
# hunks do delete are left behind. That is a kernel that cannot link (vmlinux:
# undefined security_context_to_sid_with_policy / _live, 2026-11-15). Defer, let
# SUSFS have its say about the file, then put the probe where the hook ended up.
setprocattr_stamp() { printf '%s/.nomount_setprocattr_state' "${COMMON_KERNEL_FOLDER:-}"; }

# vfs_statfs() is a slot SUSFS wants too: 50_add_susfs_in_gki inserts its
# sus_kstat and sus_mount arms between `int error;` and the statfs_by_dentry()
# call, which is the same three lines of pre-image the ghost guard takes. Applied
# up front, the guard wins the slot and SUSFS's hunk rejects -- measured, run
# 44303124210, all five trees. So the guard is deferred past SUSFS and placed on
# whichever shape the tree ended up with, ahead of SUSFS's early returns: ghost
# answers "absent", which is the stronger reply and must not be reached through a
# sus_kstat spoof. See do_postsusfs().
statfs_stamp() { printf '%s/.nomount_statfs_state' "${COMMON_KERNEL_FOLDER:-}"; }

statfs_state() {
    local f
    f="$(statfs_stamp)"
    if [ -f "$f" ]; then cat "$f"; else echo none; fi
}

statfs_mark() { # statfs_mark deferred|decided
    [ -n "${COMMON_KERNEL_FOLDER:-}" ] ||
        die "statfs: COMMON_KERNEL_FOLDER is not set, so the '$1' state cannot be recorded -- and an unrecorded deferral is how the statfs(2) oracle ships unasserted"
    printf '%s\n' "$1" >"$(statfs_stamp)"
}


setprocattr_state() {
    local f
    f="$(setprocattr_stamp)"
    if [ -f "$f" ]; then cat "$f"; else echo none; fi
}

setprocattr_mark() { # setprocattr_mark deferred|decided
    [ -n "${COMMON_KERNEL_FOLDER:-}" ] ||
        die "setprocattr: COMMON_KERNEL_FOLDER is not set, so the '$1' state cannot be recorded -- and an unrecorded deferral is how the attr/current timing tell ships unasserted"
    printf '%s\n' "$1" >"$(setprocattr_stamp)"
}

# Where the fork keeps the setprocattr hook. BakaSU 2b558ca (2026-11-22) moved
# kernel/feature/selinux_hide.c into kernel/feature/selinux_hide/ and split it
# three ways, so the filename alone now picks the WRONG half: the new
# selinux_hide.c is the fake_status plumbing and carries no hook at all, while
# the old 1837-line file became selinux_hide_auto.c. Resolve on the hook being
# present, never on the path existing, and keep the candidates in one list so a
# failure can say where it looked. Newest layout last.
KSU_HIDE_CANDIDATES='kernel/feature/selinux_hide.c
kernel/feature/selinux_hide/selinux_hide_auto.c
kernel/feature/selinux_hide/selinux_hide.c'

ksu_selinux_hide_file() {
    local rel f
    while IFS= read -r rel; do
        f="${KSU_FOLDER:-}/$rel"
        [ -f "$f" ] || continue
        grep -qE '__nocfi [a-z_]*setprocattr\(' "$f" || continue
        printf '%s\n' "$f"
        return 0
    done <<<"$KSU_HIDE_CANDIDATES"
    return 1
}

ksu_selinux_hide_tried() {
    printf '%s\n' "$KSU_HIDE_CANDIDATES" | sed "s|^|${KSU_FOLDER:-}/|" | tr '\n' ' '
}

# The hook's own body. Every shape test below reads THIS and not the file:
# KernelSU#3996 added a second hook to the same file that also calls
# security_context_to_sid_live(), so a file-wide grep can be answered by the
# wrong function.
ksu_setprocattr_body() { awk '/__nocfi [a-z_]*setprocattr\(/,/^}/' "$1"; }

# KernelSU#3981 split the parse into a live attempt plus an -EAGAIN fallback, so
# the dual parse this probe compensates for moved one block deeper and the old
# anchor stopped fitting. BakaSU 2b558ca then collapsed it again: the hook calls
# security_context_to_sid_live() with NO -EAGAIN arm, because the fallback moved
# INSIDE that helper, which parses the backup policy once for every payload the
# guard lets through and not at all for the ones it does not. Three shapes, then,
# and all three put the probe on the arm that skips the parse; they differ only in
# the pre-image they are cut against. Probed on the tree rather than on the fork
# name, so a fork pinned to an older hash still builds.
# Which of the three pre-images this hook is in: live | single | base.
#
# Split out of setprocattr_apply so the CI gate that dry-runs this family
# against every fork does not carry its own copy of these greps -- same reason
# ksu_seqno_form exists, and the same contract: read-only, one classifier, one
# answer. Reads the BODY, never the file (see ksu_setprocattr_body).
ksu_setprocattr_form() { # ksu_setprocattr_form <selinux_hide file>
    local body
    body="$(ksu_setprocattr_body "$1")"
    case "$body" in
    *"security_context_to_sid_live"*)
        case "$body" in
        *"error == -EAGAIN"*) echo live ;;
        *) echo single ;;
        esac
        ;;
    *) echo base ;;
    esac
}

# form -> patch basename. Also here rather than in the gate, so a new shape adds
# one arm in one file instead of two that can disagree about which patch a form
# selects.
ksu_setprocattr_patch() { # ksu_setprocattr_patch <form>
    case "$1" in
    live) echo equalise_setprocattr_timing_live.patch ;;
    single) echo equalise_setprocattr_timing_single.patch ;;
    base) echo equalise_setprocattr_timing.patch ;;
    *) return 1 ;;
    esac
}

setprocattr_apply() { # setprocattr_apply <hook dir>
    need KSU_FOLDER
    local f
    f="$(ksu_selinux_hide_file)" ||
        die "setprocattr: no setprocattr hook in any known selinux_hide location, so equalise_setprocattr_timing cannot be placed and writing /proc/self/attr/current still times a backup-policy parse on one payload shape and not the other. Tried: $(ksu_selinux_hide_tried). If the fork moved it again, add the path to KSU_HIDE_CANDIDATES and cut a variant against its shape."
    apply_or_die "$1/$(ksu_setprocattr_patch "$(ksu_setprocattr_form "$f")")" "$KSU_FOLDER"
}

objy() { # objy <makefile> <object> <what>
    # Anchored, and the '.' is escaped: `make fs/proc/ghost.o` builds an object
    # that is not in obj-y at all, so "it compiled" proves nothing about whether
    # it reaches vmlinux. This is the check that does.
    # grep -F on the fixed part, then one anchored -E test with the '.' spelled
    # as a character class. `local esc="${2//./\.}"` did NOT escape anything:
    # bash strips the backslash during quote removal in a pattern substitution,
    # so the '.' kept its regex meaning and `ghostXo` would have satisfied this.
    # Measured -- both ${x//./\.} and ${x//./\.} yield the input unchanged.
    local esc="${2//./[.]}"
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
    # Only assert this when the engine ref actually carries the guard:
    # nomount_ref and patches_ref are chosen independently, so an older engine
    # whose patch has no fs/xattr.c hunk is a legitimate build, not a failure.
    if grep -q 'nm_inode_hidden_from_caller' "$d/fs/nomount.c" 2>/dev/null; then
    # The xattr guard must sit between the LSM permission call and the
    # security.* branch. vfs_getxattr() hands security.* to the LSM there and
    # returns, so a guard placed after it never runs for security.selinux and a
    # hidden app still gets a context back for a file it cannot open. Asserting
    # a function NAME would be wrong: 5.4/5.10 keep this logic in
    # __vfs_getxattr() with vfs_getxattr() a thin wrapper, 6.12 has it in
    # vfs_getxattr(), and a substring test passes on either.
    awk '
      /error = security_inode_getxattr\(dentry, name\)/ { a=NR }
      /XATTR_SECURITY_PREFIX,/                          { if (a && !c) c=NR }
      /nm_inode_hidden_from_caller\(inode\)/            { if (a && !b) b=NR }
      END { exit !(a && b && c && a < b && b < c) }' "$d/fs/xattr.c" ||
        die "_hookless: the fs/xattr.c guard is missing or not between security_inode_getxattr() and the security.* branch -- a hidden app can still read security.selinux on a file it cannot open"
    fi
    grep -qx 'CONFIG_NOMOUNT=y' "$(defconfig_path)" ||
        die "_hookless: CONFIG_NOMOUNT=y is not in $(defconfig_path)"
    assert_config CONFIG_NOMOUNT "the engine is behind CONFIG_NOMOUNT; without it fs/nomount.o is not built at all and every hookless hook is absent"
    echo "_hookless: verified"
}

# Walk security/selinux/hooks.c and fail if a `:ksu:` guard appears in a
# function before that function's own avc_has_perm(). Split out because it needs
# single quotes that do not survive being inlined next to the rest of the checks.
awk_placement() {
    awk '
        /^static (int|noinline int) selinux_[a-z_]+\(/ { fn = $0; avc = 0 }
        /avc_has_perm/                                 { avc = 1 }
        /:ksu:/ { if (!avc) { print "EARLY " fn > "/dev/stderr"; bad = 1 } }
        END { exit bad ? 1 : 0 }
    ' "$1"
}

# Walk KernelSU's selinux_hide.c and fail if the timing-equalisation probe lands
# BEFORE the setprocattr hook's own PROCESS__SETCURRENT check. The probe parses
# an attacker-supplied context against backup_sepolicy; after the check only a
# domain actually allowed SETCURRENT reaches it, which on an Android tree is
# app_zygote and not untrusted_app. Before it, EVERY app could time a
# backup-policy parse -- a wider oracle than the one the patch closes. Same
# shape as awk_placement(), and split out for the same reason: the single
# quotes do not survive being inlined next to the rest of the checks.
awk_probe_placement() {
    awk '
        /__nocfi [a-z_]*setprocattr\(/ { fn = 1; avc = 0 }
        /PROCESS__SETCURRENT/           { if (fn) avc = 1 }
        /ksu_probe_ctx/ { if (fn && !avc) { print "EARLY setprocattr probe" > "/dev/stderr"; bad = 1 } }
        END { exit bad ? 1 : 0 }
    ' "$1"
}

# The compensation has to sit on the arm the detector's payloads actually reach.
# KernelSU#3969 dropped `&& str[0] != '\n'` from the condition above it, which
# moved the newline-prefixed payload out of the `else` and into the parse --
# leaving the probes on a branch nothing reaches. The patch still applied at
# fuzz 0 and every other assertion here still passed; only DuckDetector saw it,
# and only when its app_zygote preload happened to land on a slow core (entry
# CPU 3 on the OP15: +104ns there, 0 or below on 5/6/7). So assert WHERE the
# probe is, not merely that it exists.
awk_probe_failure_arm() {
    awk '
        /__nocfi [a-z_]*setprocattr\(/ { fn = 1; arm = 0 }
        /if \(error2 \|\| error\)/    { if (fn) arm = 1 }
        /^[ \t]*\} else \{/           { arm = 0 }
        /ksu_probe_ctx/ { if (fn && arm) seen = 1 }
        END { exit seen ? 0 : 1 }
    ' "$1"
}

# The abort_creds pair has to sit immediately before the parse-failure return, so
# that the arm which skips the parse is not the only one paying for a cred
# allocation. Asserted on the two lines being ADJACENT, with indentation stripped:
# KernelSU#3981 moved the dual parse one block deeper, and the literal needle this
# replaces pinned the old column count -- a shape change red-lined every target
# while the patch itself had applied correctly.
awk_abort_creds_arm() {
    awk '
        /__nocfi [a-z_]*setprocattr\(/ { fn = 1 }
        fn && /^}/                     { fn = 0 }
        fn {
            gsub(/^[ \t]+/, "")
            if (prev == "abort_creds(new);" && $0 == "return error2 ?: error;") ok = 1
            prev = $0
        }
        END { exit ok ? 0 : 1 }
    ' "$1"
}

# Same assertion on the single-parse shape, where the failure arm returns a bare
# `return error;` because there is no error2 to fold in. Split rather than
# widened: a regex matching either would also pass a tree that lost the dual
# parse without anyone noticing which shape was actually verified.
awk_abort_creds_arm_single() {
    awk '
        /__nocfi [a-z_]*setprocattr\(/ { fn = 1 }
        fn && /^}/                     { fn = 0 }
        fn {
            gsub(/^[ \t]+/, "")
            if (prev == "abort_creds(new);" && $0 == "return error;") ok = 1
            prev = $0
        }
        END { exit ok ? 0 : 1 }
    ' "$1"
}

# The kernel-side twin of the selinux_hide.c probe checks below. susfs 9b0b13f
# moved KernelSU's setprocattr hook into security/selinux/hooks.c as
# susfs_selinux_lsm_setattr(), a copy of the mainline hook that uid>=10000 reaches
# while selinux_hide runs -- and the reduction it applies to selinux_hide.c deletes
# the function the KernelSU-side probe lived in. Fewer checks here because the
# shape is simpler: susfs's copy keeps mainline's SINGLE parse and its
# `str[0] != '\n'` guard, so there is one cheap arm and one expensive one, and the
# cheap one is a plain else. The two checks that encode measurements still apply.
#
# The loop COUNT is not transferable from the KernelSU-side probe: that one was
# calibrated against a dual parse (3 ticks -> 1 with one parse, 0 with two, at
# 52ns a tick). Against a single parse the right count is an open measurement --
# re-read DuckDetector's A/B row on device before trusting it.
verify_hook_probe_susfs() {
    local f="$1" nfs="$2" probe_ctx probe_type probe_range probe_loop needle
    infn "$f" '^static int susfs_selinux_lsm_setattr' 'ksu_probe_ctx' \
        "_hook: the timing probe is not inside susfs_selinux_lsm_setattr(). susfs moved the setprocattr hook kernel-side and deleted KernelSU's copy with it, so without this the newline-prefixed payload skips susfs_security_context_to_sid() while an invalid type pays for it -- the 'App Zygote attr/current timing' DANGER, straight back."
    probe_ctx=$(sed -n 's/.*static const char ksu_probe_ctx\[\] = "\([^"]*\)".*/\1/p' "$f" | head -n1)
    [ -n "$probe_ctx" ] ||
        die "_hook: could not read ksu_probe_ctx out of $f, so the probe string cannot be checked."
    probe_type=$(printf '%s' "$probe_ctx" | cut -d: -f3)
    probe_range=$(printf '%s' "$probe_ctx" | cut -d: -f4)
    needle="\":$probe_type:\""
    case "$nfs" in
    *"$needle"*) ;;
    *) die "_hook: the probe context '$probe_ctx' uses type '$probe_type', which is NOT in the hidden-type list [$nfs]. susfs resolves it through susfs_string_to_context_struct(), which only treats a type as absent while susfs_is_sus_type_rcu() claims it -- a type this cloak does not hide resolves normally and the probe goes cheap." ;;
    esac
    [ -n "$probe_range" ] ||
        die "_hook: the probe context '$probe_ctx' carries no MLS range. The detector's payload does, and the range parse is the larger half of what the policy charges for it."
    probe_loop=$(awk '/^static int susfs_selinux_lsm_setattr/,/^}/' "$f" 2>/dev/null |
        grep -c 'probe_i < [2-9]') || true
    [ "${probe_loop:-0}" -ge 1 ] ||
        die "_hook: the kernel-side timing probe parses the context fewer than twice. If you meant to retune this, change the count -- do not remove the loop."
}

# The _hook selinuxfs cloak used to answer a hidden context with -EINVAL BEFORE
# calling security_context_to_sid(), which skips the parser entirely -- and
# skipping it is measurable from any app. Measured on an OP15 (6.12.69) from
# uid 10500, writing /sys/fs/selinux/context, 9x800 ABBA pairs pinned per core,
# only the write() timed, both payloads asserted to return EINVAL first:
# u:r:ksu:s0 was rejected 208ns faster than SEVEN different 10-byte types that
# are merely absent from policy (zsu/qsu/msu/bsu/abc/xyz/zzz -- same number for
# every one), and u:object_r:ksu_file:s0 312ns faster than its 22-byte controls,
# on 99.9% of pairs, while unknown-against-unknown measured exactly 0ns on four
# different pairs. Duck Detector build 1118 reads it as the "ksu_types timing
# with invalid types" DANGER row.
#
# The fix is poison-input: rewrite the hidden type in place and let the stock
# parser reject it, so a hidden type costs what an unknown type costs. Two
# things this guard exists to stop coming back:
#   * the early return. It is the obvious "simplification" and it is the bug.
#   * moving the test AFTER the parse. Below the uid gate the hidden type is
#     valid and takes the success path, where the same measurement reads
#     +364ns, so that flips the sign instead of closing the gap.
# Both spellings route through sel_ctx_hidden(), so its absence is the check.
verify_selinuxfs_poison() {
    local f="$COMMON_KERNEL_FOLDER/security/selinux/selinuxfs.c" n
    hasnt "$f" 'sel_ctx_hidden' \
        "_hook: selinuxfs.c is back to the sel_ctx_hidden() form. That answers a hidden context without calling security_context_to_sid(), and an app can time the parse it skips -- 208ns on a 10-byte context, 312ns on a 22-byte one, which is the 'ksu_types timing with invalid types' DANGER row. Use sel_poison_ctx() and let the stock parser do the rejecting."
    has "$f" 'sel_poison_ctx' \
        "_hook: selinuxfs.c has no sel_poison_ctx(). Nothing rewrites a hidden type, so either the cloak is gone or it went back to returning -EINVAL early."
    # One call per context argument across the seven write handlers: context 1,
    # validatetrans 3, access 2, create 2, relabel 2, user 1, member 2 = 13,
    # plus the definition line = 14. Partial reverts are the realistic failure
    # and they leave the oracle on whichever node was missed.
    n="$(grep -c 'sel_poison_ctx(' "$f" 2>/dev/null || true)"
    [ "${n:-0}" -ge 14 ] ||
        die "_hook: selinuxfs.c mentions sel_poison_ctx() on only ${n:-0} lines; the definition plus all 13 context arguments is 14. A handler left on the old form still separates a hidden type from an unknown one by its timing."
}

verify_hook() {
    local d="$COMMON_KERNEL_FOLDER"
    has "$d/security/selinux/selinuxfs.c" 'sel_hidden_bytes' "_hook: selinuxfs.c reply filter missing"
    # Runs before the setprocattr branches below, not inside them: those return
    # early on a tree where SUSFS reduced selinux_hide.c to a shell, and these
    # write handlers are a separate entry point that is still standing when they
    # do. An earlier version of this check read KernelSU's selinux_hide.c, which
    # that reduction deletes, so it passed on every SUSFS build while the live
    # code -- these handlers -- carried the oracle.
    verify_selinuxfs_poison
    # The dirty-edge mask lives in security_compute_av_user() in ss/services.c,
    # the only function that has the policy which answered the query. It carries
    # no type name of its own, so the hidden-type cross-check further down cannot
    # see it, and the per-write-node loop only asserts sel_poison_ctx(). Assert
    # it directly: without it /sys/fs/selinux/access tells any app that
    # system_server may execmem on itself -- the DirtySepolicy anomaly this
    # closes -- and nothing else here would notice it had gone.
    local av_user av_user_code av_user_callers
    av_user="$(awk '/^void security_compute_av_user/,/^}/' "$d/security/selinux/ss/services.c" 2>/dev/null || true)"
    av_user_code="$(printf '%s\n' "$av_user" | grep -v '^[[:space:]]*\(/\*\|\*\)' || true)"
    case "$av_user_code" in
    *dirty_edges*) ;;
    *) die "_hook: security_compute_av_user() no longer masks the dirty edges. /sys/fs/selinux/access is back to telling any app that system_server may execmem on itself, which is the DirtySepolicy anomaly this closes." ;;
    esac

    # The whole safety argument is that this mask cannot reach enforcement, and
    # that rests on security_compute_av_user() having exactly ONE caller:
    # sel_write_access(), the /sys/fs/selinux/access reporting node. Unlike
    # security_compute_av() it neither unmaps the class nor calls map_decision(),
    # so clearing a bit there changes only what a caller is told. A second caller
    # turns the same code into a real denial, and nothing else here would catch
    # that.
    av_user_callers=$(grep -rl --include='*.c' 'security_compute_av_user(' "$d/security/selinux" 2>/dev/null | sed "s|^$d/security/selinux/||" | grep -v '^ss/services\.c$' | sort | tr '\n' ' ' || true)
    [ "$av_user_callers" = "selinuxfs.c " ] ||
        die "_hook: security_compute_av_user() is called from [$av_user_callers], not from selinuxfs.c alone. The dirty-edge mask is only safe while this function serves the reporting node and nothing else -- another caller makes it deny real accesses."

    # Match by NAME, never by class index or a generated permission constant.
    # The tclass reaching security_compute_av_user() is the POLICY class index,
    # while SECCLASS_* are generated from classmap.h: on CPH2745 policy file=6
    # against SECCLASS_FILE=7, because the policy has no process2 in third
    # position. A SECCLASS_ comparison therefore masked process and dir by
    # coincidence and silently never fired for file. avd->allowed carries policy
    # permission bits for the same reason, so FILE__*/DIR__*/PROCESS__* are wrong
    # here too. Both failures are invisible: it builds, boots, and hides two of
    # the three edges. Comments are stripped above so the one explaining this
    # trap does not trip it.
    case "$av_user_code" in
    *SECCLASS_* | *FILE__* | *DIR__* | *PROCESS__*)
        die "_hook: security_compute_av_user() compares a kernel classmap.h constant against a POLICY index. Resolve the class, the two types and the permission by name through the policy that answered the query -- see the comment on the mask." ;;
    esac
    has "$d/security/selinux/hooks.c" ':ksu:' "_hook: hooks.c attr guard missing"
    # Per function, not per file: a file-level ':ksu:' grep stayed green for as
    # long as 5.10/5.15/6.1 carried the setprocattr arm alone.
    infn "$d/security/selinux/hooks.c" '^static int selinux_inode_setxattr' ':ksu:'         "_hook: selinux_inode_setxattr() has no hidden-type guard -- setxattr(security.selinux) then tells an unprivileged caller apart 'type not in policy' (-EINVAL) from 'type exists, denied' (-EACCES), which is a probe for the hidden types"
    # 6.12 renamed the process-attr hook; every older tree still has setprocattr.
    case "$KERNEL_VER" in
    6.12)
        infn "$d/security/selinux/hooks.c" '^static int selinux_lsm_setattr' ':ksu:'         "_hook: selinux_lsm_setattr() has no hidden-type guard"
        ;;
    *)
        infn "$d/security/selinux/hooks.c" '^static int selinux_setprocattr' ':ksu:'         "_hook: selinux_setprocattr() has no hidden-type guard"
        ;;
    esac
    has "$d/security/selinux/avc.c" ':ksu:' "_hook: avc.c denial filter missing"
    # The avc filter must stay uid-gated. Ungated it deletes the whole record
    # class, including the uid-1000 servicemanager denial that diagnosed the
    # uid-gate-widening incident in common/_hook/README.md.
    has "$d/security/selinux/avc.c" 'current_uid()' "_hook: avc.c filter has lost its uid gate"
    has "$d/security/selinux/Makefile" 'selinuxfs.o' "_hook: selinuxfs.o is not in security/selinux/Makefile"

    # Every selinuxfs WRITE NODE, by name. "selinuxfs.c contains sel_poison_ctx"
    # is satisfied by the definition alone, so a refit that dropped a handler's
    # call site passed. Three of these handlers (access, relabel, member) have
    # character-identical bodies, which means their hunks have identical
    # pre-images and `patch` resolves them by line number -- they land on the
    # three sites in some order, and this is what asserts that all three ended
    # up with a guard rather than one of them being skipped.
    local w
    for w in sel_write_context sel_write_validatetrans sel_write_access \
             sel_write_create sel_write_relabel sel_write_user sel_write_member; do
        infn "$d/security/selinux/selinuxfs.c" "^static ssize_t $w\(" 'sel_poison_ctx' \
            "_hook: $w() has no sel_poison_ctx() call -- that write node is an open hidden-type probe"
    done

    # The hidden-type list is mirrored in three files; assert they AGREE.
    # common/_hook/README.md says "adding a type means editing all three" and
    # nothing enforced it: the old check was `grep :ksu:` per file, which a
    # two-of-three edit passes. A device on this fleet can rename the ksu
    # domain, so a list that drifts is not hypothetical.
    local nfs nhooks navc
    nfs=$(grep -o '":[a-z_]*:"' "$d/security/selinux/selinuxfs.c" | sort -u | tr '\n' ' ')
    nhooks=$(grep -o '":[a-z_]*:"' "$d/security/selinux/hooks.c" | sort -u | tr '\n' ' ')
    navc=$(grep -o '":[a-z_]*:"' "$d/security/selinux/avc.c" | sort -u | tr '\n' ' ')
    [ -n "$nfs" ] || die "_hook: no hidden-type list found in selinuxfs.c"
    [ "$nfs" = "$nhooks" ] ||
        die "_hook: the hidden-type list differs between selinuxfs.c [$nfs] and hooks.c [$nhooks]. A type covered in one file and not another leaves that probe open, and nothing else would have said so."
    [ "$nfs" = "$navc" ] ||
        die "_hook: the hidden-type list differs between selinuxfs.c [$nfs] and avc.c [$navc]."
    echo "  _hook: type list mirrored in 3 files: $nfs"

    # PLACEMENT. The README records that a guard placed BEFORE the stock avc
    # check "shipped once and made 5.10/5.15/6.1 more detectable than
    # unpatched": every app domain is denied PROCESS__SETCURRENT, so the cloak
    # answered EINVAL-for-hidden and EACCES-for-garbage, which is a
    # discrimination stock cannot make. Assert the ORDER within each function,
    # not merely that the guard is somewhere in the file.
    awk_placement "$d/security/selinux/hooks.c" ||
        die "_hook: a hidden-type guard in hooks.c sits BEFORE the avc_has_perm() of its own function. That inversion turns the cloak into a one-syscall root oracle -- see common/_hook/README.md."

    # fix_selinux_seqno.patch is written against KernelSU's OWN tree: its paths
    # are relative to KSU_FOLDER, not to the kernel root. KSU_FOLDER used to be
    # optional here, so `verify hook` on its own printed "_hook: verified"
    # without ever looking at the one thing that patch does.
    [ -n "${KSU_FOLDER:-}" ] ||
        die "_hook: KSU_FOLDER is not set, so fix_selinux_seqno cannot be verified. Set it -- otherwise the policyload=0 tell goes unchecked and this function reports success anyway."
    [ -f "$KSU_FOLDER/kernel/selinux/rules.c" ] ||
        die "_hook: $KSU_FOLDER/kernel/selinux/rules.c does not exist. If this KernelSU fork keeps rules.c elsewhere, fix_selinux_seqno.patch did not land and /sys/fs/selinux/status still reports policyload=0."
    # Deferred while SUSFS still has rules.c to rewrite -- asserting here would
    # fail a correct build, and asserting nothing would let a tree through that
    # still writes policyload=0. The post-SUSFS verify is unconditional, so a
    # builder that never runs the seqno step fails there rather than silently
    # shipping the tell.
    if [ "$(seqno_state)" = deferred ]; then
        echo "  _hook: fix_selinux_seqno deferred to the seqno step -- assert-config will not let the build end without it"
    else
        verify_seqno
    fi

    # Gated exactly as the apply is, once per implementation. A fork with neither
    # file has nothing to assert; where a file exists its log line must be gone,
    # otherwise the kernel narrates every spoofed denial. The SukiSU side also
    # announces the resolved SIDs at init, so assert on the ksu one separately:
    # it survives even if the per-denial line is dropped.
    if [ -f "$KSU_FOLDER/kernel/extras.c" ]; then
        hasnt "$KSU_FOLDER/kernel/extras.c" 'replacing su_sid' \
            "_hook: quiet_avc_spoof_log did not land -- avc_spoof still prints both SIDs to the kernel log on every spoofed denial, which dmesg_restrict=0 hands to any shell."
    fi
    if [ -f "$KSU_FOLDER/kernel/feature/avc_spoof.c" ]; then
        hasnt "$KSU_FOLDER/kernel/feature/avc_spoof.c" 'replace tsid' \
            "_hook: quiet_avc_spoof_log_sukisu did not land -- SukiSU avc_spoof still logs each spoofed tsid replacement, which dmesg_restrict=0 hands to any shell."
        hasnt "$KSU_FOLDER/kernel/feature/avc_spoof.c" 'ksu SID: %u' \
            "_hook: SukiSU avc_spoof still announces the resolved ksu SID at init, which names the very context the cloak exists to hide."
    fi

    # equalise_setprocattr_timing.patch is also written against KernelSU's own
    # tree. The file is named differently per fork but present in all three
    # (KSUN, SukiSU-Ultra, BakaSU), and the function it patches is my_setprocattr
    # on two of them and ksu_handle_selinux_setprocattr on the third -- hence the
    # name-agnostic assertions below.
    # There are two places the setprocattr hook can live and they are NOT
    # exclusive. susfs has carried a kernel-side copy (susfs_selinux_lsm_setattr
    # in security/selinux/hooks.c) since a3d321a, 2026-11-07; what 9b0b13f added
    # was the setxattr pair and the reduction of selinux_hide.c to a shell. So a
    # current tree usually has BOTH, and an earlier version of this check tested
    # the kernel-side one and returned, silently skipping every KernelSU-side
    # assertion below -- the probe-string shape, the abort_creds adjacency and the
    # placement check -- on a hook that was still present and still patched.
    # Check each one that exists, and require at least one: neither carrying a
    # probe is the state that ships the DANGER row.
    local have_ksu=0 have_susfs=0 hide=
    grep -q 'susfs_selinux_lsm_setattr' "$d/security/selinux/hooks.c" 2>/dev/null && have_susfs=1
    hide="$(ksu_selinux_hide_file)" && have_ksu=1
    # Neither carrying a hook used to be fatal, on the reasoning that an
    # unequalised hook ships the timing tell. But the tell needs a hook to exist:
    # SUSFS's reduction removes KernelSU's, and below android16-6.12 it adds none
    # of its own, so the writes take the stock path and time identically. Say so in
    # the log but NOT as an annotation -- see apply_first_of(): this outcome is
    # correct on every build below android16-6.12. A silently unapplied patch set
    # cannot land here; it would leave the hook PRESENT (have_ksu=1) and take the
    # probe-assertion path below.
    if [ "$have_ksu" = 0 ] && [ "$have_susfs" = 0 ]; then
        echo "_hook: no setprocattr hook in either tree -- SUSFS removed KernelSU's and ships none on this branch, so there is no attr/current asymmetry to equalise"
        assert_config CONFIG_SECURITY_SELINUX "every _hook guard lives in security/selinux/, which is built only under CONFIG_SECURITY_SELINUX -- without it the whole family is dead code"
        echo "_hook: verified (no setprocattr hook to equalise on this tree)"
        return 0
    fi

    [ "$have_susfs" = 0 ] || verify_hook_probe_susfs "$d/security/selinux/hooks.c" "$nfs"

    if [ "$have_ksu" = 0 ]; then
        assert_config CONFIG_SECURITY_SELINUX "every _hook guard lives in security/selinux/, which is built only under CONFIG_SECURITY_SELINUX -- without it the whole family is dead code"
        echo "_hook: verified (setprocattr timing equalised kernel-side only; KernelSU's hook is gone from this tree)"
        return 0
    fi

    # Deferred means SUSFS has not reduced selinux_hide.c yet, so KernelSU's hook
    # is still standing but is NOT the one this build will ship a probe in. The
    # post-SUSFS verify is the one that has to be satisfied, and assert-config
    # refuses to end a build that never got there.
    if [ "$(setprocattr_state)" = deferred ]; then
        assert_config CONFIG_SECURITY_SELINUX "every _hook guard lives in security/selinux/, which is built only under CONFIG_SECURITY_SELINUX -- without it the whole family is dead code"
        echo "_hook: verified (setprocattr timing deferred to the postsusfs step)"
        return 0
    fi

    [ -n "$hide" ] ||
        die "_hook: no setprocattr hook in any known selinux_hide location, so equalise_setprocattr_timing cannot be verified. Tried: $(ksu_selinux_hide_tried). If this fork moved or renamed it, the patch did not land and writing /proc/self/attr/current still times a backup-policy parse on one payload shape and not the other."
    infn "$hide" '__nocfi .*setprocattr' 'ksu_probe_ctx' \
        "_hook: the timing probe is not inside the setprocattr hook. Without it the newline-prefixed payload skips security_context_to_sid_with_policy() while the bare one pays for it, and the difference is measurable from app_zygote -- the DANGER Duck Detector reports as 'App Zygote attr/current timing'."

    # The probe exists to cost what the REAL parse costs, and that cost is not a
    # property of the code -- it is a property of the string. Measured on an
    # OP15 (CPH2745, 6.12.69): the detector's A payload is a hidden-type context
    # with a valid MLS range, so it fails the BACKUP policy's type lookup and
    # then parses all the way through the LIVE policy, range included. The first
    # version of this probe re-parsed the caller's own bytes, which for a
    # same-length newline-prefixed payload is A truncated by one character --
    # 'u:r:ksu:s' instead of 'u:r:ksu:s0' -- so it died in mls_context_to_sid()
    # and never paid for the range. Verified against the live policy from uid 0,
    # where the >=2000 selinuxfs cloak is off: 'u:r:ksu:s0' validates,
    # 'u:r:ksu:s' returns EINVAL. That one missing range parse was the whole
    # residual: 157ns before the probe, still 104ns with the wrong probe string.
    #
    # So assert the SHAPE of the constant, not merely its presence:
    #   * its type must be one the cloak actually hides, or the backup lookup
    #     succeeds, the live parse is skipped, and the probe goes cheap again;
    #   * it must carry an MLS range, or the range parse is never paid for.
    # Both failures are silent -- the kernel builds, boots and hides exactly as
    # well, and only a detector sees the difference.
    probe_ctx=$(sed -n 's/.*static const char ksu_probe_ctx\[\] = "\([^"]*\)".*/\1/p' \
        "$hide" | head -n1)
    [ -n "$probe_ctx" ] ||
        die "_hook: could not read ksu_probe_ctx out of $hide, so the probe string cannot be checked. It is the only thing that makes the two paths cost the same; an unchecked one is how the 104ns residual survived a green build."
    probe_type=$(printf '%s' "$probe_ctx" | cut -d: -f3)
    probe_range=$(printf '%s' "$probe_ctx" | cut -d: -f4)
    needle="\":$probe_type:\""
    case "$nfs" in
    *"$needle"*) ;;
    *) die "_hook: the probe context '$probe_ctx' uses type '$probe_type', which is NOT in the hidden-type list [$nfs]. The probe only costs what the real parse costs while its type is absent from the backup policy and present in the live one -- i.e. while it is a type this cloak hides. Rename the hidden domain without renaming this and the oracle comes straight back, silently." ;;
    esac
    [ -n "$probe_range" ] ||
        die "_hook: the probe context '$probe_ctx' carries no MLS range. The detector's payload does, and the range parse is the larger half of what the live policy charges for it -- without one the probe is cheap and the asymmetry stays measurable."

    # The probe runs more than once ON PURPOSE, and that is a tuning constant,
    # not a correctness one -- so it is the kind of thing a later cleanup
    # "simplifies" away without noticing. CLOCK_MONOTONIC_RAW on this SoC is the
    # 19.2 MHz arch counter, i.e. ONE TICK IS 52ns, and every A-B figure the
    # detector has ever printed here is an exact multiple of it: 157/156 = 3
    # ticks unpatched, 104 = 2, 52 = 1. A single probe parse took the verdict
    # sample from 3 ticks to 1 and then stopped moving, because anything smaller
    # than a tick is invisible to the instrument. Two parses is what pushes the
    # paired median to 0 or below, which is the only state the card treats as
    # clean. Drop back to one and the asymmetry returns at a tick the detector
    # can still see, with nothing else failing.
    probe_loop=$(awk "/__nocfi .*setprocattr/,/^}/" "$hide" 2>/dev/null |
        grep -c 'probe_i < [2-9]') || true
    [ "${probe_loop:-0}" -ge 1 ] ||
        die "_hook: the timing probe parses the context fewer than twice. One parse only moves the paired median by a tick and leaves it positive, which is still 'Positive A-B timing asymmetry' to the detector. If you meant to retune this, change the count -- do not remove the loop."
    # Both of the next two encode the TWO-ARM shape: a probe inside the
    # `if (error2 || error)` fallback, and an abort_creds pair ahead of
    # `return error2 ?: error;`. BakaSU 2b558ca has neither, because the fallback
    # moved inside security_context_to_sid_live() -- one unconditional parse and a
    # bare `return error;`. Assert the shape that is THERE, which is what
    # verify_hook_probe_susfs() already does for susfs's single-parse copy; running
    # the two-arm pair against it would red-line a correctly patched tree.
    case "$(ksu_setprocattr_body "$hide")" in
    *"error == -EAGAIN"*)
        awk_probe_failure_arm "$hide" ||
            die "_hook: the timing probe is only on the else arm of the setprocattr hook. Whatever upstream's condition is now, the newline-prefixed payload reaches the parse and dies in it early while the well-formed one pays for the live type and range lookup -- and nothing charges that back. That is 'Positive A-B timing asymmetry', i.e. a DANGER SELinux card, on any core slow enough to resolve 52ns."
        awk_abort_creds_arm "$hide" ||
            die "_hook: the parse-failure arm still returns before prepare_creds(). The probe alone only moves the asymmetry: the payload that skips the parse would then pay a prepare_creds()/abort_creds() pair the other one does not, and the timing gap comes back with the sign flipped."
        ;;
    *)
        awk_abort_creds_arm_single "$hide" ||
            die "_hook: the parse-failure arm still returns before prepare_creds(). On this single-parse shape the arm is a bare 'if (error) { return error; }' and the probe arm falls through to prepare_creds(), so without the pair the payload that SKIPS the parse is the only one paying for a cred allocation -- the same timing gap with the sign flipped."
        ;;
    esac
    awk_probe_placement "$hide" ||
        die "_hook: the timing probe sits BEFORE the setprocattr hook's PROCESS__SETCURRENT check, so every app can reach a backup-policy parse instead of only the domains allowed SETCURRENT. That is a wider oracle than the one this patch closes."

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
    infn "$d/fs/proc/task_mmu.c" '^static int pagemap_pmd_range' 'pathhide_match_file'         "_pathhide: the pagemap guard is not inside pagemap_pmd_range() -- resident pages sitting at an address maps does not list is the whole gap, stated outright"
    infn "$d/mm/mincore.c" '^static long do_mincore' 'pathhide_match_file'         "_pathhide: the mincore(2) guard is not inside do_mincore(). It has to sit before can_do_mincore(), which answers resident-for-everything by memset for a file the caller cannot write."
    infn "$d/fs/proc/task_mmu.c" '^void task_mem' 'pathhide_hidden_vm_pages'         "_pathhide: the VmSize/VmPeak deduction is not inside task_mem() -- summing the visible maps ranges against VmSize is exact arithmetic, which is what makes it worth closing while RSS is deliberately left alone"
    infn "$d/fs/proc/task_mmu.c" '^unsigned long task_statm' 'pathhide_hidden_vm_pages'         "_pathhide: the statm size deduction is not inside task_statm()"
    # PAGEMAP_SCAN landed in 6.7, so only 6.12 has a second residency window.
    case "$KERNEL_VER" in
    6.12)
        infn "$d/fs/proc/task_mmu.c" '^static int pagemap_scan_test_walk' 'pathhide_match_file'         "_pathhide: the PAGEMAP_SCAN guard is not inside pagemap_scan_test_walk() -- the ioctl is a second residency window onto the same vma"
        ;;
    esac
    # The /proc/<pid>/fd half was removed on purpose: a hidden fd stays
    # allocated, so fcntl(N, F_GETFD) succeeds where /proc/self/fd/N is ENOENT.
    hasnt "$d/fs/proc/fd.c" 'pathhide' \
        "_pathhide: fs/proc/fd.c is patched again. The fd half was removed because a hidden fd stays allocated -- fcntl(N, F_GETFD) succeeds where /proc/self/fd/N answers ENOENT, which is unconditional and never true on stock."
    # No CONFIG symbol by design: a new entry in /proc/config.gz would announce
    # the patch to anything that reads it, which is what this file exists to
    # prevent. obj-y is therefore the whole of the build-side assertion.
    echo "_pathhide: verified (no CONFIG symbol by design -- see README)"
}

# infn <file> <awk-start-regex> <needle> <what>
#
# "the file mentions ghost_hidden_path" is not a coverage check. fs/namei.c is
# touched by FOUR _ghost families and fs/xattr.c by one family with four hunks,
# so a single occurrence satisfied the old assertion even when three of the four
# guards were missing -- and ghost_notdir.patch spent four kernel versions
# landing its guard in path_parentat() instead of path_lookupat(), at fuzz 0,
# with every assertion here green. Assert the FUNCTION, by name.
# NO PIPE INTO grep -q. This script runs under `set -o pipefail`, and `grep -q`
# exits the moment it matches, which closes the pipe and kills awk with SIGPIPE
# -- so the pipeline reports failure precisely when the assertion PASSED, and
# whether it does depends on how much awk had already flushed. Measured: the
# same check passed on 6.6/6.12 and failed on 5.10/5.15/6.1 for no reason but
# output size. Capture, then match.
infn() {
    local seg
    seg="$(awk "/$2/,/^}/" "$1" 2>/dev/null)" || true
    case "$seg" in
    *"$3"*) return 0 ;;
    esac
    die "$4"
}

verify_ghost() {
    local d="$COMMON_KERNEL_FOLDER" n seg f
    [ -f "$d/fs/proc/ghost.c" ] || die "_ghost: fs/proc/ghost.c missing"
    [ -f "$d/fs/proc/ghost.h" ] || die "_ghost: fs/proc/ghost.h missing"
    objy "$d/fs/proc/Makefile" 'ghost.o' "_ghost"

    infn "$d/fs/namei.c" '^static int do_o_path' 'ghost_hidden_path(&path))'         "_ghost: the O_PATH guard is not inside do_o_path()"
    infn "$d/fs/namei.c" '^static int do_open' 'unlikely(ghost_hidden_path(&nd->path))'         "_ghost: the open(2) guard is not inside do_open(). It is unconditional now: any open of a hidden path that did not just create it answers ENOENT, so plain O_RDONLY and O_CREAT agree with O_PATH instead of handing back an fd -- and, with O_TRUNC, emptying the file."
    infn "$d/fs/namei.c" '^static int path_lookupat' 'unlikely(err == -ENOTDIR)'         "_ghost: the ENOTDIR guard is not inside path_lookupat(). It applies at fuzz 0 inside path_parentat() too -- that is the bug ghost_notdir.patch's header documents, and this is the assertion that catches it."
    # BOTH walkers, not one. path_parentat() is the CREATE family's choke point
    # (filename_create -> filename_parentat), and mkdirat(p "/d") was measured on
    # an OP15 answering ENOTDIR for a hidden path where an absent one answers
    # ENOENT -- one syscall, no privilege, open after every other guard closed.
    infn "$d/fs/namei.c" '^static int path_parentat' 'unlikely(err == -ENOTDIR)'         "_ghost: the ENOTDIR guard is not inside path_parentat() -- mkdirat/mknodat/symlinkat/unlinkat/renameat reach -ENOTDIR through there and through nothing else this patch set guards"
    infn "$d/fs/namei.c" '^static struct dentry \*filename_create' 'error = err2 ? err2 : -EACCES'         "_ghost: the create guard is not inside filename_create(), or it went back to masking only on a read-only mount. mkdirat/mknodat/symlinkat/linkat all reach -EEXIST through here before may_create() runs, so a hidden name has to answer what an absent one would: err2 when the mount is read-only, -EACCES otherwise."
    infn "$d/fs/namei.c" '^(static )?int do_linkat' 'ghost_hidden_path(&old_path)'         "_ghost: the link(2) guard is not inside do_linkat()"
    infn "$d/fs/open.c" '^int do_fchownat' 'ghost_hidden_path(&path))'         "_ghost: the chown(2) guard is not inside do_fchownat()"
    infn "$d/fs/stat.c" '^static int do_readlinkat' 'ghost_hidden_path(&path))'         "_ghost: the readlink(2) guard is not inside do_readlinkat() -- it returns the hidden symlink's target where an absent path answers ENOENT"
    infn "$d/fs/open.c" '^static long do_faccessat' 'unlikely(ghost_hidden_path(&path))'         "_ghost: the access(2) guard is not inside do_faccessat(), or it is gated on the mode again. It used to fire only for MAY_WRITE, so access(F_OK) and access(R_OK) reported the hidden path as present while access(W_OK) answered ENOENT -- one syscall, two answers, and only one of them what an absent path gives."
    # The stat family is the plainest existence oracle there is, and it was the
    # one surface with no guard at all: lstat/statx handed back full metadata for
    # a path whose getxattr/listxattr already answered ENOENT. vfs_statx() is the
    # single choke point for stat/lstat/statx/newfstatat on 6.12; the older trees
    # reach it through a differently shaped vfs_statx and still need their own.
    infn "$d/fs/stat.c" '^(static )?int vfs_statx' 'ghost_hidden_path(&path))'         "_ghost: the stat(2) family guard is not inside vfs_statx() -- lstat/statx/newfstatat read the hidden object's real metadata where every other ghost surface answers ENOENT. This is the whole family through one choke point on all five trees; there is no version where it is optional."
    infn "$d/fs/open.c" 'do_fchmodat' 'ghost_hidden_path(&path))'         "_ghost: the chmod(2) guard is not inside do_fchmodat()"
    infn "$d/fs/open.c" '^(long|int) do_sys_truncate' 'ghost_hidden_path(&path))'         "_ghost: the truncate(2) guard is not inside do_sys_truncate()"
    infn "$d/fs/utimes.c" '^(static )?(long|int) do_utimes_path' 'ghost_hidden_path(&path))'         "_ghost: the utimensat(2) guard is not inside do_utimes_path()"
    # All four wrappers or none -- ghost_xattr*.patch's header argues at length
    # that a partial cloak carries every risk and closes nothing, and three of
    # the four bodies are character-identical below `retry:`.
    local w
    for w in path_setxattr path_getxattr path_listxattr path_removexattr; do
        infn "$d/fs/xattr.c" "^static (ssize_t|int) $w\(" 'ghost_hidden_path(&path))'             "_ghost: fs/xattr.c has no guard inside $w() -- the xattr family is all four wrappers or none"
    done
    n=$(grep -c 'ghost_hidden_path' "$d/fs/xattr.c" 2>/dev/null || echo 0)
    [ "$n" -eq 8 ] || die "_ghost: fs/xattr.c has $n ghost_hidden_path references, expected 8 (one extern + one call per wrapper)"

    infn "$d/fs/namei.c" '^int do_renameat2' 'struct path gpath = { .mnt = old_path.mnt, .dentry = old_dentry }'         "_ghost: the rename(2) source guard is not inside do_renameat2() -- a hidden source renames like any other file, which both answers where an absent one says ENOENT and moves the object out of the path that hides it"
    if awk '/^int do_renameat2/,/^}/' "$d/fs/namei.c" | grep -q 'err2'; then
        die "_ghost: the create guard landed in do_renameat2, not filename_create. The rename guard belongs there; the err2/-EACCES one does not."
    fi
    # (There is deliberately no "must NOT be in path_parentat" check any more.
    # There used to be: the first fix for the ambiguous pre-image pinned the
    # guard to path_lookupat() and asserted it was nowhere else. That was half
    # right -- path_parentat() needs one TOO, which is why the assertion above
    # requires it rather than forbidding it.)

    # The abstract-socket guard, in whichever of the two functions this tree has.
    # It is NOT in unix_stream_connect() any more: that site saw SOCK_STREAM only,
    # and the measured leak for @init_monitor's shape is dgram-only, so asserting
    # the old site would pass on a build that closes nothing. Both shapes reach
    # every connect(2) and sendto(2) on an abstract name.
    if grep -q '^static struct sock \*unix_find_abstract' "$d/net/unix/af_unix.c" 2>/dev/null; then
        infn "$d/net/unix/af_unix.c" '^static struct sock \*unix_find_abstract' 'ghost_abstract_hidden(sunaddr->sun_path + 1' \
            "_ghost: the abstract-socket guard is not inside unix_find_abstract() -- a hidden @name still answers, and on 6.1+ that function is the only point both connect(2) and sendto(2) pass through"
    else
        infn "$d/net/unix/af_unix.c" '^static struct sock \*unix_find_other' 'ghost_abstract_hidden(sunname->sun_path + 1' \
            "_ghost: the abstract-socket guard is not inside unix_find_other() -- 5.10/5.15 have no unix_find_abstract(), so the abstract else-arm there is the only choke point"
    fi
    n=$(grep -c 'ghost_abstract_hidden' "$d/net/unix/af_unix.c" 2>/dev/null || echo 0)
    [ "$n" -eq 3 ] || die "_ghost: net/unix/af_unix.c has $n ghost_abstract_hidden references, expected 3 (extern + weak-pointer test + call). Six means two variants landed on one tree."
    # And NOT in the site it was retired from. The count above cannot tell the
    # two apart -- the old hook had the same three references -- so name the
    # function. Capture then match: `awk | grep -q` kills awk with SIGPIPE under
    # `set -o pipefail`, which is the trap infn's header documents.
    seg="$(awk '/^static int unix_stream_connect/,/^}/' "$d/net/unix/af_unix.c" 2>/dev/null)" || true
    case "$seg" in
    *ghost_abstract_hidden*) die "_ghost: the abstract-socket guard is in unix_stream_connect(), the site it was retired from -- that one sees SOCK_STREAM only, and @init_monitor's measured leak is dgram-only, so it closes nothing for every name of that shape" ;;
    esac
    hasnt "$d/fs/proc/ghost.c" 'proc_create' \
        "_ghost: ghost.c owns a /proc node -- a file whose job is concealing files must not own a name no stock kernel has"
    # Both PRIO_USER arms or neither. The patch is one file, so grepping
    # kernel/sys.c for the helper passes with the setpriority half missing --
    # and setpriority alone is the writable direction of the same oracle.
    infn "$d/kernel/sys.c" '^SYSCALL_DEFINE3\(setpriority' 'ghost_uid_task_hidden(from_kuid' \
        "_ghost: the task-visibility guard is not inside setpriority() -- PRIO_USER still reports a concealed uid as owning tasks, which contradicts every /proc surface that says it owns none"
    infn "$d/kernel/sys.c" '^SYSCALL_DEFINE2\(getpriority' 'ghost_uid_task_hidden(from_kuid' \
        "_ghost: the task-visibility guard is not inside getpriority() -- this is the arm a detector actually reads, and it skipped silently on 5.10 and 5.15 for as long as it was applied with apply_optional"
    # Deferred past SUSFS, so the PRE-SUSFS verify cannot assert it yet. The
    # post-SUSFS one can and must; assert-config refuses to end a build that
    # never reached it, which is what stops the deferral becoming a skip.
    if [ "$(statfs_state)" = deferred ]; then
        echo "_ghost: statfs(2) guard deferred to the postsusfs step"
    else
        infn "$d/fs/statfs.c" '^int vfs_statfs' 'ghost_hidden_path(path))' \
            "_ghost: the statfs(2) guard is not inside vfs_statfs() -- statfs, statfs64 and both fstatfs forms reach the hidden object through this one function and read its real f_type and f_blocks, while stat(2), access(2) and open(2) all answer ENOENT for the same path"
    fi
    # The mountinfo family had no assertion at all until 2026-11-18, which is
    # exactly how it went unnoticed that the 6.12-only variant fails hunk 2 on
    # every older tree and apply_optional swallowed it. Name all three handlers:
    # the patch is one file, so "fs/proc_namespace.c mentions ghost_hidden_mount"
    # would pass with two of the three guards missing.
    for f in show_vfsmnt show_mountinfo show_vfsstat; do
        infn "$d/fs/proc_namespace.c" "^static int $f" 'ghost_hidden_mount(mnt))' \
            "_ghost: the mount guard is not inside $f() -- /proc/self/{mounts,mountinfo} and /proc/self/mountstats are three renderings of the same mount list, and a module bind hidden from one of them while another still names it is a contradiction, not a cloak"
    done
    # statmount(2)/listmount(2) exist from 6.8 and reach none of the three
    # fs/proc_namespace.c show handlers the mountinfo guard patches. apply_optional is
    # non-fatal by design, so when 6.12.58 moved `root` into struct kstatmount and the
    # patch anchored on the grab_requested_root() line that changed with it, the patch
    # skipped and three OnePlus targets built green with no guard at all. Assert it
    # wherever the syscalls exist, and stay quiet on the trees that predate them.
    if grep -q '^static int do_statmount' "$d/fs/namespace.c" 2>/dev/null; then
        infn "$d/fs/namespace.c" '^static int do_statmount' 'ghost_hidden_mount(s->mnt))' \
            "_ghost: the statmount(2) guard is not inside do_statmount() -- a hide-listed uid reads the module bind's root and mountpoint from one syscall, and mountinfo already denies it, so the two views disagree"
        infn "$d/fs/namespace.c" '^static ssize_t do_listmount' 'ghost_hidden_mount(&r->mnt))' \
            "_ghost: the listmount(2) guard is not inside do_listmount() -- the hidden mount's id is still emitted, and statmount then answers for an id the caller was handed"
    fi
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
    # RESOLVE the ref to a commit and record it. The comment above says a kernel
    # build "pins to what was actually released" -- a --depth 1 clone of `main`
    # does not pin anything: main moves, so two builds of the same
    # kernel_patches commit can carry different engines, and the only thing
    # recorded afterwards is NM_MODULE_VERSION, which does not change on every
    # engine commit. This does not make the build reproducible on its own (pass
    # NOMOUNT_REF=<tag> for that), but it does make it AUDITABLE: the build log
    # and $GITHUB_ENV both name the exact engine that went in.
    NM_SHA="$(git -C "$NM_SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
    export NM_SHA
    echo "engine: Bouteillepleine/NoMount-Suite@${NOMOUNT_REF:-main} = $NM_SHA"
    if [ -n "${GITHUB_ENV:-}" ]; then
        echo "NM_ENGINE_REF=${NOMOUNT_REF:-main}" >>"$GITHUB_ENV"
        echo "NM_ENGINE_SHA=$NM_SHA" >>"$GITHUB_ENV"
    fi
    case "${NOMOUNT_REF:-main}" in
    main | master)
        echo "  note: NOMOUNT_REF is a moving branch, so this build is not reproducible from kernel_patches alone. Pass NOMOUNT_REF=<tag> to pin it."
        ;;
    esac
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
    # FUZZ 0 FIRST, always. This used to go straight to --fuzz=1, which sat
    # directly under a file header that says "EVERY family is applied at fuzz 0.
    # A hunk that only lands 'with fuzz' can put a guard in the wrong function
    # silently" -- and it granted the exemption to the LARGEST and most invasive
    # patch in the stack (fs/Kconfig, fs/Makefile, fs/proc/task_mmu.c and the
    # VFS hook sites), which is backwards from the risk argument the rest of
    # this file makes for the small ones.
    #
    # The fallback stays, because this patch is generated by the engine repo
    # against its own snapshot of each tree and a real offset there is not this
    # script's to fix. But it is now the exception it always claimed to be:
    # loud, annotated, and visible in the build log rather than the default.
    if patch -p1 -F0 --forward --dry-run -d "$COMMON_KERNEL_FOLDER" <"$NM_PATCH" >/dev/null 2>&1; then
        patch -p1 -F0 --forward -d "$COMMON_KERNEL_FOLDER" <"$NM_PATCH" >/dev/null ||
            die "NoMount hookless patch dry-ran clean at -F0 and then failed to apply for $KERNEL_VER"
        echo "  hookless integration: applied at fuzz 0"
    elif patch -p1 -F0 --reverse --dry-run -d "$COMMON_KERNEL_FOLDER" <"$NM_PATCH" >/dev/null 2>&1; then
        echo "  hookless integration: already applied"
    else
        echo "::warning::hookless integration patch does not apply at fuzz 0 on $KERNEL_VER; retrying at fuzz 1. A fuzzed hunk can land a hook in the wrong function -- check fs/proc/task_mmu.c and fs/Makefile in the build output before trusting this kernel."
        patch -p1 --forward --fuzz=1 -d "$COMMON_KERNEL_FOLDER" <"$NM_PATCH" ||
            die "NoMount hookless patch failed to apply for $KERNEL_VER, at fuzz 0 and at fuzz 1"
    fi
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

# Apply, skip or refuse fix_selinux_seqno.patch on $KSU_FOLDER, by the shape the
# tree is actually in.
#
# On a tree that carries tiann/KernelSU#3964 the patch is not redundant but
# actively harmful: deleting the status update there leaves
# selnl_notify_policyload(seqno) announcing generation N while the status page
# stays at N-1, which is the very split this family exists to avoid. The old code
# was safe to cut only because every call passed a literal 0, so nothing moved.
seqno_apply() { # seqno_apply <_hook dir>
    local HOOK="$1" f="$KSU_FOLDER/kernel/selinux/rules.c" form
    form="$(ksu_seqno_form "$f")"
    case "$form" in
    upstream)
        echo "  skipped: fix_selinux_seqno (this KSU threads the real policy generation itself)"
        ;;
    split:*)
        die "fix_selinux_seqno: this KSU has reset_avc_cache(u32 seqno) but bumps pol->latest_granting at ${form#split:} of the 2 call sites, so one of apply_kernelsu_rules()/handle_sepolicy() still writes a stale generation to /sys/fs/selinux/status. Neither this patch nor skipping it is right -- fix the fork."
        ;;
    *)
        apply_or_die "$HOOK/fix_selinux_seqno.patch" "$KSU_FOLDER"
        ;;
    esac
}

# The post-condition, asserted wherever the decision has been made: the
# policyload=0 tell is gone, by our deletion or by the fork's own fix, and
# selnl_notify_policyload survived either way (gating it is a documented
# bootloop risk -- see README).
verify_seqno() {
    local f="$KSU_FOLDER/kernel/selinux/rules.c"
    case "$(ksu_seqno_form "$f")" in
    upstream)
        # The classifier reads the signature and the two bumps, so a hardcoded
        # zero left ANYWHERE else in this file would pass unseen -- and that call
        # writes policyload=0 to /sys/fs/selinux/status whatever the seqno
        # plumbing around it says. Assert the tell's absence, not the shape.
        hasnt "$f" 'selinux_status_update_policyload(0)' \
            "_hook: this KSU threads the real policy generation, yet a hardcoded selinux_status_update_policyload(0) remains in rules.c -- that call still publishes policyload=0 to /sys/fs/selinux/status"
        hasnt "$f" 'selinux_status_update_policyload(&selinux_state, 0)' \
            "_hook: this KSU threads the real policy generation, yet a hardcoded selinux_status_update_policyload(&selinux_state, 0) remains in rules.c (pre-6.4 form) -- that call still publishes policyload=0"
        echo "  _hook: fix_selinux_seqno not needed -- this KSU writes the true policy generation"
        ;;
    *)
        hasnt "$f" 'selinux_status_update_policyload' \
            "_hook: fix_selinux_seqno did not land -- KSU still writes policyload=0 to /sys/fs/selinux/status"
        ;;
    esac
    has "$f" 'selnl_notify_policyload' \
        "_hook: selnl_notify_policyload was removed -- see README, gating it is a documented bootloop risk"
}

do_seqno() {
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KSU_FOLDER
    echo "::group::Apply fix_selinux_seqno (after SUSFS)"
    local HOOK="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_hook"
    normalise "$HOOK/fix_selinux_seqno.patch"
    [ -f "$KSU_FOLDER/kernel/selinux/rules.c" ] ||
        die "seqno: $KSU_FOLDER/kernel/selinux/rules.c does not exist"
    seqno_apply "$HOOK"
    verify_seqno
    seqno_mark decided
    echo "::endgroup::"
}

# susfs 9b0b13f moved KernelSU's setprocattr hook kernel-side, so the probe that
# equalises its two arms has to be re-applied there -- the reduction susfs applies
# to selinux_hide.c deletes the function the KernelSU-side probe lived in. On a
# susfs that predates the move susfs_selinux_lsm_setattr() does not exist and this
# is a no-op; verify_hook then still requires the KernelSU-side probe, so neither
# world can ship without one.
do_postsusfs() {
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER
    local GH="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_ghost"
    # The statfs(2) guard, on the shape SUSFS actually produced. Probed on the
    # tree and never on whether susfs_ref was set: a build can ask for SUSFS and
    # still get a tree without this hunk, because 50_add_susfs_in_gki's statfs
    # arm is one of the hunks the fix sets are allowed to reject. Either variant
    # is fatal if the one the tree calls for does not fit -- a silent skip here
    # is the whole failure this stack keeps relearning.
    if [ "$(statfs_state)" = deferred ]; then
        echo "::group::Place the statfs(2) guard (after SUSFS)"
        normalise "$GH/ghost_statfs.patch" "$GH/ghost_statfs_susfs.patch"
        if grep -q 'CONFIG_KSU_SUSFS_SUS_KSTAT' "$COMMON_KERNEL_FOLDER/fs/statfs.c"; then
            apply_or_die "$GH/ghost_statfs_susfs.patch"
            echo "postsusfs: statfs guard placed ahead of the SUSFS sus_kstat arm"
        else
            apply_or_die "$GH/ghost_statfs.patch"
            echo "postsusfs: statfs guard placed on a tree SUSFS did not touch"
        fi
        statfs_mark decided
        echo "::endgroup::"
    fi
    echo "::group::Equalise setprocattr timing (after SUSFS)"
    local HOOK="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_hook"
    # The two hooks are NOT exclusive and verify_hook requires a probe in EVERY
    # one that exists, so this places a probe in every one that exists -- not the
    # first that matches. On SukiSU and KSUN the reduction deletes KernelSU's hook
    # and only the kernel-side arm is left; BakaSU keeps a selinux_hide.c the
    # reduction does not fit (1837 lines, its hunks reject) and ends up with BOTH.
    # An either/or here would have left BakaSU's hook unprobed and failed the
    # post-SUSFS verify -- which is what do_hook used to cover by applying the
    # KernelSU-side probe up front, at the cost of breaking the reduction.
    local placed=0
    if grep -q 'susfs_selinux_lsm_setattr' "$COMMON_KERNEL_FOLDER/security/selinux/hooks.c"; then
        normalise "$HOOK/equalise_setprocattr_timing_susfs.patch"
        apply_or_die "$HOOK/equalise_setprocattr_timing_susfs.patch"
        echo "postsusfs: equalised the susfs kernel-side setprocattr arms"
        placed=1
    fi
    if [ "$(setprocattr_state)" = deferred ] && ksu_selinux_hide_file >/dev/null; then
        # SUSFS left KernelSU's hook standing, so the probe belongs there too --
        # applied now, on the shape SUSFS actually produced, rather than before it
        # had its say about the file. Gated on the deferral: when do_hook already
        # placed it (every branch SUSFS does not own), re-applying would fail as
        # an already-applied patch.
        setprocattr_apply "$HOOK"
        echo "postsusfs: equalised the KernelSU-side setprocattr arms"
        placed=1
    fi
    # Not deferred means do_hook placed the KernelSU-side probe before SUSFS, and
    # the pre-SUSFS verify already asserted it in full. Say so rather than going
    # silent: a step that prints nothing is how a skipped probe hides.
    if [ "$(setprocattr_state)" != deferred ]; then
        echo "postsusfs: the KernelSU-side probe went on before SUSFS (${KV:-this tree} has no kernel-side hook to re-place it in); nothing to do here"
        placed=1
    fi
    # No hook anywhere is a legitimate end state below android16-6.12:
    # susfs_selinux_lsm_setattr exists only in 50_add_susfs_in_gki-android16-6.12
    # (6.6 / 6.1 / 5.15 -> 0 hits), and the enable patch reduces KernelSU's
    # selinux_hide.c to a shell on every branch. With no hook there is no
    # backup-policy parse on either payload shape, so there is no asymmetry to
    # equalise -- the oracle needs SukiSU's hook to EXIST. The sepolicy surface
    # itself stays covered by the common-kernel _hook patches
    # (mask_dirty_sepolicy_edges, hide_selinux_selinuxfs, hide_selinux_attr),
    # which is where this family's SELinux cloak actually lives.
    # Plain log line, not an annotation: legitimate on every build below 6.12.
    [ "$placed" = 1 ] ||
        echo "postsusfs: SUSFS left no setprocattr hook in either tree, so there is no attr/current asymmetry to equalise; the sepolicy cloak is carried by the common-kernel _hook patches"
    setprocattr_mark decided
    echo "::endgroup::"
}

do_hook() {
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KSU_FOLDER
    echo "::group::Apply SELinux oracle (_hook) patches"
    local HOOK="$BOUTEILLE_KERNEL_PATCHES_FOLDER/common/_hook"
    normalise "$HOOK"/*.patch

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
    # 6.6 carries the mnt_idmap-era selinux_inode_setxattr() that the 6.12 hunk
    # guards, but still the 6.6-shaped selinux_setprocattr(). It used to take the
    # setprocattr-ONLY fallback, which left setxattr(security.selinux) uncovered
    # there while the README listed the gap as 5.10/5.15/6.1 only.
    6.6)  REQ_ATTR=hide_selinux_attr_6_6.patch ;;
    # 5.10/5.15/6.1 now have their own two-arm variant. They were on the
    # setprocattr-only fallback because the 6.6 setxattr hunk did not fit: all
    # three pass &selinux_state to security_context_to_sid(), which sits in that
    # hunk's context. One variant covers the three -- the pre-image is identical
    # in each. Without it, setxattr(security.selinux, "...:ksu_file:...") still
    # separated "type not in policy" (-EINVAL) from "type exists, denied"
    # (-EACCES), which is an app-reachable probe for the hidden types.
    5.10 | 5.15 | 6.1) REQ_ATTR=hide_selinux_attr_5_10.patch ;;
    # Kept only as the multi-match partner apply_first_of resolves against: the
    # setprocattr-only patch still applies everywhere, so the pin is what picks.
    *) REQ_ATTR=hide_selinux_attr.patch ;;
    esac

    apply_first_of selinuxfs "$REQ_SFS" \
        "$HOOK/hide_selinux_selinuxfs_6_12.patch" "$HOOK/hide_selinux_selinuxfs_5_10.patch"
    apply_first_of attr "$REQ_ATTR" \
        "$HOOK/hide_selinux_attr_6_12.patch" "$HOOK/hide_selinux_attr_6_6.patch"         "$HOOK/hide_selinux_attr_5_10.patch" "$HOOK/hide_selinux_attr.patch"
    apply_first_of avc-audit "$REQ_AUDIT" \
        "$HOOK/quiet_selinux_audit.patch" "$HOOK/quiet_selinux_audit_legacy.patch"
    # One variant covers every version this family supports. It anchors on the
    # tail of security_compute_av_user(), which is byte-identical from 5.10 to
    # 6.12 -- only the function's signature differs across them, and that is not
    # in the hunk.
    apply_or_die "$HOOK/mask_dirty_sepolicy_edges.patch"
    if [ "${SUSFS_ON:-}" = true ]; then
        seqno_mark deferred
        echo "  deferred: fix_selinux_seqno (SUSFS rewrites rules.c; the seqno step owns it afterwards)"
    else
        seqno_apply "$HOOK"
    fi
    if [ "${SUSFS_ON:-}" = true ]; then
        setprocattr_mark deferred
        echo "  deferred: equalise_setprocattr_timing (SUSFS reduces selinux_hide.c; the postsusfs step places the probe in whichever hook survives)"
    else
        setprocattr_apply "$HOOK"
        setprocattr_mark decided
    fi

    # avc_spoof now exists in two shapes, so probe for each rather than assuming
    # one fork owns it. KernelSU-Next keeps it in kernel/extras.c and logs
    # 'replacing su_sid'. SukiSU-Ultra grew its own in kernel/feature/avc_spoof.c
    # as of v4.2.1-r2, logging 'replace tsid' on every spoofed denial plus the
    # resolved su/ksu/priv_app SIDs at init -- the ksu one being the worst of the
    # three, since it names the context the cloak exists to hide. Probed on the
    # tree, not on the fork name: a fork that gains the feature picks this up, and
    # one that drops the line stops failing the build. Left in, either of these
    # hands a dmesg_restrict=0 device's shell a running commentary on the thing
    # avc_spoof exists to hide.
    _avc_quieted=0
    if [ -f "$KSU_FOLDER/kernel/extras.c" ] &&
        grep -q 'replacing su_sid' "$KSU_FOLDER/kernel/extras.c"; then
        apply_or_die "$HOOK/quiet_avc_spoof_log.patch" "$KSU_FOLDER"
        _avc_quieted=1
    fi
    if [ -f "$KSU_FOLDER/kernel/feature/avc_spoof.c" ] &&
        grep -q 'replace tsid' "$KSU_FOLDER/kernel/feature/avc_spoof.c"; then
        apply_or_die "$HOOK/quiet_avc_spoof_log_sukisu.patch" "$KSU_FOLDER"
        _avc_quieted=1
    fi
    if [ "$_avc_quieted" != 1 ]; then
        echo "  skipped: quiet_avc_spoof_log (this KSU has no avc_spoof log)"
    fi
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
    normalise "$d/fs/pathhide.c" "$d/fs/pathhide.h"
    normalise "$PH"/*.patch
    # The maps/smaps guards sit in context that an AOSP GKI tree and an OPlus tree
    # spell differently at the same version: 6.12.69 renamed vma_pages() to
    # vma_data_pages() in show_map()/show_smap() and gave show_smaps_rollup() an
    # extra local, so the OPlus-fitted patch misses three of its six hunks there.
    # Probed, not keyed on KERNEL_VER, for the same reason the accounting variants
    # are: both trees report 6.12.
    if [ "$KERNEL_VER" = 6.12 ] && grep -q 'vma_data_pages' "$d/fs/proc/task_mmu.c"; then
        apply_first_of pathhide pathhide_6.12_gki_integration.patch \
            "$PH/pathhide_6.12_integration.patch" \
            "$PH/pathhide_6.12_gki_integration.patch"
    else
        apply_or_die "$PH/pathhide_${KERNEL_VER}_integration.patch"
    fi
    apply_or_die "$PH/pathhide_mapfiles_${KERNEL_VER}_integration.patch"
    # Dropping a vma's line from maps leaves the mapping itself in place, so the
    # gap stays readable through pagemap, mincore(2) and the accounting-derived
    # counters (VmSize/VmPeak/statm) -- none of which the maps cloak touches.
    # Every pin below reads the tree instead of KERNEL_VER. A version key was
    # correct for these two across all 54 vendor trees the builders build, but it
    # was also correct for the accounting pin right up until sm8750 at 6.6.89,
    # where the shape tracked the vendor branch rather than the GKI number. The
    # markers were measured over those same 54 trees and separate them exactly.
    local REQ_PAGEMAP REQ_MINCORE REQ_ACCT
    # PAGEMAP_SCAN arrived in 6.7, so pagemap_scan_test_walk() exists only on the
    # 6.12 trees (6 of 54) and is the extra hunk the 6.12 variant carries.
    # pagemap_pmd_range() otherwise splits on `bool migration`, present on
    # 5.10/5.15/6.1 (33 trees) and gone by 6.6 (15). The marker has to be scoped
    # to that function: `bool migration` appears elsewhere in task_mmu.c, and
    # the 6.12 variant's userfaultfd_wp_async() context belongs to the
    # PAGEMAP_SCAN hunk, not to pagemap_pmd_range.
    if grep -q 'pagemap_scan_test_walk' "$d/fs/proc/task_mmu.c"; then
        REQ_PAGEMAP=pathhide_pagemap_6.12_integration.patch
    elif awk '/^static int pagemap_pmd_range/,/^}/' "$d/fs/proc/task_mmu.c" |
        grep -q 'bool migration'; then
        REQ_PAGEMAP=pathhide_pagemap_5.10_integration.patch
    else
        REQ_PAGEMAP=pathhide_pagemap_6.6_integration.patch
    fi
    # do_mincore() finds the vma with find_vma()+vm_start on the older trees and
    # with vma_lookup() from 6.6 on. The guard has to sit before
    # can_do_mincore(), which memsets "resident" for a file the caller cannot
    # write -- so the unwritable case leaks through the side channel, not the walk.
    if grep -q 'vma_lookup(current->mm, addr)' "$d/mm/mincore.c"; then
        REQ_MINCORE=pathhide_mincore_6.12_integration.patch
    else
        REQ_MINCORE=pathhide_mincore_5.10_integration.patch
    fi
    # KERNEL_VER cannot pick this one at all, so do not try. What the three
    # variants differ on is how task_statm() reads its counters, and that tracks
    # the vendor branch rather than the GKI version:
    #
    #   __page_size_count(mm->total_vm)  OnePlus's page-size emulation. OP15's
    #                                    6.12.58 manifest carries it, its 6.12.23
    #                                    manifest does not, and both report 6.12.
    #   get_mm_counter_sum(...ANONPAGES) the summed-counter shape. Some 6.6 trees
    #                                    have it; sm8750 at 6.6.89 does not, which
    #                                    is what a version-keyed pin got wrong.
    #   get_mm_counter(...ANONPAGES)     everything else.
    #
    # Order matters: the emulated shape reads through get_mm_counter_sum() too, so
    # it has to be tested first or it would match the 6.6 variant.
    #
    # For the emulated tree the subtraction also has to land INSIDE the
    # conversion: pathhide_hidden_vm_pages() counts real PAGE_SIZE pages while
    # __page_size_count() DIV_ROUND_UPs into the emulated size, so converting
    # first and subtracting after rounds twice and can over-deduct a page.
    # 6.12.81 moved __page_size_count() INSIDE the resident sum, so it still
    # matches the pgcompat test below while its second hunk no longer applies.
    # Test the narrower shape first or the tree is pinned to a variant that
    # cannot land, which is how OP15-6.12.81 failed at fuzz 0.
    if grep -q '\*resident = \*shared + __page_size_count(' "$d/fs/proc/task_mmu.c"; then
        REQ_ACCT=pathhide_accounting_pgsplit_integration.patch
    elif grep -q '__page_size_count(mm->total_vm)' "$d/fs/proc/task_mmu.c"; then
        REQ_ACCT=pathhide_accounting_pgcompat_integration.patch
    elif grep -q 'get_mm_counter_sum(mm, MM_ANONPAGES)' "$d/fs/proc/task_mmu.c"; then
        REQ_ACCT=pathhide_accounting_6.6_integration.patch
    else
        REQ_ACCT=pathhide_accounting_integration.patch
    fi
    apply_first_of pathhide-pagemap "$REQ_PAGEMAP" \
        "$PH/pathhide_pagemap_6.12_integration.patch" \
        "$PH/pathhide_pagemap_6.6_integration.patch" \
        "$PH/pathhide_pagemap_5.10_integration.patch"
    apply_first_of pathhide-mincore "$REQ_MINCORE" \
        "$PH/pathhide_mincore_6.12_integration.patch" \
        "$PH/pathhide_mincore_5.10_integration.patch"
    apply_first_of pathhide-accounting "$REQ_ACCT" \
        "$PH/pathhide_accounting_pgsplit_integration.patch" \
        "$PH/pathhide_accounting_6.6_integration.patch" \
        "$PH/pathhide_accounting_pgcompat_integration.patch" \
        "$PH/pathhide_accounting_integration.patch"
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
    normalise "$d/fs/proc/ghost.c" "$d/fs/proc/ghost.h"
    normalise "$GH"/*.patch

    local REQ_XATTR REQ_LINKAT REQ_CHMOD REQ_UNIXSOCK REQ_MOUNTINFO REQ_GETPRIO
    case "$KERNEL_VER" in
    6.12)
        REQ_XATTR=ghost_xattr_6_12.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod.patch
        REQ_UNIXSOCK=ghost_unixsock.patch
        REQ_MOUNTINFO=ghost_mountinfo_6_12.patch
        REQ_GETPRIO=ghost_getpriority.patch
        ;;
    # 6.6 agrees with 6.12 on every row but the mountinfo one, which is why this
    # arm is split where it used to pair the two versions up. 6.12 replaced the
    # inline `if (sb->s_op->show_path)` branch in show_mountinfo() with a call to
    # show_path(), and that line is hunk 2's trailing context -- so on 6.6 and
    # below the 6.12 variant fails that one hunk, and `patch` then applies none
    # of the three. The other two handlers, show_vfsmnt() and show_vfsstat(),
    # are byte-identical from 5.10 to 6.12 and were being dropped with it.
    6.6)
        REQ_XATTR=ghost_xattr_6_12.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod.patch
        REQ_UNIXSOCK=ghost_unixsock.patch
        REQ_MOUNTINFO=ghost_mountinfo_5_10.patch
        REQ_GETPRIO=ghost_getpriority.patch
        ;;
    # 6.1 and 5.15 agree on every row but the socket one: unix_find_abstract()
    # was split out of unix_find_other() in 6.1, so 6.1 joins 6.6/6.12 there
    # and 5.15 keeps the unix_find_other() shape. That is why this arm is split
    # in two where the others pair the versions up.
    6.1)
        REQ_XATTR=ghost_xattr_5_15.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        REQ_UNIXSOCK=ghost_unixsock.patch
        REQ_MOUNTINFO=ghost_mountinfo_5_10.patch
        REQ_GETPRIO=ghost_getpriority.patch
        ;;
    5.15)
        REQ_XATTR=ghost_xattr_5_15.patch
        REQ_LINKAT=ghost_linkat_5_15.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        REQ_UNIXSOCK=ghost_unixsock_5_15.patch
        REQ_MOUNTINFO=ghost_mountinfo_5_10.patch
        REQ_GETPRIO=ghost_getpriority_5_10.patch
        ;;
    5.10)
        REQ_XATTR=ghost_xattr.patch
        REQ_LINKAT=ghost_linkat.patch
        REQ_CHMOD=ghost_chmod_5_10.patch
        REQ_UNIXSOCK=ghost_unixsock_5_10.patch
        REQ_MOUNTINFO=ghost_mountinfo_5_10.patch
        REQ_GETPRIO=ghost_getpriority_5_10.patch
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
    # chown is chmod's sibling in the mnt_want_write-answers-first family, and
    # do_fchownat() is byte-identical on all five, so it needs no variant table.
    apply_or_die "$GH/ghost_chown.patch"
    # The task-visibility guard. getpriority(PRIO_USER)/setpriority answer
    # -ESRCH for a concealed uid, which is what the kernel already answers for
    # a user that owns no task, so a concealed uid reads as idle rather than
    # special. Inert until userspace pushes a `c` list through ghost_ctl().
    #
    # Two variants, pinned by version. The guard goes in ahead of the PRIO_USER
    # loop in both syscalls, and that loop is the hunks' trailing context: 6.1
    # carries for_each_process_thread(), 5.10 and 5.15 still spell it
    # do_each_thread(). This was apply_optional until 2026-11-18 and so skipped
    # silently on those two -- 20 of the 84 a16 configs shipped with the guard
    # absent, and this is a MEASURED oracle (DuckDetector reads it off a running
    # app), not a reasoned one.
    apply_first_of ghost-getpriority "$REQ_GETPRIO" \
        "$GH/ghost_getpriority.patch" "$GH/ghost_getpriority_5_10.patch"
    # The abstract-socket guard. A hidden @name answers -ECONNREFUSED, which is
    # what an app already gets when nothing is listening, so a service that is
    # spoofed as stopped cannot be caught still holding its control socket.
    #
    # The guard sits in the NAME LOOKUP, not in unix_stream_connect() where it
    # started. It used to be anchored on unix_validate_addr() and the BPF connect
    # hook either side of it, which fit 6.12 alone -- and, worse, covered only
    # SOCK_STREAM. All four entry points (stream connect, dgram connect, dgram
    # sendmsg, seqpacket) funnel through unix_find_other(), and both LSM hooks
    # (security_unix_stream_connect, security_unix_may_send) run AFTER the socket
    # is found, so EACCES from them means "found". Measured on OP15 from
    # untrusted_app_27: @init_monitor answers ECONNREFUSED on STREAM but EACCES on
    # DGRAM, and @cp64.sock the other way round -- each name answers on one type
    # only. A stream-only guard therefore closed nothing at all for every name of
    # @init_monitor's shape. Guarding the lookup preempts both LSM hooks, so both
    # types answer ECONNREFUSED.
    #
    # Two shapes, and the pin matters: 6.1 split unix_find_abstract() out of
    # unix_find_other(), and the function is byte-identical on 6.1/6.6/6.12, so
    # one file covers all three. 5.10/5.15 guard the abstract else-arm of
    # unix_find_other() itself and differ only in the unix_find_socket_byname()
    # call that follows (type, hash vs type ^ hash) -- which is the whole reason
    # they are two files and not one. Exactly one variant applies at fuzz 0 per
    # tree, so a miss here is drift, not a version gap: apply_first_of dies rather
    # than skipping, the way the statmount guard should have.
    #
    # Path-bound sockets need nothing here. unix_find_bsd()/the sun_path arm
    # resolve through kern_path(), so /dev/socket/<name> is already answered by
    # the engine's hijacked lookup ops under the same ghostpath rule.
    apply_first_of ghost-unixsock "$REQ_UNIXSOCK" \
        "$GH/ghost_unixsock.patch" "$GH/ghost_unixsock_5_15.patch" "$GH/ghost_unixsock_5_10.patch"
    # The mount-table guard. A hook framework's dex2oat/app_process bind is the
    # one real mount the mountless posture keeps by design (absorb declines it:
    # dropping it breaks dexopt), and it is rooted at /adb/modules/... . An app
    # forked from the app zygote never sees it -- that namespace has it unmounted
    # -- but the Android 17 zygote_next isolated path runs in a COPY of init's
    # namespace, which still carries it, so one isolated read of
    # /proc/self/mountinfo names the module that owns the bind. The guard matches
    # the mount's SOURCE ROOT (mountinfo field 4) against the same hidden-path
    # table, not its d_path: d_path renders the mountpoint (/apex/.../dex2oat64),
    # a path the binary still has to resolve, so matching that would over-hide.
    # Two variants, pinned by version and never by "first that applies": they
    # differ only in hunk 2's trailing context, so neither fits the other's tree
    # and a fallback would silently ship a kernel with all three handlers open.
    # This was apply_optional until 2026-11-18, which is a non-fatal skip -- so
    # 5.10 through 6.6 built green with no mountinfo, /proc/mounts or mountstats
    # guard at all, and nothing said so. That is 73 of the 84 a16 configs.
    apply_first_of ghost-mountinfo "$REQ_MOUNTINFO" \
        "$GH/ghost_mountinfo_6_12.patch" "$GH/ghost_mountinfo_5_10.patch"
    # The same mount, through the syscalls that reach none of those three handlers.
    # statmount(2)/listmount(2) are 6.8 and newer and walk the namespace rbtree in
    # kernel code, so the SEQ_SKIP guard above is simply not on their path. Measured
    # on CPH2747 6.12.69 as a hide-listed uid: mountinfo showed no module bind while
    # statmount handed over root=/adb/modules/zygisk_lsposed/bin/dex2oat64 -- the two
    # views disagreeing for one caller, which is a stronger tell than the leak was.
    # do_listmount() drops the mount before its id is emitted and do_statmount()
    # answers -ENOENT, the same as for an id that never existed. Optional because
    # nothing below 6.8 has the syscalls for the anchors to fit.
    apply_optional "$GH/ghost_statmount_6_12.patch"
    # statfs(2)/statfs64(2) and their fstatfs forms all reach vfs_statfs(), which
    # is byte-identical from 5.10 to 6.12. Every other ghost surface answers
    # ENOENT for a hidden path while this one handed back a real f_type and
    # f_blocks -- one caller, two answers, the contradiction the stat(2) guard
    # exists to prevent. NoMount patches user_statfs() one frame up and only
    # rewrites f_type for INJECTED paths, so it closes nothing here.
    #
    # DEFERRED past SUSFS, which wants the same slot -- see statfs_stamp() above
    # and do_postsusfs(). Marked rather than silently skipped so the pre-SUSFS
    # verify can tell "not placed yet" from "never placed".
    statfs_mark deferred
    # access(W_OK), and the write-intent and O_CREAT forms of open(2): the
    # sb_permission() short-circuit inside inode_permission(), which answers
    # -EROFS before do_inode_permission() dispatches to the engine. One file
    # each, 5.10 through 6.12.
    apply_or_die "$GH/ghost_access.patch"
    apply_or_die "$GH/ghost_open.patch"
    apply_or_die "$GH/ghost_create.patch"
    apply_or_die "$GH/ghost_build_integration.patch"
    # stat(2) family -- the plainest existence oracle there is, and the last
    # surface that had no guard at all. Three shapes: 5.10/5.15 resolve with
    # user_path_at(), 6.1/6.6 with filename_lookup() into vfs_getattr(), 6.12
    # with filename_lookup() into vfs_statx_path(). All three take their error
    # path with `goto out`, where out: is a bare `return error` that does NOT
    # path_put -- so each guard puts the path itself rather than falling through.
    local REQ_STATX
    case "$KERNEL_VER" in
    6.12) REQ_STATX=ghost_statx_6_12.patch ;;
    6.6 | 6.1) REQ_STATX=ghost_statx_6_1.patch ;;
    5.15 | 5.10) REQ_STATX=ghost_statx_5_10.patch ;;
    esac
    apply_first_of ghost-statx "$REQ_STATX" \
        "$GH/ghost_statx_6_12.patch" "$GH/ghost_statx_6_1.patch" \
        "$GH/ghost_statx_5_10.patch"
    # readlink(2). Two shapes: 6.12 resolves through filename_lookup() and owns a
    # struct filename the guard has to putname(); everything older goes through
    # user_path_at_empty() and has only the path to drop.
    local REQ_READLINK
    case "$KERNEL_VER" in
    6.12) REQ_READLINK=ghost_readlink_6_12.patch ;;
    *) REQ_READLINK=ghost_readlink_5_10.patch ;;
    esac
    apply_first_of ghost-readlink "$REQ_READLINK" \
        "$GH/ghost_readlink_6_12.patch" "$GH/ghost_readlink_5_10.patch"
    # rename(2), SOURCE half only. At that point `error` is already -ENOENT and
    # exit4 is the unwind a genuinely absent source takes, so a hidden source is
    # byte-identical to an absent one -- and it also stops a hidden file being
    # renamed out of the path that hides it. The TARGET half is deliberately not
    # guarded: rename onto an absent target SUCCEEDS, and no error a guard can
    # return matches that without performing the rename, so RENAME_NOREPLACE
    # onto a hidden target still answers -EEXIST. Same trade as filename_create.
    local REQ_RENAME
    case "$KERNEL_VER" in
    5.10) REQ_RENAME=ghost_rename_5_10.patch ;;
    *) REQ_RENAME=ghost_rename_5_15.patch ;;
    esac
    apply_first_of ghost-rename "$REQ_RENAME" \
        "$GH/ghost_rename_5_10.patch" "$GH/ghost_rename_5_15.patch"
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
seqno)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER KSU_FOLDER
    do_seqno
    ;;
postsusfs)
    need BOUTEILLE_KERNEL_PATCHES_FOLDER COMMON_KERNEL_FOLDER
    resolve_kv
    do_postsusfs
    ;;
# Read-only, and the reason the CI job that measures the patch's fit against every
# KSU fork does not carry its own copy of these greps: one classifier, one answer.
seqno-form)
    [ $# -ge 1 ] || die "seqno-form: pass the KernelSU tree root"
    ksu_seqno_form "$1/kernel/selinux/rules.c"
    ;;
# Read-only twin of the above for the setprocattr family, so the gate asks the
# tree the same question the builder does. Prints the form and the path the hook
# was actually found at, and the patch that form selects. The path matters
# because BakaSU 2b558ca moved it and the filename alone resolves to the wrong
# half of the split; the patch name is emitted here rather than mapped by the
# caller so the gate cannot disagree with the builder about which variant a
# shape selects.
setprocattr-form)
    [ $# -ge 1 ] || die "setprocattr-form: pass the KernelSU tree root"
    KSU_FOLDER="$1"
    if _spa_hide="$(ksu_selinux_hide_file)"; then
        _spa_form="$(ksu_setprocattr_form "$_spa_hide")"
        printf '%s %s %s\n' "$_spa_form" "${_spa_hide#"$KSU_FOLDER"/}" "$(ksu_setprocattr_patch "$_spa_form")"
    else
        echo none
    fi
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
    # Before the config assertions, because this one says the build is INCOMPLETE
    # rather than misconfigured, and it is the last place anything checks.
    if [ "$(seqno_state)" = deferred ]; then
        die "the _hook step deferred fix_selinux_seqno to the post-SUSFS seqno step, and that step never ran: KernelSU still writes policyload=0 to /sys/fs/selinux/status and nothing asserted otherwise. Add 'apply_nomount_stack.sh seqno' after the SUSFS enable patch."
    fi
    if [ "$(setprocattr_state)" = deferred ]; then
        die "the _hook step deferred equalise_setprocattr_timing to the post-SUSFS postsusfs step, and that step never ran: nothing equalises the two attr/current arms and the timing asymmetry ships unasserted. Add 'apply_nomount_stack.sh postsusfs' after the SUSFS enable patch."
    fi
    if [ "$(statfs_state)" = deferred ]; then
        die "the _ghost step deferred ghost_statfs to the post-SUSFS postsusfs step, and that step never ran: vfs_statfs() has no guard, so statfs(2) reports a real f_type and f_blocks for a path stat(2) and open(2) both answer ENOENT for. Add 'apply_nomount_stack.sh postsusfs' after the SUSFS enable patch."
    fi
    CONFIG_STRICT=1
    assert_config CONFIG_NOMOUNT "the engine is behind CONFIG_NOMOUNT; without it fs/nomount.o is not built at all"
    assert_config CONFIG_SECURITY_SELINUX "every _hook guard is compiled only under CONFIG_SECURITY_SELINUX"
    ;;
*)
    usage
    ;;
esac
