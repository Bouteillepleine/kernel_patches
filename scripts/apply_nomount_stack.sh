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

    # Every selinuxfs WRITE NODE, by name. "selinuxfs.c contains sel_ctx_hidden"
    # is satisfied by the definition alone, so a refit that dropped a handler's
    # call site passed. Three of these handlers (access, relabel, member) have
    # character-identical bodies, which means their hunks have identical
    # pre-images and `patch` resolves them by line number -- they land on the
    # three sites in some order, and this is what asserts that all three ended
    # up with a guard rather than one of them being skipped.
    local w
    for w in sel_write_context sel_write_validatetrans sel_write_access \
             sel_write_create sel_write_relabel sel_write_user sel_write_member; do
        infn "$d/security/selinux/selinuxfs.c" "^static ssize_t $w\(" 'sel_ctx_hidden' \
            "_hook: $w() has no sel_ctx_hidden() gate -- that write node is an open hidden-type probe"
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
    hasnt "$KSU_FOLDER/kernel/selinux/rules.c" 'selinux_status_update_policyload' \
        "_hook: fix_selinux_seqno did not land -- KSU still writes policyload=0 to /sys/fs/selinux/status"
    has "$KSU_FOLDER/kernel/selinux/rules.c" 'selnl_notify_policyload' \
        "_hook: selnl_notify_policyload was removed -- see README, gating it is a documented bootloop risk"

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
    local d="$COMMON_KERNEL_FOLDER" n
    [ -f "$d/fs/proc/ghost.c" ] || die "_ghost: fs/proc/ghost.c missing"
    [ -f "$d/fs/proc/ghost.h" ] || die "_ghost: fs/proc/ghost.h missing"
    objy "$d/fs/proc/Makefile" 'ghost.o' "_ghost"

    infn "$d/fs/namei.c" '^static int do_o_path' 'ghost_hidden_path(&path))'         "_ghost: the O_PATH guard is not inside do_o_path()"
    infn "$d/fs/namei.c" '^static int do_open' 'op->acc_mode & MAY_WRITE'         "_ghost: the open(2) guards are not inside do_open()"
    infn "$d/fs/namei.c" '^static int path_lookupat' 'unlikely(err == -ENOTDIR)'         "_ghost: the ENOTDIR guard is not inside path_lookupat(). It applies at fuzz 0 inside path_parentat() too -- that is the bug ghost_notdir.patch's header documents, and this is the assertion that catches it."
    infn "$d/fs/namei.c" '^static struct dentry \*filename_create' 'err2 && ghost_hidden_path'         "_ghost: the create guard is not inside filename_create()"
    infn "$d/fs/namei.c" '^(static )?int do_linkat' 'ghost_hidden_path(&old_path)'         "_ghost: the link(2) guard is not inside do_linkat()"
    infn "$d/fs/open.c" '^int do_fchownat' 'ghost_hidden_path(&path))'         "_ghost: the chown(2) guard is not inside do_fchownat()"
    infn "$d/fs/open.c" '^static long do_faccessat' 'mode & MAY_WRITE) && ghost_hidden_path'         "_ghost: the access(2) guard is not inside do_faccessat()"
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

    if awk '/^int do_renameat2/,/^}/' "$d/fs/namei.c" | grep -q 'ghost_hidden_path'; then
        die "_ghost: the create guard landed in do_renameat2, not filename_create"
    fi
    if awk '/^static int path_parentat/,/^}/' "$d/fs/namei.c" | grep -q 'ghost_hidden_path'; then
        die "_ghost: a guard landed in path_parentat(). That is where ghost_notdir.patch's first hunk went on 5.10/5.15/6.1/6.6 before its context was widened -- see that file's header."
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
    # 5.10/5.15/6.1 keep the setprocattr-only fallback: their
    # selinux_inode_setxattr() has neither shape the setxattr hunk is fitted to,
    # so setxattr(security.selinux) stays uncovered there -- see the README.
    *) REQ_ATTR=hide_selinux_attr.patch ;;
    esac

    apply_first_of selinuxfs "$REQ_SFS" \
        "$HOOK/hide_selinux_selinuxfs_6_12.patch" "$HOOK/hide_selinux_selinuxfs_5_10.patch"
    apply_first_of attr "$REQ_ATTR" \
        "$HOOK/hide_selinux_attr_6_12.patch" "$HOOK/hide_selinux_attr_6_6.patch"         "$HOOK/hide_selinux_attr.patch"
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
    normalise "$d/fs/pathhide.c" "$d/fs/pathhide.h"
    normalise "$PH"/*.patch
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
    normalise "$d/fs/proc/ghost.c" "$d/fs/proc/ghost.h"
    normalise "$GH"/*.patch

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
    # chown is chmod's sibling in the mnt_want_write-answers-first family, and
    # do_fchownat() is byte-identical on all five, so it needs no variant table.
    apply_or_die "$GH/ghost_chown.patch"
    # access(W_OK), and the write-intent and O_CREAT forms of open(2): the
    # sb_permission() short-circuit inside inode_permission(), which answers
    # -EROFS before do_inode_permission() dispatches to the engine. One file
    # each, 5.10 through 6.12.
    apply_or_die "$GH/ghost_access.patch"
    apply_or_die "$GH/ghost_open.patch"
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
