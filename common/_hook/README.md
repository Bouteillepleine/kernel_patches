# `_hook` — SELinux oracle cloak

Four families - seven files - that close SELinux-side oracles a detector uses to
tell a rooted kernel from a stock one. Applied by the NoMount kernel builders
after the KSU patches, at **fuzz 0**, each fail-closed
(`scripts/apply_nomount_stack.sh hook`).

| family | closes |
|---|---|
| `hide_selinux_attr.patch` / `hide_selinux_attr_6_12.patch` | `write(/proc/self/attr/*)`, `lsm_set_self_attr(2)` and - on the `_6_12` variant only - `setxattr(security.selinux)` returning EACCES (type exists) instead of EINVAL (type absent) |
| `hide_selinux_selinuxfs_5_10.patch` / `hide_selinux_selinuxfs_6_12.patch` | the same probe through every `selinuxfs` write node (`access`/`create`/`relabel`/`user`/`member`/`context`/`validatetrans`), plus a reply filter so a computed context never echoes a hidden type back |
| `quiet_selinux_audit.patch` / `_legacy.patch` | AVC denial records naming a root type, **at uid >= 2000 only** |
| `fix_selinux_seqno.patch` | `/sys/fs/selinux/status` reporting `policyload = 0` after KSU's runtime rules |

### Which variant applies where

Every cell was produced by `patch -p1 -F0 --dry-run` against the AOSP common
tree for that version **and** against the OnePlus tree the builder fleet pins
for it, and the object each one touches was compiled (`ARCH=arm64 LLVM=1`).

| family | 5.10 | 5.15 | 6.1 | 6.6 | 6.12 |
|---|---|---|---|---|---|
| `hide_selinux_selinuxfs_6_12.patch` | - | - | - | YES | YES |
| `hide_selinux_selinuxfs_5_10.patch` | YES | YES | YES | - | - |
| `hide_selinux_attr_6_12.patch` | - | - | - | - | YES |
| `hide_selinux_attr.patch` (fallback) | YES | YES | YES | YES | YES |
| `quiet_selinux_audit.patch` | YES | YES | YES | YES | YES |
| `quiet_selinux_audit_legacy.patch` | YES | YES | YES | YES | YES |

Three rows of that table are traps, and the builder handles all of them the same
way: it **pins the variant by kernel version and selects it by name**, rather
than taking the first that applies.

* The two `quiet_selinux_audit` files have *byte-identical* patch context on all
  five versions - the insertion point is a blank-line-delimited spot around
  `a->selinux_audit_data = &sad;` that never changed - and differ only in
  whether the added code passes `state` to `security_sid_to_context()`. Both
  dry-run clean everywhere; the wrong one fails at compile time.
* `hide_selinux_attr.patch` also applies on 6.12, where `_6_12` must win because
  it additionally guards `selinux_inode_setxattr()`.

### Deleted, and why

* **`hide_selinux_selinuxfs.patch`** (the old base variant). It hooked
  `selinux_transaction_write()`, the *generic dispatcher*, ahead of every
  handler's own `avc_has_perm()` - reproducing the "cloak becomes the detector"
  inversion described below - and it matched with `strnstr()` over the whole
  raw write buffer while the handlers parse with fixed-arity `sscanf()` and
  ignore trailing junk. Appending `:ksu:` after the four fields returned EINVAL
  where `:kzu:` succeeded; a stock kernel answers OK uniformly to every
  trailing-junk variant, measured. It also had no reply filter, and it never
  covered `validatetrans` (which has its own `file_operations` and does not go
  through the dispatcher at all). Its replacement,
  `hide_selinux_selinuxfs_5_10.patch`, is the `_6_12` design refitted down.
* **`quiet_selinux_audit_user.patch`**. The same ungated raw-buffer shape in
  `audit_receive_msg()`, on a path already behind `CAP_AUDIT_WRITE` - so it
  cloaked a record class only a privileged caller could generate in the first
  place - and it was the fourth place the hardcoded type list had to be kept in
  step. Dropping it takes the list from four copies to three.

## The oracle these close

Writing a context to `/proc/self/attr/current` answers differently depending on
whether the *type* exists in the loaded policy:

* **EINVAL** — `security_context_to_sid()` failed, the type is unknown. This is
  what a stock kernel says for `u:r:ksu:s0`.
* **EACCES / success** — the type resolved, so it exists. Which means the kernel
  is rooted, with no further probing needed.

The patches force EINVAL for the root-framework types, making them
indistinguishable from types that were never in the policy.

## Checking coverage on a device

**The covered type list is hardcoded and still lives in more than one place.**
It reads `:ksu:`, `:ksu_file:`, `:lsposed_file:`, `:zygisk_file:`. Within
`selinuxfs.c` it is centralized in `sel_ctx_hidden()` / `sel_hidden_bytes()`,
which every write node and the reply filter call, so all eight selinuxfs sites
share one list. Two copies remain — `security/selinux/hooks.c`
(`selinux_setprocattr` / `selinux_lsm_setattr` and `selinux_inode_setxattr`) and
`security/selinux/avc.c` (`slow_avc_audit`) — because they patch different
source files, at different kernel versions, and a shared header would have to be
installed and included by all of them (too invasive for the patch form). Each of
those sites carries a comment pointing at the others; adding a type means editing
all three. It was four until `quiet_selinux_audit_user.patch` was deleted. A
setup that adds a type those strings do not name (Magisk, APatch, a
differently-named hook framework) leaves the oracle open for it, and nothing
fails a build to say so.

Three placement rules the guards now follow, and any new site must too:

* **After the stock `avc_has_perm`, never before it.** The guard returns
  `-EINVAL`, but a domain that lacks the permission (isolated_app, sdk_sandbox)
  gets `-EACCES` from stock for *any* string. A guard placed at function or
  dispatch entry would answer EINVAL-for-hidden but EACCES-for-garbage from those
  domains — making the cloak itself the detector. Placed after the perm check and
  immediately before `security_context_to_sid()`, a hidden type is
  indistinguishable from an absent one for every caller.
* **The two attr patches are NOT identical, and must not be assumed so.**
  `hide_selinux_attr_6_12.patch` guards `selinux_lsm_setattr` (which
  `lsm_set_self_attr(2)` reaches directly) *and* `selinux_inode_setxattr`; its
  hunks are fitted to the 6.6+ signatures (`struct mnt_idmap *`), so it fails
  dry-run on 5.10/5.15/6.1. `hide_selinux_attr.patch` is the fallback for those
  and guards `selinux_setprocattr` only — **`setxattr(security.selinux)` is
  therefore uncovered on 5.10/5.15/6.1.** Do not read the coverage table above as
  applying to the fallback.

  History worth keeping: the fallback shipped for a while with its guard at
  *function entry*, ahead of the `PROCESS__SETCURRENT` check — breaking the first
  rule above and inverting the cloak into a one-syscall root oracle on those three
  kernel versions (EINVAL for a hidden type, EACCES for anything else, from an
  unprivileged app, via its own `/proc/self/attr/current`). It now lands after the
  perm check and immediately before `security_context_to_sid()`.

  A second, quieter version of the same problem lived in how it was *applied*.
  The hunk carried three lines of leading context and one of trailing, so GNU
  `patch` reported **fuzz 2** on every tree in the fleet - and fuzz 2 against one
  trailing line means the guard was being placed by line number, in the function
  where that matters most. The earlier note here claiming `git apply` accepted it
  at zero fuzz was wrong; measured, it did not. The context is now balanced at
  3/3 and the hunk header names the function, so it applies at `-F0` on 5.10,
  5.15, 6.1, 6.6 and 6.12 - AOSP common and the pinned OnePlus trees alike - and
  `security/selinux/hooks.o` compiles clean on all five.

  The builder's `apply_first_of` selects `_6_12` **by name** on 6.12; every other
  version takes the fallback. The fallback also applies cleanly on 6.12, which is
  precisely why selection is by name and not by "first that applies".

* **Match the PARSED field, never the raw write buffer.** Every gate now runs on
  a NUL-terminated context the handler has already parsed, or - for the reply
  filter, whose buffer is kernel-generated and carries embedded NULs from
  `sel_write_user()` - on an explicitly length-bounded scan of that reply. The
  attr guards bound their scan with `strnlen(value, size)` for the same reason.

  This is not a style rule. Handlers parse with fixed-arity `sscanf()` and ignore
  everything after the last field, and `security_context_to_sid()` stops at the
  first NUL. A gate over the raw buffer therefore rejects
  `"<well-formed query> :ksu:"` and `"<valid ctx>\0:ksu:"` where stock accepts
  both, while the same junk spelled `:kzu:` is accepted on both - a
  discrimination stock cannot make, reachable by appending seven bytes. Measured:
  on a stock kernel every trailing-junk variant answers OK uniformly. It is the
  same inversion as a misplaced guard, arriving through the *length argument*
  rather than through placement, and it is what got the old base selinuxfs
  variant deleted.

Verify on the target rather than assume. Run as a **non-root uid** (the gate is
`uid >= 2000`), and use `dd` rather than `echo` — toybox `echo` does not check
the `write()` return, so every probe looks like it succeeded:

```sh
probe() {
  r=$(printf "%s" "$1" | dd of=/proc/self/attr/current bs=64 count=1 2>&1 >/dev/null)
  case "$r" in
    *"Invalid argument"*)  v="EINVAL  (stock-looking)";;
    *"Permission denied"*) v="EACCES  <-- LEAK: type exists";;
    *records*)             v="WROTE OK";;
    *) v="[$r]";;
  esac
  printf "  %-34s %s\n" "$1" "$v"
}
for c in u:r:ksu:s0 u:object_r:ksu_file:s0 \
         u:object_r:lsposed_file:s0 u:object_r:zygisk_file:s0 \
         u:r:magisk:s0 u:r:definitely_not_a_type_xyz:s0; do probe "$c"; done
```

Invoke it with `su 2000 -c 'sh probe.sh'`.

Every covered type must answer **exactly the same** as
`definitely_not_a_type_xyz`. If one answers differently, that type is a live
oracle and belongs in all three copies of the list (selinuxfs.c, hooks.c, avc.c).

To find what a given device actually has, list the policy's types and look for
ones a stock build would not carry — note `strings` defaults to 4 characters and
will silently drop `ksu`:

```sh
strings -n 3 /sys/fs/selinux/policy | sort -u | grep -iE 'ksu|magisk|apatch|zygisk|lsposed|susfs'
```

Measured on OP15 / ReSukiSU (2026-08-21): the policy carries exactly `ksu`,
`ksu_file`, `lsposed_file` and `zygisk_file`, so the hardcoded list is complete
**for that device**. All four probe as EINVAL, identical to an absent type.

## `fix_selinux_seqno` — the trade it makes

It drops `selinux_status_update_policyload()` from KSU's runtime rule path, so
the `/sys/fs/selinux/status` mmap page keeps the values a stock boot produces.

Get the mechanism right, because the earlier description here had it backwards.
`selinux_status_update_policyload(seqno)` does **not** *bump* a policyload
counter — it **assigns** `status->policyload = seqno` (and bumps
`status->sequence` twice, once before and once after, so a concurrent reader can
detect the update). KSU calls it from its rule path with **`seqno == 0`**. So
the observable on an *unpatched* kernel is not "a higher load count" — it is
`policyload == 0`, a value the kernel only ever writes before the first policy
has loaded and which is therefore impossible on a running device, sitting next to
a `sequence` that has advanced past a stock boot's. Either half is a tell; the
pair together is unambiguous. Dropping the call leaves both stock.

Verified on OP15: `policyload = 1`, `sequence` matching one boot-time load, which
is what a single boot-time policy load looks like.

**Post-condition to assert** (in a device probe, not the build): read the status
page and require `policyload != 0 && policyload == avd.seqno`, where `avd.seqno`
is the sequence returned by a `/sys/fs/selinux/access` compute — i.e. the
policyload field must equal the *real* current policy sequence, never 0.

The cost: userspace AVC caches (libselinux) flush on that notification, so they
can hold a stale decision across a KSU policy change. Narrow in practice —
`avc_ss_reset()` is deliberately *kept*, so the kernel's own AVC still flushes;
only userspace-cached decisions are affected, and KSU installs its rules early in
boot, before most userspace caching matters.

**Closed, will not fix (was M-C2).** The patch still lets
`selnl_notify_policyload(0)` broadcast a policy-load event on `NETLINK_SELINUX`
that no stock device emits after boot — a second, netlink-side tell that mirrors
the status-page one this patch closes. It stays.

Receiving that broadcast requires a `netlink_selinux_socket`, and **no app domain
is allowed to create one.** Measured 2026-08-25 against the live OP15 policy, via
the `/sys/fs/selinux/access` compute_av node (class index 35, requested
`0xffffffff`):

| source domain | allowed |
| --- | --- |
| `untrusted_app` | `0` |
| `priv_app` | `0` |
| `isolated_app` | `0` |
| `platform_app` | `0` |
| `system_app` | `0` |

Zero for every one, platform- and system-signed included — so the only readers
are domains that have already won. Gating the call would trade a tell that no
app can observe for a documented bootloop risk, and the CI verifier in
`verify-hook-pathhide.yml` asserts `selnl_notify_policyload` survives precisely
to stop that being done casually. Re-open only with evidence of a reachable
listener, and update that CI assertion in the same change.

## Why the gate is `uid >= 2000` and must not be widened

Tested 2026-08-21 on OP15 (branch `hook/uid-gate-non-root`, kernel run
32506537161): changing all the gates from `uid >= 2000` to `uid != 0`, so that
system-uid callers are cloaked too. **It boots, it closes the oracle for
uid 1000-1999 -- and it costs every app its root grant.** Do not re-attempt.

The mechanism survives the selinuxfs refit unchanged. The guards no longer sit in
`selinux_transaction_write()` -- they sit in each handler, after its own
`avc_has_perm()` -- but one of those handlers is `sel_write_access()`, i.e.
`/sys/fs/selinux/access`, which is what libselinux's `selinux_check_access()`
writes to. Access checks are performed **by a proxy, on behalf of somebody
else**, so the outcome is identical:

```
ksud (uid 0, u:r:ksu:s0) asks servicemanager for the "package" service
  -> servicemanager (uid 1000) calls selinux_check_access("u:r:ksu:s0", ...)
     -> libselinux writes that string to /sys/fs/selinux/access
        -> string contains ":ksu:", caller is uid 1000, now cloaked -> -EINVAL
           -> libselinux reads the failure as a denial
              -> servicemanager refuses the lookup
```

Observed: `avc: denied { find } ... name=package scontext=u:r:ksu:s0
tcontext=u:object_r:package_service:s0 permissive=0`, from 8.17s of uptime,
repeating once a second indefinitely. ksud never builds the package->appid map,
so the allowlist is never applied and no app gets root. `.allowlist` on disk is
untouched -- reflashing a `>= 2000` kernel restores everything.

The tell is easy to misread: `adb` root still works, because uid-0 `su` does not
go through servicemanager. It looks like a userspace problem, not a kernel one.
The previous boot's `/data/adb/ksu/log/dmesg.old.log` had **0** of these denials;
same KernelSU driver 35088 both boots.

So the residual gap is real but narrow: an oracle at uid 1000-1999 needs an
attacker who **already holds a system uid** (platform-signed, or sharedUserId
android.uid.system). Every detector worth cloaking against runs at uid >= 10000
and is covered.

## The AVC-audit filter is uid-gated too, and that is a deliberate trade

`quiet_selinux_audit.patch` / `_legacy.patch` used to be the one pair here with
**no** uid gate: they deleted every AVC denial record naming a covered type, at
every uid. That is more than the job needs and it costs something specific.

The record they deleted is the one that diagnosed the incident above:
`avc: denied { find } ... name=package scontext=u:r:ksu:s0
tcontext=u:object_r:package_service:s0`, emitted by **servicemanager at uid
1000**, once a second from 8.17s of uptime, with the previous boot's
`dmesg.old.log` carrying zero of them. Without that line in the log the failure
reads as a userspace problem and the kernel change that caused it is invisible.

So the filter now fires at `uid >= 2000` and nowhere below, matching every other
site in this directory. An app-uid task's denial no longer names a root type; a
system- or root-uid task's denial still does. State the residual plainly: a
reader that can reach the kernel log can still see system-originated records
naming a covered type. That is the price of keeping the incident above
debuggable.

One caveat that is not obvious from the code: `avc_audit()` can run in **softirq**
for the network checks, where `current` is whatever task was interrupted, so the
gate is not meaningful for those. It is safe (`current` is never NULL), and root
frameworks do not generate network AVCs against their own types -- but do not
read a network denial's presence or absence as a signal. Note also that `setprocattr` alone could safely take `!= 0` --
it can only ever set the *caller's own* label, so nothing is proxied -- except
that a uid-1000 LSPosed daemon setting `attr/fscreate` to
`u:object_r:lsposed_file:s0` goes through the same string match. Not worth it.
