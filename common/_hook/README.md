# `_hook` — SELinux oracle cloak

Six patches that close SELinux-side oracles a detector uses to tell a rooted
kernel from a stock one. Applied by the NoMount kernel builders after the KSU
patches; each is fail-closed (`apply_or_die`).

| patch | closes |
|---|---|
| `hide_selinux_attr.patch` / `hide_selinux_attr_6_12.patch` | `write(/proc/self/attr/*)`, `lsm_set_self_attr(2)` and `setxattr(security.selinux)` returning EACCES (type exists) instead of EINVAL (type absent) |
| `hide_selinux_selinuxfs.patch` | the same probe through every `selinuxfs` write node (`access`/`create`/`relabel`/`user`/`member`/`context`/`validatetrans`), plus results that would echo a hidden type back |
| `quiet_selinux_audit.patch` / `_legacy.patch` | AVC denial records naming a root type |
| `quiet_selinux_audit_user.patch` | userspace-generated `AUDIT_USER_AVC` records naming one |
| `fix_selinux_seqno.patch` | `/sys/fs/selinux/status` policyload count bumped by KSU's runtime rules |

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
`selinuxfs.c` it is now centralized in a single `sel_ctx_hidden()` helper that
every write node calls, so the six selinuxfs sites share one list. But three
copies remain — `security/selinux/hooks.c` (`selinux_lsm_setattr` and
`selinux_inode_setxattr`), `security/selinux/avc.c` (`slow_avc_audit`) and
`kernel/audit.c` (`audit_receive_msg`) — because they patch different source
files, at different kernel versions, and a shared header would have to be
installed and included by all of them (too invasive for the patch form). Each of
those sites carries a comment pointing at the others; adding a type means editing
all four call sites. A setup that adds a type those strings do not name (Magisk,
APatch, a differently-named hook framework) leaves the oracle open for it, and
nothing fails a build to say so.

Two placement rules the guards now follow, and any new site must too:

* **After the stock `avc_has_perm`, never before it.** The guard returns
  `-EINVAL`, but a domain that lacks the permission (isolated_app, sdk_sandbox)
  gets `-EACCES` from stock for *any* string. A guard placed at function or
  dispatch entry would answer EINVAL-for-hidden but EACCES-for-garbage from those
  domains — making the cloak itself the detector. Placed after the perm check and
  immediately before `security_context_to_sid()`, a hidden type is
  indistinguishable from an absent one for every caller.
* **`hide_selinux_attr.patch` and `hide_selinux_attr_6_12.patch` are now
  identical**, both guarding `selinux_lsm_setattr` (which `lsm_set_self_attr(2)`
  reaches directly, bypassing the old `selinux_setprocattr`-only guard). The
  builder's `apply_first_of` picks one; whichever it picks lands the guard in the
  right place. They can be de-duplicated to a single patch once the builder's
  variant list is updated to match.

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
oracle and belongs in all four patches.

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
32506537161): changing all three gates from `uid >= 2000` to `uid != 0`, so that
system-uid callers are cloaked too. **It boots, it closes the oracle for
uid 1000-1999 -- and it costs every app its root grant.** Do not re-attempt.

`hide_selinux_selinuxfs.patch` hooks `selinux_transaction_write()`, the *generic*
dispatcher for every selinuxfs transaction file. That includes
`/sys/fs/selinux/access`, which is what libselinux's `selinux_check_access()`
writes to -- and access checks are performed **by a proxy, on behalf of somebody
else**:

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
and is covered. Note also that `setprocattr` alone could safely take `!= 0` --
it can only ever set the *caller's own* label, so nothing is proxied -- except
that a uid-1000 LSPosed daemon setting `attr/fscreate` to
`u:object_r:lsposed_file:s0` goes through the same string match. Not worth it.
