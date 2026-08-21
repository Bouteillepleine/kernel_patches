# `_hook` — SELinux oracle cloak

Six patches that close SELinux-side oracles a detector uses to tell a rooted
kernel from a stock one. Applied by the NoMount kernel builders after the KSU
patches; each is fail-closed (`apply_or_die`).

| patch | closes |
|---|---|
| `hide_selinux_attr.patch` / `hide_selinux_attr_6_12.patch` | `write(/proc/self/attr/*)` returning EACCES (type exists) instead of EINVAL (type absent) |
| `hide_selinux_selinuxfs.patch` | the same probe through `selinuxfs` transaction writes |
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

**The covered type list is hardcoded, in four separate patches.** It currently
reads `:ksu:`, `:ksu_file:`, `:lsposed_file:`, `:zygisk_file:`. A setup that adds
types those four strings do not name (Magisk, APatch, a differently-named hook
framework) leaves the oracle open for them, and nothing fails a build to say so.

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
`/sys/fs/selinux/status` keeps the policyload count a stock boot produces.
Verified on OP15: `policyload = 1`, which is what one boot-time policy load looks
like. Without it, every KSU rule batch bumps the counter and any process that
mmaps the status page sees more policy loads than a stock device ever performs.

The cost: userspace AVC caches (libselinux) flush on that notification, so they
can hold a stale decision across a KSU policy change. Narrow in practice —
`avc_ss_reset()` is deliberately *kept*, so the kernel's own AVC still flushes;
only userspace-cached decisions are affected, and KSU installs its rules early in
boot, before most userspace caching matters.
