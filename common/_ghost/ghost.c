// SPDX-License-Identifier: GPL-2.0
/*
 * ghost - make a NoMount-injected path look ABSENT, not merely inaccessible,
 *	   to a uid the engine hides it from.
 *
 * NoMount injects files into read-only ROM partitions by hijacking per-inode
 * inode_operations/file_operations, and hides them per-uid: for a blocked uid
 * every op it controls answers -ENOENT, so the partition looks stock.
 *
 * A syscall that resolves a path and then acts WITHOUT consulting a hijacked op
 * escapes that, and there are four distinct orderings by which it happens. This
 * file supplies the predicate all of them key on; the per-version
 * *_integration.patch files place the guards. Nine families ship:
 *
 *   1. the syscall never reaches a file-level op at all
 *        open(p, O_PATH) + readlink(/proc/self/fd/N)  -> hands back the path
 *        getxattr(p, "security.selinux")              -> hands back the label
 *        stat(p "/zzz") and the whole LOOKUP_DIRECTORY family -> ENOTDIR
 *        link(p, "/data/local/tmp/x")                 -> EXDEV
 *
 *   2. mnt_want_write() answers first, on a read-only ROM mount
 *        truncate(p, 0) / utimensat(p) / chmod(p) / chown(p)  -> EROFS
 *
 *   3. existence is decided ahead of the write check
 *        mkdirat/mknodat/symlinkat/linkat via filename_create()  -> EEXIST
 *        open(p, O_CREAT|O_EXCL) via do_open()                   -> EEXIST
 *
 *   4. sb_permission() short-circuits inode_permission() before
 *      do_inode_permission() ever dispatches to the engine
 *        access(p, W_OK) / open(p, O_WRONLY|O_RDWR|O_TRUNC)      -> EROFS
 *
 * Everything in 1 and the first three of 2 were measured on a live OP15
 * (Android 16, 6.12.23) against all 24 blocked uids, with a 7020-path
 * genuinely-absent control that produced zero false positives; 3 was measured
 * the same way at engine v26. Family 4 and the chown half of 2 were found by
 * reading fs/namei.c and fs/open.c rather than by probing -- see the headers of
 * ghost_access.patch, ghost_open.patch and ghost_chown.patch, which quote the
 * exact ordering in each.
 *
 * WHY THIS IS NOT THE ENGINE'S OWN PREDICATE
 * ------------------------------------------
 * The engine's nm_hidden_from_caller() lives in the nomount driver and is
 * reachable only from the hijacked ops. A core-VFS guard runs before any op
 * dispatch and cannot call it without making fs/namei.c and fs/xattr.c depend
 * on the engine -- which would stop these patches applying to a tree that does
 * not carry it, and would make the two patch sets non-independent. So this
 * file keeps its own copy of the decision, pushed down from userspace over the
 * same control plane _pathhide uses. It is a REPLICA, and everything below is
 * shaped by the consequences of that replica drifting.
 *
 * WHAT MAY BE PUT IN THE PATH TABLE -- READ THIS BEFORE CONFIGURING IT
 * -------------------------------------------------------------------
 * ONLY paths that exist *because* of injection and that the engine already
 * answers -ENOENT for. NEVER a path that also exists on the stock partition.
 *
 * NoMount does two different things: it ADDS new paths, and it OVERRIDES
 * existing ones. For an override, a blocked uid must see the STOCK file --
 * not nothing. Feeding an override path to this table makes a real, shipped
 * ROM file vanish for those uids, which is a functional regression the engine
 * would never produce on its own.
 *
 * The failure directions are deliberately asymmetric, and that asymmetry is
 * the safety argument for the whole design:
 *
 *   table MISSING an injected path  ->  the oracles stay open for it.
 *				       Exactly today's behaviour. Harmless.
 *   table HOLDING a non-hidden path ->  a file the uid is entitled to see
 *				       returns -ENOENT from open(O_PATH),
 *				       getxattr, listxattr, setxattr,
 *				       removexattr, link, access(W_OK),
 *				       open(O_WRONLY) and any lookup that
 *				       walks through it. Apps break.
 *
 * So this file fails OPEN on every internal error (no rules, no uids, d_path
 * failure, buffer exhaustion) and never fails closed.
 *
 * FAIL-OPEN CASE WORTH KNOWING: d_path() renders relative to the CALLER's root
 * and mount namespace. A hidden uid whose process lives in a different mount
 * namespace, or under a chroot, or below a bind-mounted view of the partition,
 * produces a path string that matches no rule, and every guard returns false
 * for it. The engine's own hiding is namespace-independent; this replica is
 * not. On Android that gap is theoretical -- app processes share init's mount
 * namespace -- but it is a real difference between the two, and it is the
 * reason a rule is an absolute path rather than a dev/ino pair.
 *
 * WHY EXACT MATCH, NOT pathhide's SUBSTRING MATCH
 * -----------------------------------------------
 * pathhide_match_file() takes substrings because a wrong match there only
 * omits a /proc/<pid>/maps line. A wrong match HERE returns -ENOENT to a
 * syscall. pathhide.c's own header records what substrings cost: measured
 * against system_server's 5442 file-backed mappings on OP15, the needle "lib"
 * matched 2270 of them and "/system/" matched 1638. The same needle here would
 * delete 30% of /system from 24 apps. Compare the OxC bootloop, where a single
 * `nm add /product` rule on a partition ROOT masked the overlays and took
 * SystemUI down with SIGABRT.
 *
 * Rules are therefore absolute, fully resolved paths, matched whole:
 *
 *	"/system/etc/foo.conf"	   matches exactly that path
 *	"/system/etc/foodir/"	   matches everything BELOW /system/etc/foodir
 *				   (trailing slash = subtree), but not the
 *				   directory itself -- add it separately if the
 *				   directory is itself injected
 *
 * ghost_rule_sane() additionally refuses anything that could plausibly be a
 * partition root; see it for the exact test. That check is a backstop for
 * operator error, not a security boundary.
 *
 * WHAT CONFIGURES IT
 * ------------------
 * Nothing in this patch set. Same arrangement, and same caveat, as _pathhide's
 * M-C8: the real control plane is nomount's private CAP_SYS_ADMIN raw-netlink
 * channel, which must forward NM_KNOB_GHOST -> ghost_ctl() and
 * NM_CMD_GET_GHOST -> ghost_get_rule() through WEAK externs. That forwarder is
 * supplied by the nomount engine repo, NOT by kernel_patches. A kernel built
 * from _ghost alone links and boots and matches correctly, but its tables stay
 * empty forever, so ghost_hidden_path() short-circuits to false on its first
 * line and every guard is dead code. That is a safe state, not a broken one --
 * it is exactly the unpatched kernel's behaviour.
 *
 * (The gate was CAP_NET_ADMIN until the engine moved it. One ADD_RULE redirects
 * any path on any ROM partition at any file, which is root-equivalent, and
 * CAP_NET_ADMIN is held on Android by domains that are not -- netd,
 * system_server. Nothing here checks capabilities itself, for the reason
 * ghost_ctl() gives, so this comment is the only place the current gate is
 * named: keep it in step with nomount.c's netlink_capable() call.)
 *
 * There is deliberately NO /proc node, not even an opt-in one. _pathhide
 * measured what such a node costs: on OP15 (2026-08-23), from a real app
 * domain, untrusted_app/app_zygote/priv_app all hold proc:dir read, so a plain
 * readdir of /proc listed the entry and announced the patch to anything that
 * looked. This file conceals the existence of files; owning a name in /proc
 * that no stock kernel has would defeat its own purpose more loudly than the
 * oracles it closes.
 */
/*
 * linux/kernel.h is what supplies kstrtou32() and scnprintf() on every version
 * in range: 5.10's kernel.h declares both directly, and 6.12's pulls them in
 * via <linux/kstrtox.h> and <linux/sprintf.h>. Do NOT include those two
 * directly -- kstrtox.h only exists from 5.19 and sprintf.h from 6.9, so a
 * direct include compiles on the newest tree and fails on the oldest. Same
 * class of mistake as pathhide.c's file_user_path() guard, which was set at 6.6
 * and had to be moved to 6.7.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include "ghost.h"

/* 256 was not enough for a real device. Measured on OP15 (2026-08-25): a
 * plain four-module setup produces 260 injection targets, so the boot sync
 * filled the table and the last 4 paths were rejected -- and a PARTIALLY
 * populated table is worse than an empty one, because some paths are cloaked
 * and others are not, which is itself a pattern. 512 costs 96 KiB of
 * always-resident .bss against 48 KiB, which is the price of the guarantee
 * that the table matches the rule set rather than a prefix of it.
 *
 * ghost_ctl() still returns -ENOSPC past the cap and the Suite still counts
 * and reports rejections, so overflowing this again is loud, not silent. */
#define GH_MAX_RULES	512
#define GH_RULE_LEN	192
#define GH_MAX_UIDS	128

static char ghost_rules[GH_MAX_RULES][GH_RULE_LEN];
/* Length of each rule, cached at insert time. ghost_path_locked() used to call
 * strlen() per rule per lookup: 512 strlen()s over 192-byte strings, inside the
 * lock AND with preemption disabled, on every guarded syscall a hidden uid
 * makes. The lengths never change while a rule is in the table, so computing
 * them once at insert turns the scan into a length compare plus a memcmp of
 * the few candidates that survive it. u8 is enough: ghost_rule_sane() refuses
 * anything at or past GH_RULE_LEN, so no stored length can exceed 191. */
static u8   ghost_rlen[GH_MAX_RULES];
static int  ghost_nrules;
static u32  ghost_uids[GH_MAX_UIDS];
static int  ghost_nuids;

/*
 * Plain spin_lock, NOT spin_lock_irqsave -- same reasoning as pathhide.c: no
 * caller is in interrupt or softirq context. ghost_hidden_path() runs off a
 * syscall, ghost_ctl()/ghost_get_rule() off a netlink command.
 *
 * Taken for the PATH scan only. The uid gate that runs first is lock-free (see
 * ghost_uid_hidden), so a call from a uid that is not hidden -- the
 * overwhelming majority on a device with 24 blocked uids out of a few hundred
 * running -- now touches no lock at all. It used to take this one twice: once
 * for the uid gate and once for the path scan, which made the "colder than
 * pathhide's lock by construction" claim in the previous version of this
 * comment false for exactly the calls it was claiming to be cheap.
 */
static DEFINE_SPINLOCK(ghost_lock);

/*
 * Preallocated per-CPU path buffers, for the reason pathhide.c gives: an
 * allocation here could only fail open, and a PATH_MAX kmalloc on a syscall
 * path is a cost with no upside. Costs PATH_MAX per CPU for the life of the
 * kernel.
 */
static DEFINE_PER_CPU(char [PATH_MAX], ghost_pathbuf);

/*
 * Lock-free, deliberately. The uid table is append-mostly and tiny, and every
 * way this can race is safe:
 *
 *   - an add appends the value and only then publishes the count, so a reader
 *     never sees a slot it has not been told about;
 *   - a delete overwrites the removed slot with the LAST entry and only then
 *     publishes the smaller count (swap-remove, not memmove), so every value a
 *     reader can observe is either a current member or one that was a member
 *     microseconds ago. It can never be an unrelated uid, which is the only
 *     outcome that would matter -- that would hide a path from a caller that
 *     was never on the list.
 *
 * A stale read in either direction is a race the caller could equally have won
 * or lost by arriving a microsecond earlier, and this file's whole error policy
 * is to fail open.
 */
static bool ghost_uid_hidden(u32 uid)
{
	int i, n = READ_ONCE(ghost_nuids);

	if (n > GH_MAX_UIDS)
		n = GH_MAX_UIDS;
	for (i = 0; i < n; i++)
		if (READ_ONCE(ghost_uids[i]) == uid)
			return true;
	return false;
}

/*
 * Callers hold ghost_lock. Whole-path match; a rule ending in '/' matches the
 * subtree strictly below it. Lengths come from ghost_rlen[], so the common case
 * (a rule of a different length) costs one compare and no memory traffic.
 */
static bool ghost_path_locked(const char *path, size_t plen)
{
	int i, n = ghost_nrules;

	for (i = 0; i < n; i++) {
		size_t rlen = ghost_rlen[i];

		if (!rlen)
			continue;
		if (ghost_rules[i][rlen - 1] == '/') {
			if (plen > rlen && !memcmp(path, ghost_rules[i], rlen))
				return true;
		} else if (plen == rlen && !memcmp(path, ghost_rules[i], rlen)) {
			return true;
		}
	}
	return false;
}

bool ghost_hidden_path(const struct path *path)
{
	char (*bufp)[PATH_MAX];
	char *p;
	bool hit;
	u32 uid;

	/*
	 * Ordered cheapest-first, and the first test is the one that makes this
	 * a no-op on a stock configuration: with either table empty there is
	 * nothing this file could possibly hide, so it never touches @path.
	 */
	if (!READ_ONCE(ghost_nrules) || !READ_ONCE(ghost_nuids))
		return false;
	if (!path || !path->dentry || !path->mnt)
		return false;

	/*
	 * The REAL uid, matching how the engine builds its hide list from
	 * package -> uid. Not euid: a setuid transition is not what is being
	 * cloaked here, and keying on euid would let a uid drop out of the
	 * hidden set by changing its effective identity.
	 *
	 * Rendering the path is the expensive half, so the uid gate goes first.
	 * On a live device that means every process that is NOT one of the
	 * hidden apps leaves this function without a d_path() call and without
	 * having taken a lock.
	 */
	uid = from_kuid(&init_user_ns, current_uid());
	if (!ghost_uid_hidden(uid))
		return false;

	hit = false;
	/* Disables preemption; d_path() and ghost_path_locked() never sleep. */
	bufp = get_cpu_ptr(&ghost_pathbuf);
	p = d_path(path, *bufp, PATH_MAX);
	if (!IS_ERR(p)) {
		size_t plen = strlen(p);

		spin_lock(&ghost_lock);
		hit = ghost_path_locked(p, plen);
		spin_unlock(&ghost_lock);
	}
	put_cpu_ptr(&ghost_pathbuf);

	return hit;
}

/*
 * Backstop against the failure mode described at the top of this file: a rule
 * broad enough to delete a working directory tree from 24 apps at once.
 *
 * Requires an absolute path, no empty components, and at least two '/' -- so
 * "/system/build.prop" is accepted and a bare partition root "/system",
 * "/vendor", "/product" is not. A subtree rule (trailing '/') needs three, so
 * "/system/etc/" is accepted and "/system/" is not.
 *
 * This does not and cannot decide whether a rule is CORRECT -- only userspace
 * knows which paths the engine actually hides. It only rejects the shapes whose
 * blast radius is a whole partition.
 *
 * Returns 0, or the errno to report. -ENAMETOOLONG and -EINVAL are kept
 * DISTINCT: a path longer than the table's slot is a rule userspace cannot
 * express here and has to hear about as such, where -EINVAL sends whoever reads
 * the Suite's rejection list looking for a typo that is not there.
 */
static int ghost_rule_sane(const char *s)
{
	size_t len = strlen(s);
	int slashes = 0;
	size_t i;

	if (len >= GH_RULE_LEN)
		return -ENAMETOOLONG;
	if (len < 6)
		return -EINVAL;
	if (s[0] != '/')
		return -EINVAL;
	for (i = 0; i < len; i++) {
		if (s[i] != '/')
			continue;
		slashes++;
		if (i + 1 < len && s[i + 1] == '/')
			return -EINVAL;	/* "//" -- not a resolved path */
	}
	if (s[len - 1] == '/')
		return slashes >= 3 ? 0 : -EINVAL;
	return slashes >= 2 ? 0 : -EINVAL;
}

/*
 * Callers hold ghost_lock. Returns 0 on success (or if already present) and
 * -ENOSPC when the table is full -- which the caller MUST propagate, for the
 * reason pathhide.c's ph_add_locked() spells out: reporting success from a full
 * table tells the operator a path is cloaked while it is still in plain view.
 */
static int ghost_add_path_locked(const char *s, size_t slen)
{
	int i;

	for (i = 0; i < ghost_nrules; i++)
		if (ghost_rlen[i] == slen && !memcmp(ghost_rules[i], s, slen))
			return 0;
	if (ghost_nrules >= GH_MAX_RULES)
		return -ENOSPC;
	memcpy(ghost_rules[ghost_nrules], s, slen);
	ghost_rules[ghost_nrules][slen] = '\0';
	ghost_rlen[ghost_nrules] = (u8)slen;
	WRITE_ONCE(ghost_nrules, ghost_nrules + 1);
	return 0;
}

/* Callers hold ghost_lock. -ENOENT when there was no such rule; propagate it. */
static int ghost_del_path_locked(const char *s)
{
	size_t slen = strlen(s);
	int i, n = ghost_nrules;

	for (i = 0; i < n; i++) {
		if (ghost_rlen[i] == slen && !memcmp(ghost_rules[i], s, slen)) {
			memmove(&ghost_rules[i], &ghost_rules[i + 1],
				(n - i - 1) * GH_RULE_LEN);
			memmove(&ghost_rlen[i], &ghost_rlen[i + 1],
				(n - i - 1) * sizeof(ghost_rlen[0]));
			WRITE_ONCE(ghost_nrules, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

/* Callers hold ghost_lock. */
static int ghost_add_uid_locked(u32 uid)
{
	if (ghost_uid_hidden(uid))
		return 0;
	if (ghost_nuids >= GH_MAX_UIDS)
		return -ENOSPC;
	/* Value first, count second: a lock-free reader must never be told
	 * about a slot before the slot holds the value. */
	WRITE_ONCE(ghost_uids[ghost_nuids], uid);
	smp_wmb();
	WRITE_ONCE(ghost_nuids, ghost_nuids + 1);
	return 0;
}

/*
 * Callers hold ghost_lock. Swap-remove, not memmove: a lock-free reader may
 * observe the array mid-update, and moving the LAST entry into the hole means
 * every value it can see is a real member (current or just-removed) rather
 * than a half-shifted neighbour. Order in this table carries no meaning --
 * ghost_get_rule() enumerates it, and the Suite sorts what it gets.
 */
static int ghost_del_uid_locked(u32 uid)
{
	int i, n = ghost_nuids;

	for (i = 0; i < n; i++) {
		if (ghost_uids[i] == uid) {
			WRITE_ONCE(ghost_uids[i], ghost_uids[n - 1]);
			smp_wmb();
			WRITE_ONCE(ghost_nuids, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

/*
 * Pull the next '\n'/'\r'-delimited token out of [*pp, end) into @out, which
 * must be GH_RULE_LEN bytes. Returns the token length, 0 when there are no more
 * tokens, or -ENAMETOOLONG for a token that cannot fit a rule slot.
 *
 * Empty tokens are skipped, so a trailing newline, CRLF line endings and a
 * blank line in the middle of a batch all behave.
 */
static int ghost_next_token(const char **pp, const char *end, char *out)
{
	const char *p = *pp, *s;
	size_t len;

	for (;;) {
		while (p < end && (*p == '\n' || *p == '\r'))
			p++;
		if (p >= end) {
			*pp = p;
			return 0;
		}
		s = p;
		while (p < end && *p != '\n' && *p != '\r')
			p++;
		len = p - s;
		if (!len)
			continue;
		*pp = p;
		if (len >= GH_RULE_LEN)
			return -ENAMETOOLONG;
		memcpy(out, s, len);
		out[len] = '\0';
		return len;
	}
}

/*
 * Apply one control command. This is the whole control surface.
 *
 * @buf need NOT be NUL-terminated -- tokens are copied out of it one at a time,
 * which is what lets a netlink attribute payload be passed straight through
 * without the caller staging its own buffer, and without this function ever
 * putting a payload-sized array on the kernel stack.
 *
 *   "p+<path>"      add one path rule
 *   "p+<p1>\n<p2>…" add several, in one command
 *   "p=<p1>\n<p2>…" REPLACE the whole path table with exactly these
 *   "p~<path>"      remove one path rule
 *   "p-"            clear every path rule
 *   "u+10234"       add a hidden uid (also accepts a newline-separated list)
 *   "u=10234\n…"    replace the whole uid table
 *   "u~10234"       remove one
 *   "u-"            clear every hidden uid
 *
 * WHY '=' EXISTS. A resync used to be `p-` followed by one netlink command per
 * path -- on a measured 260-rule device, 260 round trips during which the table
 * held a PREFIX of the rule set. A prefix is the state this file's own comments
 * call worse than an empty table: some paths cloaked and others not is a
 * pattern of its own. '=' does the clear and the whole fill under ONE
 * acquisition of ghost_lock, so no reader can observe an intermediate table.
 *
 * Residual, stated plainly: a rule set too large for one netlink payload has to
 * arrive as '=' followed by '+' chunks, and the table holds a prefix between
 * them. That window is two or three commands wide instead of hundreds, and the
 * Suite sends the largest chunks the payload allows -- a real 260-rule set fits
 * in one. Eliminating it entirely needs a staging table, i.e. a second 96 KiB
 * of .bss, which is not worth it for the multi-chunk case alone.
 *
 * Deliberately does NOT check capabilities, for the reason pathhide_ctl() gives:
 * the only caller is already behind CAP_SYS_ADMIN, and a second, different check
 * here would make the two paths disagree about who may configure this.
 *
 * Returns 0, or a negative errno the caller MUST propagate. In a batch the
 * FIRST failure is reported and the remaining tokens are still applied, so one
 * over-long path in a list of 300 does not silently drop the other 299 -- the
 * caller learns something was refused and `nm l g` says what landed.
 */
int ghost_ctl(const char *buf, size_t count)
{
	char line[GH_RULE_LEN];
	const char *p, *end = buf + count;
	int ret = 0, first_err = 0, len, ntok = 0;
	bool replace;
	char op, mode;
	u32 uid;

	if (count < 2)
		return -EINVAL;
	op = buf[0];
	mode = buf[1];
	if (op != 'p' && op != 'u')
		return -EINVAL;

	if (mode == '-') {
		/* Nothing but trailing line endings may follow a clear. */
		for (p = buf + 2; p < end; p++)
			if (*p != '\n' && *p != '\r')
				return -EINVAL;
		spin_lock(&ghost_lock);
		if (op == 'p')
			WRITE_ONCE(ghost_nrules, 0);
		else
			WRITE_ONCE(ghost_nuids, 0);
		spin_unlock(&ghost_lock);
		return 0;
	}
	if (mode != '+' && mode != '~' && mode != '=')
		return -EINVAL;
	replace = (mode == '=');
	if (replace && op != 'p' && op != 'u')
		return -EINVAL;

	p = buf + 2;

	/*
	 * Pass one: validate every token BEFORE taking the lock, so a '='
	 * cannot clear the table and then discover it has nothing legal to put
	 * back. A batch that does not validate is refused whole and changes
	 * nothing -- which is the only behaviour that makes '=' safe to use as
	 * the resync primitive it exists to be.
	 */
	if (replace) {
		const char *scan = p;

		while ((len = ghost_next_token(&scan, end, line)) != 0) {
			if (len < 0)
				return len;
			if (op == 'p') {
				ret = ghost_rule_sane(line);
				if (ret)
					return ret;
			} else {
				if (kstrtou32(line, 10, &uid) || uid == 0)
					return -EINVAL;
			}
		}
	}

	spin_lock(&ghost_lock);
	if (replace) {
		if (op == 'p')
			WRITE_ONCE(ghost_nrules, 0);
		else
			WRITE_ONCE(ghost_nuids, 0);
	}
	while ((len = ghost_next_token(&p, end, line)) != 0) {
		if (len < 0) {
			if (!first_err)
				first_err = len;
			continue;
		}
		if (op == 'p') {
			ret = ghost_rule_sane(line);
			if (!ret) {
				if (mode == '~')
					ret = ghost_del_path_locked(line);
				else
					ret = ghost_add_path_locked(line, len);
			}
		} else {
			/*
			 * uid 0 is never hidden from. Root is the engine's own
			 * identity (ksud, the nm client, every module script);
			 * ghosting a path from root would break the thing doing
			 * the injecting, and no detector worth cloaking against
			 * runs as root anyway.
			 */
			if (kstrtou32(line, 10, &uid) || uid == 0)
				ret = -EINVAL;
			else if (mode == '~')
				ret = ghost_del_uid_locked(uid);
			else
				ret = ghost_add_uid_locked(uid);
		}
		if (ret && !first_err)
			first_err = ret;
		ntok++;
	}
	spin_unlock(&ghost_lock);

	/* An empty operand list is a caller bug, not a no-op to be reported as
	 * success: `nm k g p+` with nothing after it, or with nothing but line
	 * endings after it, used to return 0 and change nothing. */
	if (!first_err && !ntok)
		return -EINVAL;
	return first_err;
}

/*
 * Copy entry @idx into @out as "p /abs/path" or "u 10234". Returns its length,
 * or 0 once @idx is past the end -- which is how a caller iterating from 0
 * knows to stop. Path rules come first, then uids.
 *
 * One entry per call rather than a bulk copy so a netlink dump can allocate and
 * emit each attribute with ghost_lock DROPPED; nlmsg_put() and friends must not
 * run under a spinlock.
 */
int ghost_get_rule(int idx, char *out, size_t outsz)
{
	int len = 0;

	if (!out || outsz < GH_RULE_LEN + 4 || idx < 0)
		return -EINVAL;

	spin_lock(&ghost_lock);
	if (idx < ghost_nrules) {
		len = scnprintf(out, outsz, "p %s", ghost_rules[idx]);
	} else {
		idx -= ghost_nrules;
		if (idx < ghost_nuids)
			len = scnprintf(out, outsz, "u %u", ghost_uids[idx]);
	}
	spin_unlock(&ghost_lock);
	return len;
}
