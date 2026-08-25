// SPDX-License-Identifier: GPL-2.0
/*
 * ghost - make a NoMount-injected path look ABSENT, not merely inaccessible,
 *	   to a uid the engine hides it from.
 *
 * NoMount injects files into read-only ROM partitions by hijacking per-inode
 * inode_operations/file_operations, and hides them per-uid: for a blocked uid
 * every op it controls answers -ENOENT, so the partition looks stock.
 *
 * Four VFS surfaces have no filesystem op to hijack, so the engine cannot
 * answer them and a hidden path stays distinguishable from an absent one:
 *
 *   open(p, O_PATH) + readlink(/proc/self/fd/N)   hands back the full path
 *   getxattr(p, "security.selinux")               hands back the label
 *   stat(p "/zzz")                                -ENOTDIR, not -ENOENT
 *   link(p, "/data/local/tmp/x")                  -EXDEV,   not -ENOENT
 *
 * All four were measured on a live OP15 (Android 16, 6.12.23) against all 24
 * blocked uids, with a 7020-path genuinely-absent control that produced zero
 * false positives. This file supplies the predicate the four guards key on;
 * the per-version *_integration.patch files place the guards.
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
 *   table MISSING an injected path  ->  the four oracles stay open for it.
 *				       Exactly today's behaviour. Harmless.
 *   table HOLDING a non-hidden path ->  a file the uid is entitled to see
 *				       returns -ENOENT from open(O_PATH),
 *				       getxattr, listxattr, setxattr,
 *				       removexattr, link and any lookup that
 *				       walks through it. Apps break.
 *
 * So this file fails OPEN on every internal error (no rules, no uids, d_path
 * failure, buffer exhaustion) and never fails closed.
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
 * M-C8: the real control plane is nomount's private CAP_NET_ADMIN raw-netlink
 * channel, which must forward NM_KNOB_GHOST -> ghost_ctl() and
 * NM_CMD_GET_GHOST -> ghost_get_rule() through WEAK externs. That forwarder is
 * supplied by the nomount engine repo, NOT by kernel_patches. A kernel built
 * from _ghost alone links and boots and matches correctly, but its tables stay
 * empty forever, so ghost_hidden_path() short-circuits to false on its first
 * line and every guard is dead code. That is a safe state, not a broken one --
 * it is exactly the unpatched kernel's behaviour.
 *
 * There is deliberately NO /proc node, not even an opt-in one. _pathhide
 * measured what such a node costs: on OP15 (2026-08-23), from a real app
 * domain, untrusted_app/app_zygote/priv_app all hold proc:dir read, so a plain
 * readdir of /proc listed the entry and announced the patch to anything that
 * looked. This file conceals the existence of files; owning a name in /proc
 * that no stock kernel has would defeat its own purpose more loudly than the
 * four oracles it closes.
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
#include "ghost.h"

#define GH_MAX_RULES	256
#define GH_RULE_LEN	192
#define GH_MAX_UIDS	128

static char ghost_rules[GH_MAX_RULES][GH_RULE_LEN];
static int  ghost_nrules;
static u32  ghost_uids[GH_MAX_UIDS];
static int  ghost_nuids;

/*
 * Plain spin_lock, NOT spin_lock_irqsave -- same reasoning as pathhide.c: no
 * caller is in interrupt or softirq context. ghost_hidden_path() runs off a
 * syscall, ghost_ctl()/ghost_get_rule() off a netlink command.
 *
 * Colder than pathhide's lock by construction. pathhide takes its lock once
 * per VMA (~5400 acquisitions to read one /proc/<pid>/maps). This one is taken
 * at most twice per open(O_PATH), *xattr(2), link(2), or -ENOTDIR-returning
 * lookup, and only after the uid gate has already passed -- so on a device with
 * 24 blocked uids out of a few hundred running, the overwhelming majority of
 * calls return false without ever reaching the second acquisition.
 */
static DEFINE_SPINLOCK(ghost_lock);

/*
 * Preallocated per-CPU path buffers, for the reason pathhide.c gives: an
 * allocation here could only fail open, and a PATH_MAX kmalloc on a syscall
 * path is a cost with no upside. Costs PATH_MAX per CPU for the life of the
 * kernel.
 */
static DEFINE_PER_CPU(char [PATH_MAX], ghost_pathbuf);

/* Callers hold ghost_lock. */
static bool ghost_uid_locked(u32 uid)
{
	int i;

	for (i = 0; i < ghost_nuids; i++)
		if (ghost_uids[i] == uid)
			return true;
	return false;
}

/*
 * Callers hold ghost_lock. Whole-path match; a rule ending in '/' matches the
 * subtree strictly below it.
 */
static bool ghost_path_locked(const char *path, size_t plen)
{
	int i;

	for (i = 0; i < ghost_nrules; i++) {
		const char *r = ghost_rules[i];
		size_t rlen = strlen(r);

		if (!rlen)
			continue;
		if (r[rlen - 1] == '/') {
			if (plen > rlen && !memcmp(path, r, rlen))
				return true;
		} else if (plen == rlen && !memcmp(path, r, rlen)) {
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
	 * hidden apps leaves this function without a d_path() call.
	 */
	uid = from_kuid(&init_user_ns, current_uid());
	spin_lock(&ghost_lock);
	hit = ghost_uid_locked(uid);
	spin_unlock(&ghost_lock);
	if (!hit)
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
 */
static bool ghost_rule_sane(const char *s)
{
	size_t len = strlen(s);
	int slashes = 0;
	size_t i;

	if (len < 6 || len >= GH_RULE_LEN)
		return false;
	if (s[0] != '/')
		return false;
	for (i = 0; i < len; i++) {
		if (s[i] != '/')
			continue;
		slashes++;
		if (i + 1 < len && s[i + 1] == '/')
			return false;	/* "//" -- not a resolved path */
	}
	if (s[len - 1] == '/')
		return slashes >= 3;
	return slashes >= 2;
}

/*
 * Callers hold ghost_lock. Returns 0 on success (or if already present) and
 * -ENOSPC when the table is full -- which the caller MUST propagate, for the
 * reason pathhide.c's ph_add_locked() spells out: reporting success from a full
 * table tells the operator a path is cloaked while it is still in plain view.
 */
static int ghost_add_path_locked(const char *s)
{
	int i;

	for (i = 0; i < ghost_nrules; i++)
		if (!strcmp(ghost_rules[i], s))
			return 0;
	if (ghost_nrules >= GH_MAX_RULES)
		return -ENOSPC;
	strscpy(ghost_rules[ghost_nrules], s, GH_RULE_LEN);
	WRITE_ONCE(ghost_nrules, ghost_nrules + 1);
	return 0;
}

/* Callers hold ghost_lock. -ENOENT when there was no such rule; propagate it. */
static int ghost_del_path_locked(const char *s)
{
	int i, n = ghost_nrules;

	for (i = 0; i < n; i++) {
		if (!strcmp(ghost_rules[i], s)) {
			memmove(&ghost_rules[i], &ghost_rules[i + 1],
				(n - i - 1) * GH_RULE_LEN);
			WRITE_ONCE(ghost_nrules, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

/* Callers hold ghost_lock. */
static int ghost_add_uid_locked(u32 uid)
{
	if (ghost_uid_locked(uid))
		return 0;
	if (ghost_nuids >= GH_MAX_UIDS)
		return -ENOSPC;
	ghost_uids[ghost_nuids] = uid;
	WRITE_ONCE(ghost_nuids, ghost_nuids + 1);
	return 0;
}

/* Callers hold ghost_lock. */
static int ghost_del_uid_locked(u32 uid)
{
	int i, n = ghost_nuids;

	for (i = 0; i < n; i++) {
		if (ghost_uids[i] == uid) {
			memmove(&ghost_uids[i], &ghost_uids[i + 1],
				(n - i - 1) * sizeof(ghost_uids[0]));
			WRITE_ONCE(ghost_nuids, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

/*
 * Apply one control command. This is the whole control surface.
 *
 * @buf need NOT be NUL-terminated -- it is copied and terminated here, which is
 * what lets a netlink attribute payload be passed straight through without the
 * caller staging its own buffer.
 *
 * Deliberately does NOT check capabilities, for the reason pathhide_ctl() gives:
 * the only caller is already behind CAP_NET_ADMIN, and a second, different check
 * here would make the two paths disagree about who may configure this.
 *
 * Returns 0, or a negative errno the caller MUST propagate.
 */
int ghost_ctl(const char *buf, size_t count)
{
	char line[GH_RULE_LEN + 4];
	const char *s;
	size_t n = count;
	int ret;
	u32 uid;

	if (n == 0)
		return -EINVAL;
	if (n > GH_RULE_LEN + 2)
		return -ENAMETOOLONG;
	memcpy(line, buf, n);
	line[n] = '\0';
	while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	if (n < 2)
		return -EINVAL;

	s = line + 2;

	if (line[0] == 'p') {
		if (line[1] == '-' && line[2] == '\0') {
			spin_lock(&ghost_lock);
			WRITE_ONCE(ghost_nrules, 0);
			spin_unlock(&ghost_lock);
			return 0;
		}
		if (line[1] != '+' && line[1] != '~')
			return -EINVAL;
		if (!ghost_rule_sane(s))
			return -EINVAL;
		spin_lock(&ghost_lock);
		if (line[1] == '~')
			ret = ghost_del_path_locked(s);
		else
			ret = ghost_add_path_locked(s);
		spin_unlock(&ghost_lock);
		return ret;
	}

	if (line[0] == 'u') {
		if (line[1] == '-' && line[2] == '\0') {
			spin_lock(&ghost_lock);
			WRITE_ONCE(ghost_nuids, 0);
			spin_unlock(&ghost_lock);
			return 0;
		}
		if (line[1] != '+' && line[1] != '~')
			return -EINVAL;
		if (kstrtou32(s, 10, &uid))
			return -EINVAL;
		/*
		 * uid 0 is never hidden from. Root is the engine's own identity
		 * (ksud, the nm client, every module script); ghosting a path
		 * from root would break the thing doing the injecting, and no
		 * detector worth cloaking against runs as root anyway.
		 */
		if (uid == 0)
			return -EINVAL;
		spin_lock(&ghost_lock);
		if (line[1] == '~')
			ret = ghost_del_uid_locked(uid);
		else
			ret = ghost_add_uid_locked(uid);
		spin_unlock(&ghost_lock);
		return ret;
	}

	return -EINVAL;
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
