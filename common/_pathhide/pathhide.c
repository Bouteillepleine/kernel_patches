// SPDX-License-Identifier: GPL-2.0
/*
 * pathhide - omit selected file-backed entries from /proc/<pid>/maps,
 * /proc/<pid>/smaps, /proc/<pid>/map_files and /proc/<pid>/fd.
 *
 * Rules are plain substrings matched against the resolved d_path of a VMA's
 * or fd's backing file. The control plane is nomount's private raw-netlink
 * channel, driven by the bundled `nm` client:
 *
 *     nm k p '+io.github.chsbuffer.revancedxposed'   # add rule
 *     nm k p '+/data/adb/lspd'                       # add
 *     nm k p '~/data/adb/lspd'                       # remove one
 *     nm k p '-'                                     # clear all
 *     nm l p                                         # list rules
 *
 * That channel is CAP_NET_ADMIN-gated, is not enumerable, and creates no dirent
 * anywhere -- see the stealth notes below for why this file no longer owns a
 * /proc node. nomount.c forwards NM_KNOB_PATHHIDE to pathhide_ctl() and
 * NM_CMD_GET_PATHHIDE to pathhide_get_rule(), both through WEAK symbols, so the
 * two patch sets still apply independently: a kernel with nomount but without
 * pathhide answers -EINVAL on the knob, and a kernel with pathhide but without
 * nomount still matches (it just has no way to be configured unless the
 * PH_ENABLE_PROC fallback below is compiled in).
 *
 * Rules are substrings of the *full* path, so prefer specific needles
 * (a package id or an absolute prefix) over short tokens that could match
 * unrelated paths. This is a genuine footgun, not a style note -- measured
 * against system_server's 5442 file-backed mappings on OP15:
 *
 *     "com.strawing.duckusb"  ->     0 hidden   (a package id: exact)
 *     "base.apk"              ->   665 hidden   (12%)
 *     "/system/"              ->  1638 hidden   (30%)
 *     "lib"                   ->  2270 hidden   (42%)
 *     "com"                   ->  2271 hidden   (42%)
 *
 * Nothing here rejects a rule for being too broad, and the same needle also
 * removes entries from /proc/<pid>/fd, where a vanished fd can confuse anything
 * that enumerates them. A sloppy rule therefore degrades the whole system in a
 * way that is very hard to attribute back to this file. Keep needles specific.
 *
 * Inert until the first rule is added (pathhide_match_file() short-circuits on
 * an empty rule set), so it is a no-op on stock configurations.
 *
 * Stealth notes -- READ THESE BEFORE RELYING ON THEM:
 *   - There is NO /proc node by default. It used to be created unconditionally
 *     and was the loudest thing this file did: a stock kernel has no such entry,
 *     so `ls /proc` found it with no permission at all, and the module announced
 *     "a path-hiding patch is installed" while concealing seven package names.
 *     Measured on OP15 (2026-08-23), and measured from a REAL app domain rather
 *     than a root shell, because `su <uid> -c` runs in the ksu domain and gives
 *     the wrong answer:
 *         untrusted_app / app_zygote / priv_app -> proc:dir  INCLUDES read
 *             => readdir of /proc lists the entry. This was the tell.
 *         untrusted_app / app_zygote / priv_app -> proc:file == 0
 *             => stat() and open() on it are refused by SELinux, so the earlier
 *                note here claiming "stat() by name still succeeds" was only
 *                ever true for shell/ksu, never for an app.
 *   - Two further claims in the previous version of this comment were simply
 *     wrong about the code beneath it: it said the node was created 0666 and
 *     that ph_open()'s -ENOENT was therefore reachable. pathhide_init() created
 *     it 0600, so an unprivileged open() got EACCES from may_open() -- which
 *     confirms the file exists -- and ph_open() never ran. Verified on-device.
 *     Do not reintroduce a stealth claim without measuring it from an app
 *     domain first.
 *   - PH_ENABLE_PROC brings the node back for anyone applying this patch set
 *     WITHOUT nomount, who would otherwise have no way to configure it. It is
 *     opt-in precisely because it reintroduces the tell above: the builders do
 *     not define it. Renaming via PH_PROC_NAME makes the node less
 *     self-describing but no less present, so it is not a substitute.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/version.h>
#include "pathhide.h"

#ifndef PH_PROC_NAME
#define PH_PROC_NAME	"pathhide"
#endif

/*
 * Match on the path the kernel actually DISPLAYS. From 6.7 that is
 * file_user_path(), which diverges from f_path for FMODE_BACKING files (an
 * overlayfs upper backed by a lower) -- /proc/<pid>/maps, map_files and the fd
 * symlinks all render file_user_path(), so matching f_path there would let an
 * overlay-backed hook file slip past the very listing it is displayed in. Older
 * kernels have no user-path split, so f_path is the displayed path.
 *
 * 6.7, not 6.6: file_user_path() arrived with the backing-file series in 6.7.
 * Guarding at 6.6 made the 6.6 build treat it as an implicit int-returning
 * function and fail with "incompatible integer to pointer conversion" at the
 * d_path() call below (measured on the OnePlus android15-6.6 tree).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
#define PH_FILE_PATH(f)		file_user_path(f)
#else
#define PH_FILE_PATH(f)		(&(f)->f_path)
#endif

#define PH_MAX_RULES	64
#define PH_RULE_LEN	128

static char ph_rules[PH_MAX_RULES][PH_RULE_LEN];
static int  ph_nrules;
static DEFINE_SPINLOCK(ph_lock);

/*
 * Plain spin_lock, NOT spin_lock_irqsave.
 *
 * Nothing takes ph_lock from interrupt or softirq context -- every caller is
 * process context: pathhide_match_file() off a /proc read, pathhide_ctl() off a
 * netlink command, pathhide_get_rule() off a dump, ph_seq_show() off a /proc
 * read. Disabling interrupts bought nothing and was paid for on the hottest path
 * this file has: one call per VMA, so system_server's ~5400 file-backed mappings
 * mean ~5400 acquisitions to read /proc/<pid>/maps once, each holding the lock
 * across up to PH_MAX_RULES strstr() passes over a PATH_MAX string.
 *
 * Not converted to RCU. It would let readers run lock-free, which is the right
 * shape for a read-mostly set -- but it needs the rule array to become an
 * immutable, pointer-swapped object, and getting that wrong is a use-after-free
 * on a path every process hits. The scan is bounded (64 rules, short needles) and
 * the realistic set is under ten, so the win did not justify the risk here. If
 * this ever shows up in a profile, that is the change to make.
 */
static bool ph_match_str(const char *path)
{
	bool hit = false;
	int i;

	spin_lock(&ph_lock);
	for (i = 0; i < ph_nrules; i++) {
		if (strstr(path, ph_rules[i])) {
			hit = true;
			break;
		}
	}
	spin_unlock(&ph_lock);
	return hit;
}

/*
 * Preallocated per-CPU path buffers. An allocation here could only fail
 * "open" -- a NULL buffer means no match, which emits the very mapping we
 * were asked to conceal -- so the allocation is removed rather than made
 * more robust. Costs PATH_MAX per CPU, held for the life of the kernel.
 */
static DEFINE_PER_CPU(char [PATH_MAX], ph_pathbuf);

bool pathhide_match_file(struct file *file)
{
	char (*bufp)[PATH_MAX];
	char *p;
	bool hit = false;

	if (!file || !READ_ONCE(ph_nrules))
		return false;

	/* Disables preemption; d_path() and ph_match_str() never sleep. */
	bufp = get_cpu_ptr(&ph_pathbuf);
	p = d_path(PH_FILE_PATH(file), *bufp, PATH_MAX);
	if (!IS_ERR(p))
		hit = ph_match_str(p);
	put_cpu_ptr(&ph_pathbuf);

	return hit;
}

/*
 * Callers hold ph_lock. Returns 0 on success (or if already present) and
 * -ENOSPC when the table is full -- the caller MUST propagate that. Silently
 * returning success from a full table meant `echo +rule > /proc/pathhide`
 * reported success while hiding nothing, so a user past PH_MAX_RULES believed
 * paths were cloaked that were still in plain view. Same class as the batch-add
 * bug that let the nomount engine report an applied rule it had refused.
 */
static int ph_add_locked(const char *s)
{
	int i;

	for (i = 0; i < ph_nrules; i++)
		if (!strcmp(ph_rules[i], s))
			return 0;		/* already present */
	if (ph_nrules >= PH_MAX_RULES)
		return -ENOSPC;
	strscpy(ph_rules[ph_nrules], s, PH_RULE_LEN);
	if (!ph_rules[ph_nrules][0])
		return -EINVAL;
	WRITE_ONCE(ph_nrules, ph_nrules + 1);
	return 0;
}

/*
 * Callers hold ph_lock. Returns 0, or -ENOENT when there was no such rule --
 * which the caller MUST propagate, for the same reason ph_add_locked() reports a
 * full table: `nm k p '~needle'` returning success while the needle is still
 * being matched tells the operator a path was UNCLOAKED when it is still hidden.
 * That is the mirror image of the add-side bug and just as quiet.
 */
static int ph_del_locked(const char *s)
{
	int i, n = ph_nrules;

	for (i = 0; i < n; i++) {
		if (!strcmp(ph_rules[i], s)) {
			memmove(&ph_rules[i], &ph_rules[i + 1],
				(n - i - 1) * PH_RULE_LEN);
			WRITE_ONCE(ph_nrules, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

/*
 * Apply one control command. This is the whole control surface; the netlink
 * knob and the optional /proc write handler are both thin wrappers around it.
 *
 *     "+needle"   add a rule        "~needle"   remove one
 *     "needle"    add (bare form)   "-"         clear every rule
 *
 * @buf need NOT be NUL-terminated -- it is copied and terminated here, which is
 * what lets a netlink attribute payload be passed straight through without the
 * caller staging its own buffer.
 *
 * Deliberately does NOT check capabilities: every caller is already behind one
 * (CAP_NET_ADMIN on the netlink knob, CAP_SYS_ADMIN on the /proc write). Putting
 * a second, different check here would make the two paths disagree about who may
 * configure this.
 *
 * Returns 0, or a negative errno the caller MUST propagate -- see ph_add_locked
 * for why a full table has to be reported rather than swallowed.
 */
int pathhide_ctl(const char *buf, size_t count)
{
	char line[PH_RULE_LEN + 1];
	const char *s;
	size_t n = count;
	int ret;

	if (n == 0)
		return -EINVAL;
	if (n > PH_RULE_LEN)
		return -ENAMETOOLONG;
	memcpy(line, buf, n);
	line[n] = '\0';
	while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	if (n == 0)
		return 0;

	/* '-' on its own clears every rule. */
	if (line[0] == '-' && line[1] == '\0') {
		spin_lock(&ph_lock);
		WRITE_ONCE(ph_nrules, 0);
		spin_unlock(&ph_lock);
		return 0;
	}

	/* '~needle' removes one existing rule; '+needle'/bare needle adds one. */
	if (line[0] == '~' || line[0] == '+')
		s = line + 1;
	else
		s = line;
	if (!*s)
		return -EINVAL;
	if (strlen(s) >= PH_RULE_LEN)
		return -ENAMETOOLONG;

	spin_lock(&ph_lock);
	if (line[0] == '~')
		ret = ph_del_locked(s);
	else
		ret = ph_add_locked(s);
	spin_unlock(&ph_lock);
	return ret;
}

/*
 * Copy rule @idx into @out. Returns its length, or 0 once @idx is past the end
 * (which is how a caller iterating from 0 knows to stop).
 *
 * One rule per call rather than a bulk copy so the netlink dump can allocate and
 * emit each attribute with ph_lock DROPPED -- nlmsg_put() and friends must not
 * run under a spinlock. The list is tiny and read only by an explicit `nm l p`.
 */
int pathhide_get_rule(int idx, char *out, size_t outsz)
{
	int len = 0;

	if (!out || outsz < PH_RULE_LEN || idx < 0)
		return -EINVAL;
	spin_lock(&ph_lock);
	if (idx < ph_nrules) {
		strscpy(out, ph_rules[idx], outsz);
		len = strlen(out);
	}
	spin_unlock(&ph_lock);
	return len;
}

#ifdef PH_ENABLE_PROC
static int ph_seq_show(struct seq_file *m, void *v)
{
	int i;

	spin_lock(&ph_lock);
	for (i = 0; i < ph_nrules; i++)
		seq_printf(m, "%s\n", ph_rules[i]);
	spin_unlock(&ph_lock);
	return 0;
}

static int ph_open(struct inode *inode, struct file *file)
{
	/* Look absent to unprivileged probes. */
	if (!capable(CAP_SYS_ADMIN))
		return -ENOENT;
	return single_open(file, ph_seq_show, NULL);
}

static ssize_t ph_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char line[PH_RULE_LEN + 1];
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (count == 0)
		return -EINVAL;
	if (count > PH_RULE_LEN)
		return -ENAMETOOLONG;
	if (copy_from_user(line, ubuf, count))
		return -EFAULT;

	ret = pathhide_ctl(line, count);
	return ret ? ret : count;
}

static const struct proc_ops ph_proc_ops = {
	.proc_open	= ph_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= ph_write,
};

/*
 * Only built when PH_ENABLE_PROC is defined. Without it this file registers
 * nothing and owns no name anywhere in the filesystem -- configuration arrives
 * over nomount's netlink channel instead. See the stealth notes at the top for
 * the measurement that motivated making this opt-in.
 *
 * Still 0600 when it IS enabled: loosening to 0666 would make ph_open()'s
 * -ENOENT reachable, but that closes only the open() vector while readdir still
 * lists the entry -- and readdir is the one an app can actually reach.
 */
static int __init pathhide_init(void)
{
	proc_create(PH_PROC_NAME, 0600, NULL, &ph_proc_ops);
	return 0;
}
late_initcall(pathhide_init);
#endif /* PH_ENABLE_PROC */
