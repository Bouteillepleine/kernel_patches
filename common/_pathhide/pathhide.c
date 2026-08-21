// SPDX-License-Identifier: GPL-2.0
/*
 * pathhide - omit selected file-backed entries from /proc/<pid>/maps,
 * /proc/<pid>/smaps, /proc/<pid>/map_files and /proc/<pid>/fd.
 *
 * Rules are plain substrings matched against the resolved d_path of a VMA's
 * or fd's backing file. Configure via /proc/<PH_PROC_NAME> (root, 0600):
 *
 *     echo '+io.github.chsbuffer.revancedxposed' > /proc/pathhide   # add rule
 *     echo '+/data/adb/lspd'                     > /proc/pathhide
 *     echo '~/data/adb/lspd'                     > /proc/pathhide   # remove one
 *     echo '-'                                   > /proc/pathhide   # clear all
 *     cat /proc/pathhide                                            # list rules
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
 *   - ph_open() returns -ENOENT without CAP_SYS_ADMIN so an open() by name
 *     answers exactly as it would for a file that is not there. That check is
 *     only REACHABLE because the node is created world-openable (0666): at 0600
 *     the VFS rejected on DAC in may_open() before ph_open() ever ran, and the
 *     caller got EACCES -- which confirms the file exists. Measured on OP15 at
 *     0600, as uid 2000: `cat /proc/pathhide` -> "Permission denied". Every
 *     write path still checks CAP_SYS_ADMIN, and a non-admin cannot obtain a fd
 *     at all, so 0666 grants nothing.
 *   - The dirent REMAINS VISIBLE to an unprivileged /proc readdir, and stat()
 *     by name still succeeds. Measured on OP15 as uid 2000:
 *         ls /proc | grep pathhide   -> 1
 *         ls -l /proc/pathhide       -> -rw------- root root
 *     A stock kernel has no such entry, so this is a one-syscall,
 *     zero-permission, self-naming tell -- louder than anything this file
 *     hides. Renaming via PH_PROC_NAME only makes it less self-describing; it
 *     does not make it absent, and nothing in the builders currently overrides
 *     it, so the node ships literally called "pathhide".
 *   - The real fix is not to have a /proc node at all: nomount moved its own
 *     knobs off /sys/kernel/<name> onto a private raw-netlink protocol for
 *     exactly this reason (CAP_NET_ADMIN-gated, not enumerable, no dirent).
 *     This control plane should follow it.
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
#include "pathhide.h"

#ifndef PH_PROC_NAME
#define PH_PROC_NAME	"pathhide"
#endif

#define PH_MAX_RULES	64
#define PH_RULE_LEN	128

static char ph_rules[PH_MAX_RULES][PH_RULE_LEN];
static int  ph_nrules;
static DEFINE_SPINLOCK(ph_lock);

static bool ph_match_str(const char *path)
{
	unsigned long flags;
	bool hit = false;
	int i;

	spin_lock_irqsave(&ph_lock, flags);
	for (i = 0; i < ph_nrules; i++) {
		if (strstr(path, ph_rules[i])) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ph_lock, flags);
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
	p = d_path(&file->f_path, *bufp, PATH_MAX);
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

/* Callers hold ph_lock. */
static void ph_del_locked(const char *s)
{
	int i, n = ph_nrules;

	for (i = 0; i < n; i++) {
		if (!strcmp(ph_rules[i], s)) {
			memmove(&ph_rules[i], &ph_rules[i + 1],
				(n - i - 1) * PH_RULE_LEN);
			WRITE_ONCE(ph_nrules, n - 1);
			return;
		}
	}
}

static int ph_seq_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ph_lock, flags);
	for (i = 0; i < ph_nrules; i++)
		seq_printf(m, "%s\n", ph_rules[i]);
	spin_unlock_irqrestore(&ph_lock, flags);
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
	unsigned long flags;
	const char *s;
	size_t n = count;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (n == 0)
		return -EINVAL;
	if (n > PH_RULE_LEN)
		return -ENAMETOOLONG;
	if (copy_from_user(line, ubuf, n))
		return -EFAULT;
	line[n] = '\0';
	while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	if (n == 0)
		return count;

	/* '-' on its own clears every rule. */
	if (line[0] == '-' && line[1] == '\0') {
		spin_lock_irqsave(&ph_lock, flags);
		WRITE_ONCE(ph_nrules, 0);
		spin_unlock_irqrestore(&ph_lock, flags);
		return count;
	}

	/* '~needle' removes one existing rule; '+needle'/bare needle adds one. */
	if (line[0] == '~')
		s = line + 1;
	else if (line[0] == '+')
		s = line + 1;
	else
		s = line;
	if (!*s)
		return -EINVAL;
	if (strlen(s) >= PH_RULE_LEN)
		return -ENAMETOOLONG;

	spin_lock_irqsave(&ph_lock, flags);
	if (line[0] == '~') {
		ph_del_locked(s);
		ret = 0;
	} else {
		ret = ph_add_locked(s);
	}
	spin_unlock_irqrestore(&ph_lock, flags);
	return ret ? ret : count;
}

static const struct proc_ops ph_proc_ops = {
	.proc_open	= ph_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= ph_write,
};

static int __init pathhide_init(void)
{
	/*
	 * Kept at 0600. Loosening it to 0666 would make ph_open()'s -ENOENT
	 * reachable (the VFS otherwise refuses in may_open() first and hands an
	 * unprivileged caller EACCES, which proves the node exists) -- but that
	 * closes only ONE of three disclosure vectors while readdir and stat still
	 * expose the node, and a world-writable /proc entry is itself an anomaly.
	 * Trading a certain oddity for a partial gain is not worth it; the fix is
	 * to stop using /proc at all. See the stealth notes at the top.
	 */
	proc_create(PH_PROC_NAME, 0600, NULL, &ph_proc_ops);
	return 0;
}
late_initcall(pathhide_init);
