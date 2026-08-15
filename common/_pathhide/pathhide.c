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
 * unrelated paths.
 *
 * Inert until the first rule is added (pathhide_match_file() short-circuits on
 * an empty rule set), so it is a no-op on stock configurations.
 *
 * Stealth notes:
 *   - The control node returns -ENOENT to callers without CAP_SYS_ADMIN, so an
 *     unprivileged probe that open()s the path by name cannot confirm it exists.
 *   - The node name is a build-time knob (PH_PROC_NAME); override it to blend
 *     into the target tree. The dirent is still visible to an unprivileged
 *     /proc readdir, so for full stealth also hide the name via the readdir
 *     cloak (69_hide_stuff / maphide).
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

/* Callers hold ph_lock. */
static void ph_add_locked(const char *s)
{
	int i;

	for (i = 0; i < ph_nrules; i++)
		if (!strcmp(ph_rules[i], s))
			return;			/* already present */
	if (ph_nrules >= PH_MAX_RULES)
		return;
	strscpy(ph_rules[ph_nrules], s, PH_RULE_LEN);
	if (ph_rules[ph_nrules][0])
		WRITE_ONCE(ph_nrules, ph_nrules + 1);
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
	if (line[0] == '~')
		ph_del_locked(s);
	else
		ph_add_locked(s);
	spin_unlock_irqrestore(&ph_lock, flags);
	return count;
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
	proc_create(PH_PROC_NAME, 0600, NULL, &ph_proc_ops);
	return 0;
}
late_initcall(pathhide_init);
