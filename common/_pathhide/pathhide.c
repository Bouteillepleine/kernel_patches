// SPDX-License-Identifier: GPL-2.0
/*
 * pathhide - omit selected file-backed entries from /proc/<pid>/maps and
 * /proc/<pid>/fd.
 *
 * Rules are plain substrings matched against the resolved d_path of a VMA's
 * or fd's backing file. Configure via /proc/pathhide (root, 0600):
 *
 *     echo '+io.github.chsbuffer.revancedxposed' > /proc/pathhide   # add rule
 *     echo '+/data/adb/lspd'                     > /proc/pathhide
 *     echo '-'                                   > /proc/pathhide   # clear all
 *     cat /proc/pathhide                                            # list rules
 *
 * Inert until the first rule is added (pathhide_match_file() short-circuits on
 * an empty rule set), so it is a no-op on stock configurations.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/init.h>
#include "pathhide.h"

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

bool pathhide_match_file(struct file *file)
{
	char *buf, *p;
	bool hit = false;

	if (!file || !READ_ONCE(ph_nrules))
		return false;

	buf = kmalloc(PATH_MAX, GFP_ATOMIC);
	if (!buf)
		return false;

	p = d_path(&file->f_path, buf, PATH_MAX);
	if (!IS_ERR(p))
		hit = ph_match_str(p);

	kfree(buf);
	return hit;
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
	return single_open(file, ph_seq_show, NULL);
}

static ssize_t ph_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char line[PH_RULE_LEN + 1];
	unsigned long flags;
	size_t n = count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (n == 0)
		return -EINVAL;
	if (n > PH_RULE_LEN)
		n = PH_RULE_LEN;
	if (copy_from_user(line, ubuf, n))
		return -EFAULT;
	line[n] = '\0';
	while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	if (n == 0)
		return count;

	spin_lock_irqsave(&ph_lock, flags);
	if (line[0] == '-' && line[1] == '\0') {
		ph_nrules = 0;
	} else if (ph_nrules < PH_MAX_RULES) {
		const char *s = (line[0] == '+') ? line + 1 : line;

		strscpy(ph_rules[ph_nrules], s, PH_RULE_LEN);
		if (ph_rules[ph_nrules][0])
			ph_nrules++;
	}
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
	proc_create("pathhide", 0600, NULL, &ph_proc_ops);
	return 0;
}
late_initcall(pathhide_init);
