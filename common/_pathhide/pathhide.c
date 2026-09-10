// SPDX-License-Identifier: GPL-2.0
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

static DEFINE_PER_CPU(char [PATH_MAX], ph_pathbuf);

bool pathhide_match_file(struct file *file)
{
	char (*bufp)[PATH_MAX];
	char *p;
	bool hit = false;

	if (!file || !READ_ONCE(ph_nrules))
		return false;

	bufp = get_cpu_ptr(&ph_pathbuf);
	p = d_path(PH_FILE_PATH(file), *bufp, PATH_MAX);
	if (!IS_ERR(p))
		hit = ph_match_str(p);
	put_cpu_ptr(&ph_pathbuf);

	return hit;
}

static int ph_add_locked(const char *s)
{
	int i;

	for (i = 0; i < ph_nrules; i++)
		if (!strcmp(ph_rules[i], s))
			return 0;
	if (ph_nrules >= PH_MAX_RULES)
		return -ENOSPC;
	strscpy(ph_rules[ph_nrules], s, PH_RULE_LEN);
	if (!ph_rules[ph_nrules][0])
		return -EINVAL;
	WRITE_ONCE(ph_nrules, ph_nrules + 1);
	return 0;
}

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

	if (line[0] == '-' && line[1] == '\0') {
		spin_lock(&ph_lock);
		WRITE_ONCE(ph_nrules, 0);
		spin_unlock(&ph_lock);
		return 0;
	}

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

static int __init pathhide_init(void)
{
	proc_create(PH_PROC_NAME, 0600, NULL, &ph_proc_ops);
	return 0;
}
late_initcall(pathhide_init);
#endif
