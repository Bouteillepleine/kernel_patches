// SPDX-License-Identifier: GPL-2.0
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

#define GH_MAX_RULES	512
#define GH_RULE_LEN	192
#define GH_MAX_UIDS	128

static char ghost_rules[GH_MAX_RULES][GH_RULE_LEN];
static u8   ghost_rlen[GH_MAX_RULES];
static int  ghost_nrules;
static u32  ghost_uids[GH_MAX_UIDS];
static int  ghost_nuids;

static DEFINE_SPINLOCK(ghost_lock);

static DEFINE_PER_CPU(char [PATH_MAX], ghost_pathbuf);

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

	if (!READ_ONCE(ghost_nrules) || !READ_ONCE(ghost_nuids))
		return false;
	if (!path || !path->dentry || !path->mnt)
		return false;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!ghost_uid_hidden(uid))
		return false;

	hit = false;
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
			return -EINVAL;
	}
	if (s[len - 1] == '/')
		return slashes >= 3 ? 0 : -EINVAL;
	return slashes >= 2 ? 0 : -EINVAL;
}

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

static int ghost_add_uid_locked(u32 uid)
{
	if (ghost_uid_hidden(uid))
		return 0;
	if (ghost_nuids >= GH_MAX_UIDS)
		return -ENOSPC;
	WRITE_ONCE(ghost_uids[ghost_nuids], uid);
	smp_wmb();
	WRITE_ONCE(ghost_nuids, ghost_nuids + 1);
	return 0;
}

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

	if (!first_err && !ntok)
		return -EINVAL;
	return first_err;
}

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
