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
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/stringhash.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include "ghost.h"

#define GH_RULE_LEN	192
#define GH_MAX_UIDS	128
#define GH_MAX_RULES	65536
#define GH_HASH_BITS	13
#define GH_HASH_SIZE	(1u << GH_HASH_BITS)

struct gh_rule {
	struct hlist_node hnode;
	struct list_head lnode;
	struct rcu_head rcu;
	u32 hash;
	u16 len;
	bool prefix;
	char path[];
};

static struct hlist_head ghost_ht[GH_HASH_SIZE];
static HLIST_HEAD(ghost_prefixes);
static LIST_HEAD(ghost_all);
static int ghost_nrules;
static u32 ghost_uids[GH_MAX_UIDS];
static int ghost_nuids;

static DEFINE_MUTEX(ghost_mutex);

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

static struct hlist_head *ghost_bucket(u32 hash)
{
	return &ghost_ht[hash & (GH_HASH_SIZE - 1)];
}

static bool ghost_path_rcu(const char *path, size_t plen)
{
	struct gh_rule *r;
	u32 hash;

	if (plen < GH_RULE_LEN) {
		hash = full_name_hash(NULL, path, plen);
		hlist_for_each_entry_rcu(r, ghost_bucket(hash), hnode) {
			if (r->hash == hash && r->len == plen &&
			    !memcmp(r->path, path, plen))
				return true;
		}
	}

	hlist_for_each_entry_rcu(r, &ghost_prefixes, hnode) {
		if (plen > r->len && !memcmp(path, r->path, r->len))
			return true;
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

		rcu_read_lock();
		hit = ghost_path_rcu(p, plen);
		rcu_read_unlock();
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

static struct gh_rule *ghost_find_locked(const char *s, size_t slen)
{
	struct gh_rule *r;
	u32 hash;

	if (slen && s[slen - 1] == '/') {
		hlist_for_each_entry(r, &ghost_prefixes, hnode)
			if (r->len == slen && !memcmp(r->path, s, slen))
				return r;
		return NULL;
	}
	hash = full_name_hash(NULL, s, slen);
	hlist_for_each_entry(r, ghost_bucket(hash), hnode)
		if (r->hash == hash && r->len == slen && !memcmp(r->path, s, slen))
			return r;
	return NULL;
}

static void ghost_drop_locked(struct gh_rule *r)
{
	hlist_del_rcu(&r->hnode);
	list_del(&r->lnode);
	WRITE_ONCE(ghost_nrules, ghost_nrules - 1);
	kfree_rcu(r, rcu);
}

static int ghost_add_path_locked(const char *s, size_t slen)
{
	struct gh_rule *r;

	if (ghost_find_locked(s, slen))
		return 0;
	if (ghost_nrules >= GH_MAX_RULES)
		return -ENOSPC;
	r = kzalloc(sizeof(*r) + slen + 1, GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	memcpy(r->path, s, slen);
	r->path[slen] = '\0';
	r->len = (u16)slen;
	r->prefix = s[slen - 1] == '/';
	r->hash = full_name_hash(NULL, s, slen);
	list_add_tail(&r->lnode, &ghost_all);
	if (r->prefix)
		hlist_add_head_rcu(&r->hnode, &ghost_prefixes);
	else
		hlist_add_head_rcu(&r->hnode, ghost_bucket(r->hash));
	WRITE_ONCE(ghost_nrules, ghost_nrules + 1);
	return 0;
}

static int ghost_del_path_locked(const char *s)
{
	struct gh_rule *r = ghost_find_locked(s, strlen(s));

	if (!r)
		return -ENOENT;
	ghost_drop_locked(r);
	return 0;
}

static void ghost_clear_paths_locked(void)
{
	struct gh_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &ghost_all, lnode)
		ghost_drop_locked(r);
	WRITE_ONCE(ghost_nrules, 0);
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
		mutex_lock(&ghost_mutex);
		if (op == 'p')
			ghost_clear_paths_locked();
		else
			WRITE_ONCE(ghost_nuids, 0);
		mutex_unlock(&ghost_mutex);
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

	mutex_lock(&ghost_mutex);
	if (replace) {
		if (op == 'p')
			ghost_clear_paths_locked();
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
	mutex_unlock(&ghost_mutex);

	if (!first_err && !ntok)
		return -EINVAL;
	return first_err;
}

int ghost_get_rule(int idx, char *out, size_t outsz)
{
	struct gh_rule *r;
	int len = 0, i = 0;

	if (!out || outsz < GH_RULE_LEN + 4 || idx < 0)
		return -EINVAL;

	mutex_lock(&ghost_mutex);
	if (idx < ghost_nrules) {
		list_for_each_entry(r, &ghost_all, lnode) {
			if (i++ != idx)
				continue;
			len = scnprintf(out, outsz, "p %s", r->path);
			break;
		}
	} else {
		idx -= ghost_nrules;
		if (idx < ghost_nuids)
			len = scnprintf(out, outsz, "u %u", ghost_uids[idx]);
	}
	mutex_unlock(&ghost_mutex);
	return len;
}
