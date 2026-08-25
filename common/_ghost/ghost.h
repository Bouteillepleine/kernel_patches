/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ships co-located with ghost.c (both copied into fs/proc/, next to
 * pathhide.c), so ghost.c pulls it in via #include "ghost.h". The fs/namei.c
 * and fs/xattr.c integration sites do NOT include this header -- they
 * forward-declare ghost_hidden_path() with a function-local extern, exactly as
 * the _pathhide integration sites do for pathhide_match_file(), so no header
 * has to be installed and no include line has to be added to a hot core file.
 */
#ifndef _LINUX_GHOST_H
#define _LINUX_GHOST_H

#include <linux/types.h>

struct path;

/*
 * Returns true if @path is one of the configured injected paths AND the
 * calling task's real uid is one of the configured hidden uids.
 *
 * Callers use it at the four VFS sites where NoMount's per-inode op hijack has
 * nothing to hook, so an injected-but-hidden path is otherwise distinguishable
 * from an absent one. Every caller answers -ENOENT when this returns true.
 *
 * Inert (returns false before touching @path) until BOTH a path rule and a uid
 * have been configured, so it is a no-op on stock configurations.
 *
 * Safe to call in process context with a fully resolved, reference-counted
 * struct path. It is NOT safe under RCU-walk: it renders d_path(), which needs
 * a stable path. Every integration site calls it only after the lookup has
 * completed or after try_to_unlazy()/unlazy_walk() has legitimised the walk.
 */
bool ghost_hidden_path(const struct path *path);

/*
 * Control plane. The nomount engine reaches both of these through WEAK externs
 * (it does not include this header, so the two patch sets stay independently
 * applicable), behind its existing CAP_NET_ADMIN check on the private netlink
 * channel -- the same arrangement _pathhide uses for pathhide_ctl().
 *
 * ghost_ctl()      applies one command from a buffer that need not be
 *                  NUL-terminated. Returns 0 or a negative errno the caller
 *                  MUST propagate.
 *
 *                    "p+/abs/path"  add a path rule
 *                    "p~/abs/path"  remove one path rule
 *                    "p-"           clear every path rule
 *                    "u+10234"      add a hidden uid
 *                    "u~10234"      remove one hidden uid
 *                    "u-"           clear every hidden uid
 *
 * ghost_get_rule() copies entry @idx into @out as "p /abs/path" or "u 10234",
 *                  returning its length, or 0 once @idx is past the end. Path
 *                  rules are enumerated first, then uids, so one loop from 0
 *                  dumps the whole configuration. One entry per call so the
 *                  caller can emit each with no lock held.
 */
int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);

#endif /* _LINUX_GHOST_H */
