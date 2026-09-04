/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ships co-located with ghost.c (both copied into fs/proc/, next to
 * pathhide.c), so ghost.c pulls it in via #include "ghost.h". The fs/namei.c,
 * fs/open.c, fs/utimes.c and fs/xattr.c integration sites do NOT include this
 * header -- they forward-declare ghost_hidden_path() with a function-local
 * extern, exactly as the _pathhide integration sites do for
 * pathhide_match_file(), so no header has to be installed and no include line
 * has to be added to a hot core file.
 */
#ifndef _LINUX_GHOST_H
#define _LINUX_GHOST_H

#include <linux/types.h>

struct path;

/*
 * Returns true if @path is one of the configured injected paths AND the
 * calling task's real uid is one of the configured hidden uids.
 *
 * Callers use it at the VFS sites where NoMount's per-inode op hijack has
 * nothing to hook, so an injected-but-hidden path is otherwise distinguishable
 * from an absent one. Most callers answer -ENOENT when this returns true;
 * ghost_create.patch and ghost_open.patch answer what an ABSENT name would
 * have got instead, which on a read-only mount is -EROFS. See ghost.c's header
 * for the four orderings and the nine guard families that key on this.
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
 * applicable), behind its existing CAP_SYS_ADMIN check on the private netlink
 * channel -- the same arrangement _pathhide uses for pathhide_ctl(). (It was
 * CAP_NET_ADMIN before the engine tightened it; nothing here checks
 * capabilities itself, so keep this in step with nomount.c rather than adding
 * a second, different check.)
 *
 * ghost_ctl()      applies one command from a buffer that need not be
 *                  NUL-terminated. Returns 0 or a negative errno the caller
 *                  MUST propagate.
 *
 *                    "p+/abs/path"       add a path rule
 *                    "p+/a\n/b\n/c"      add several, one command
 *                    "p=/a\n/b\n/c"      REPLACE the path table with exactly
 *                                        these -- validated first, then applied
 *                                        under one lock, so no reader ever sees
 *                                        a half-built table
 *                    "p~/abs/path"       remove one path rule
 *                    "p-"                clear every path rule
 *                    "u+10234"           add a hidden uid (list form too)
 *                    "u=10234\n10235"    replace the whole uid table
 *                    "u~10234"           remove one hidden uid
 *                    "u-"                clear every hidden uid
 *
 *                  A batch reports the FIRST error and still applies the rest,
 *                  so one bad entry in a list of 300 does not silently drop the
 *                  other 299. A '=' batch is the exception: it is validated in
 *                  full before anything is touched and refused whole, because a
 *                  replace that half-succeeds is the one outcome worse than not
 *                  running at all.
 *
 *                  -ENAMETOOLONG (a path past the rule-slot size) is distinct
 *                  from -EINVAL (a malformed or too-broad rule) on purpose: the
 *                  Suite reports rejections to a human.
 *
 * ghost_get_rule() copies entry @idx into @out as "p /abs/path" or "u 10234",
 *                  returning its length, or 0 once @idx is past the end. Path
 *                  rules are enumerated first, then uids, so one loop from 0
 *                  dumps the whole configuration. One entry per call so the
 *                  caller can emit each with no lock held. @out must be at
 *                  least 196 bytes.
 */
int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);

#endif /* _LINUX_GHOST_H */
