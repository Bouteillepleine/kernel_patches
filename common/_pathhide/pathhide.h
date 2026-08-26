/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ships co-located with pathhide.c (both copied into fs/), so pathhide.c pulls
 * it in via #include "pathhide.h". The fs/proc integration sites do NOT include
 * this header — they forward-declare pathhide_match_file() with a local extern,
 * so they need no installed header.
 */
#ifndef _LINUX_PATHHIDE_H
#define _LINUX_PATHHIDE_H

#include <linux/types.h>

struct file;

/*
 * Returns true if @file's backing path contains any configured needle.
 * Callers use it to omit /proc/<pid>/maps, /proc/<pid>/smaps,
 * /proc/<pid>/smaps_rollup, /proc/<pid>/numa_maps and /proc/<pid>/map_files
 * entries whose backing file matches (e.g. injected hook-framework module
 * APKs). It is NOT used for /proc/<pid>/fd any more -- see pathhide.c for why
 * that half was removed. Inert (returns false immediately) until at least one
 * rule is configured, and nothing configures one by default, so it is a no-op
 * on every shipped build.
 */
bool pathhide_match_file(struct file *file);

/*
 * Control plane. nomount.c reaches both of these through WEAK externs (it does
 * not include this header, so the two patch sets stay independently
 * applicable); the optional /proc handler in pathhide.c calls pathhide_ctl()
 * directly.
 *
 * pathhide_ctl()      applies one command -- "+needle", "~needle", "-" -- from
 *                     a buffer that need not be NUL-terminated. Returns 0 or a
 *                     negative errno the caller must propagate.
 * pathhide_get_rule() copies rule @idx into @out, returning its length, or 0
 *                     once @idx is past the end. One rule per call so a caller
 *                     can emit each one with no lock held.
 */
int pathhide_ctl(const char *buf, size_t count);
int pathhide_get_rule(int idx, char *out, size_t outsz);

#endif /* _LINUX_PATHHIDE_H */
