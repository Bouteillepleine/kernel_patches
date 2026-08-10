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
 * /proc/<pid>/map_files and /proc/<pid>/fd entries whose backing file matches
 * (e.g. injected hook-framework module APKs). Inert (returns false
 * immediately) until at least one rule is written to /proc/<PH_PROC_NAME>, so
 * it is a no-op on stock configurations.
 */
bool pathhide_match_file(struct file *file);

#endif /* _LINUX_PATHHIDE_H */
