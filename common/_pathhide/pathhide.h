/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Install this header as include/linux/pathhide.h so both pathhide.c and the
 * fs/proc integration sites can reach it via <linux/pathhide.h>.
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
