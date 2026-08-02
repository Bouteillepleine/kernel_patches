/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PATHHIDE_H
#define _LINUX_PATHHIDE_H

struct file;

/*
 * Returns true if @file's backing path contains any configured needle.
 * Callers use it to omit /proc/<pid>/maps and /proc/<pid>/fd entries whose
 * backing file matches (e.g. injected hook-framework module APKs). Inert
 * (returns false immediately) until at least one rule is written to
 * /proc/pathhide, so it is a no-op on stock configurations.
 */
bool pathhide_match_file(struct file *file);

#endif /* _LINUX_PATHHIDE_H */
