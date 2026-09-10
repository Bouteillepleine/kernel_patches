/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GHOST_H
#define _LINUX_GHOST_H

#include <linux/types.h>

struct path;

bool ghost_hidden_path(const struct path *path);

int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);

#endif
