/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_SHM_H
#define _LTT_SHM_H

char *shm_ust_get_mmap(char *shm_path, int global);

int shm_create_anonymous(const char *owner_name);

#endif /* _LTT_SHM_H */
