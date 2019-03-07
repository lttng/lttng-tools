/*
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_HT_CLEANUP_H
#define _LTTNG_HT_CLEANUP_H

#include <pthread.h>
#include "thread.h"

struct lttng_thread *launch_ht_cleanup_thread(void);

#endif /* _LTTNG_HT_CLEANUP_H */
