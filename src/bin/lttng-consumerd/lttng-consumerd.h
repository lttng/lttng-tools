/*
 * Copyright (C) 2011 Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_CONSUMERD_H
#define _LTTNG_CONSUMERD_H


#define NR_LTTNG_CONSUMER_READY		1
extern int lttng_consumer_ready;

extern const char *tracing_group_name;

/*
 * This function is dlsym-ed from a test, making it have a C linkage name
 * makes it easier.
 */
extern "C" enum lttng_consumer_type lttng_consumer_get_type();

#endif /* _LTTNG_CONSUMERD_H */
