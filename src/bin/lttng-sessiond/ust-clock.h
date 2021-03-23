/*
 * Copyright (C) 2010 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _UST_CLOCK_H
#define _UST_CLOCK_H

#include <common/compat/time.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <urcu/system.h>
#include <urcu/arch.h>
#include <lttng/ust-clock.h>

#include <common/uuid.h>

static __inline__
uint64_t trace_clock_read64(void)
{
	uint64_t clock_value = 0;
	lttng_ust_clock_read64_function read64_cb;

	if (lttng_ust_trace_clock_get_read64_cb(&read64_cb)) {
		goto end;
	}

	clock_value = read64_cb();
end:
	return clock_value;
}

static __inline__
uint64_t trace_clock_freq(void)
{
	uint64_t frequency = 0;
	lttng_ust_clock_freq_function get_freq_cb;

	if (lttng_ust_trace_clock_get_freq_cb(&get_freq_cb)) {
		goto end;
	}

	frequency = get_freq_cb();
end:
	return frequency;
}

static __inline__
int trace_clock_uuid(char *uuid)
{
	int ret;
	lttng_ust_clock_uuid_function get_uuid_cb;

	if (lttng_ust_trace_clock_get_uuid_cb(&get_uuid_cb)) {
		ret = -EINVAL;
		goto end;
	}

	ret = get_uuid_cb(uuid);
end:
	return ret;

}

static __inline__
const char *trace_clock_name(void)
{
	const char *name;
	lttng_ust_clock_name_function get_name_cb;

	if (lttng_ust_trace_clock_get_name_cb(&get_name_cb)) {
		name = NULL;
		goto end;
	}

	name = get_name_cb();
end:
	return name;
}

static __inline__
const char *trace_clock_description(void)
{
	const char *description;
	lttng_ust_clock_description_function get_description_cb;

	if (lttng_ust_trace_clock_get_description_cb(&get_description_cb)) {
		description = NULL;
		goto end;
	}

	description = get_description_cb();
end:
	return description;
}

#endif /* _UST_CLOCK_H */
