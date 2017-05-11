/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_CONDITION_BUFFER_USAGE_H
#define LTTNG_CONDITION_BUFFER_USAGE_H

#include <lttng/condition/evaluation.h>
#include <lttng/condition/condition.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_condition;
struct lttng_evaluation;

extern struct lttng_condition *
lttng_condition_buffer_usage_low_create(void);

extern struct lttng_condition *
lttng_condition_buffer_usage_high_create(void);

/* threshold_ratio expressed as [0.0, 1.0]. */
extern enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold_ratio(
		const struct lttng_condition *condition,
	        double *threshold_ratio);

/* threshold_ratio expressed as [0.0, 1.0]. */
extern enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold_ratio(
		struct lttng_condition *condition,
	        double threshold_ratio);

extern enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold(
		const struct lttng_condition *condition,
	        uint64_t *threshold_bytes);

extern enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold(
		struct lttng_condition *condition,
	        uint64_t threshold_bytes);

extern enum lttng_condition_status
lttng_condition_buffer_usage_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name);

extern enum lttng_condition_status
lttng_condition_buffer_usage_set_session_name(
		struct lttng_condition *condition,
		const char *session_name);

extern enum lttng_condition_status
lttng_condition_buffer_usage_get_channel_name(
		const struct lttng_condition *condition,
		const char **channel_name);

extern enum lttng_condition_status
lttng_condition_buffer_usage_set_channel_name(
		struct lttng_condition *condition,
		const char *channel_name);

extern enum lttng_condition_status
lttng_condition_buffer_usage_get_domain_type(
		const struct lttng_condition *condition,
		enum lttng_domain_type *type);

extern enum lttng_condition_status
lttng_condition_buffer_usage_set_domain_type(
		struct lttng_condition *condition,
		enum lttng_domain_type type);


/* LTTng Condition Evaluation */
extern enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage_ratio(
		const struct lttng_evaluation *evaluation,
		double *usage_ratio);

extern enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage(
		const struct lttng_evaluation *evaluation,
	        uint64_t *usage_bytes);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_BUFFER_USAGE_H */
