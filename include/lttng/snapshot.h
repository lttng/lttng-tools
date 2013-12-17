/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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

#ifndef LTTNG_SNAPSHOT_H
#define LTTNG_SNAPSHOT_H

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Snapshot output object is opaque to the user. Use the helper functions below
 * to use them.
 */
struct lttng_snapshot_output;
struct lttng_snapshot_output_list;

/*
 * Return an newly allocated snapshot output object or NULL on error.
 */
struct lttng_snapshot_output *lttng_snapshot_output_create(void);

/*
 * Free a given snapshot output object.
 */
void lttng_snapshot_output_destroy(struct lttng_snapshot_output *output);

/*
 * Snapshot output getter family functions. They all return the value present
 * in the object.
 */

/* Return snapshot ID. */
uint32_t lttng_snapshot_output_get_id(struct lttng_snapshot_output *output);
/* Return maximum size of a snapshot. */
uint64_t lttng_snapshot_output_get_maxsize(struct lttng_snapshot_output *output);
/* Return snapshot name. */
const char *lttng_snapshot_output_get_name(struct lttng_snapshot_output *output);
/* Return snapshot control URL in a text format. */
const char *lttng_snapshot_output_get_ctrl_url(struct lttng_snapshot_output *output);
/* Return snapshot data URL in a text format. */
const char *lttng_snapshot_output_get_data_url(struct lttng_snapshot_output *output);

/*
 * Snapshot output setter family functions.
 *
 * For every set* call, 0 is returned on success or else -LTTNG_ERR_INVALID is
 * returned indicating that at least one given parameter is invalid.
 */

/* Set a custom ID. */
int lttng_snapshot_output_set_id(uint32_t id,
		struct lttng_snapshot_output *output);
/* Set the maximum size. */
int lttng_snapshot_output_set_size(uint64_t size,
		struct lttng_snapshot_output *output);
/* Set the snapshot name. */
int lttng_snapshot_output_set_name(const char *name,
		struct lttng_snapshot_output *output);
/* Set the control URL. Local and remote URL are supported. */
int lttng_snapshot_output_set_ctrl_url(const char *url,
		struct lttng_snapshot_output *output);
/* Set the data URL. Local and remote URL are supported. */
int lttng_snapshot_output_set_data_url(const char *url,
		struct lttng_snapshot_output *output);

/*
 * Add an output object to a session identified by name.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
int lttng_snapshot_add_output(const char *session_name,
		struct lttng_snapshot_output *output);

/*
 * Delete an output object to a session identified by name.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
int lttng_snapshot_del_output(const char *session_name,
		struct lttng_snapshot_output *output);

/*
 * List all snapshot output(s) of a session identified by name. The output list
 * object is populated and can be iterated over with the get_next call below.
 *
 * Return 0 on success or else a negative LTTNG_ERR code and the list pointer
 * is untouched.
 */
int lttng_snapshot_list_output(const char *session_name,
		struct lttng_snapshot_output_list **list);

/*
 * Return the next available snapshot output object in the given list. A list
 * output command MUST have been done before.
 *
 * Return the next object on success or else NULL indicating the end of the
 * list.
 */
struct lttng_snapshot_output *lttng_snapshot_output_list_get_next(
		struct lttng_snapshot_output_list *list);

/*
 * Free an output list object.
 */
void lttng_snapshot_output_list_destroy(struct lttng_snapshot_output_list *list);

/*
 * Snapshot a trace for the given session.
 *
 * The output object can be NULL but an add output MUST be done prior to this
 * call. If it's not NULL, it will be used to snapshot a trace.
 *
 * The wait parameter is ignored for now. The snapshot record command will
 * ALWAYS wait for the snapshot to complete before returning meaning the
 * snapshot has been written on disk or streamed over the network to a relayd.
 *
 * Return 0 on success or else a negative LTTNG_ERR value.
 */
int lttng_snapshot_record(const char *session_name,
		struct lttng_snapshot_output *output, int wait);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_SNAPSHOT_H */
