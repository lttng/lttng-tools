/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SNAPSHOT_H
#define LTTNG_SNAPSHOT_H

#include <lttng/lttng-export.h>

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
LTTNG_EXPORT extern struct lttng_snapshot_output *lttng_snapshot_output_create(void);

/*
 * Free a given snapshot output object.
 */
LTTNG_EXPORT extern void lttng_snapshot_output_destroy(struct lttng_snapshot_output *output);

/*
 * Snapshot output getter family functions. They all return the value present
 * in the object.
 */

/* Return snapshot ID. */
LTTNG_EXPORT extern uint32_t
lttng_snapshot_output_get_id(const struct lttng_snapshot_output *output);
/* Return maximum size of a snapshot. */
LTTNG_EXPORT extern uint64_t
lttng_snapshot_output_get_maxsize(const struct lttng_snapshot_output *output);
/* Return snapshot name. */
LTTNG_EXPORT extern const char *
lttng_snapshot_output_get_name(const struct lttng_snapshot_output *output);
/* Return snapshot control URL in a text format. */
LTTNG_EXPORT extern const char *
lttng_snapshot_output_get_ctrl_url(const struct lttng_snapshot_output *output);
/* Return snapshot data URL in a text format. */
LTTNG_EXPORT extern const char *
lttng_snapshot_output_get_data_url(const struct lttng_snapshot_output *output);

/*
 * Snapshot output setter family functions.
 *
 * For every set* call, 0 is returned on success or else -LTTNG_ERR_INVALID is
 * returned indicating that at least one given parameter is invalid.
 */

/* Set a custom ID. */
LTTNG_EXPORT extern int lttng_snapshot_output_set_id(uint32_t id,
						     struct lttng_snapshot_output *output);
/* Set the maximum size. */
LTTNG_EXPORT extern int lttng_snapshot_output_set_size(uint64_t size,
						       struct lttng_snapshot_output *output);
/* Set the snapshot name. */
LTTNG_EXPORT extern int lttng_snapshot_output_set_name(const char *name,
						       struct lttng_snapshot_output *output);

/*
 * Set the output destination to be a path on the local filesystem.
 *
 * The path must be absolute. It can optionally begin with `file://`.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
LTTNG_EXPORT extern int lttng_snapshot_output_set_local_path(const char *path,
							     struct lttng_snapshot_output *output);

/*
 * Set the output destination to be the network from a combined control/data
 * URL.
 *
 * `url` must start with `net://` or `net6://`.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
LTTNG_EXPORT extern int lttng_snapshot_output_set_network_url(const char *url,
							      struct lttng_snapshot_output *output);

/*
 * Set the output destination to be the network using separate URLs for control
 * and data.
 *
 * Both ctrl_url and data_url must be non-null.
 *
 * `ctrl_url` and `data_url` must start with `tcp://` or `tcp6://`.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
LTTNG_EXPORT extern int lttng_snapshot_output_set_network_urls(
	const char *ctrl_url, const char *data_url, struct lttng_snapshot_output *output);

/* Set the control URL. Local and remote URL are supported. */
LTTNG_EXPORT extern int lttng_snapshot_output_set_ctrl_url(const char *url,
							   struct lttng_snapshot_output *output);
/* Set the data URL. Local and remote URL are supported. */
LTTNG_EXPORT extern int lttng_snapshot_output_set_data_url(const char *url,
							   struct lttng_snapshot_output *output);

/*
 * Add an output object to a session identified by name.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
LTTNG_EXPORT extern int lttng_snapshot_add_output(const char *session_name,
						  struct lttng_snapshot_output *output);

/*
 * Delete an output object to a session identified by name.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
LTTNG_EXPORT extern int lttng_snapshot_del_output(const char *session_name,
						  struct lttng_snapshot_output *output);

/*
 * List all snapshot output(s) of a session identified by name. The output list
 * object is populated and can be iterated over with the get_next call below.
 *
 * Return 0 on success or else a negative LTTNG_ERR code and the list pointer
 * is untouched.
 */
LTTNG_EXPORT extern int lttng_snapshot_list_output(const char *session_name,
						   struct lttng_snapshot_output_list **list);

/*
 * Return the next available snapshot output object in the given list. A list
 * output command MUST have been done before.
 *
 * Return the next object on success or else NULL indicating the end of the
 * list.
 */
LTTNG_EXPORT extern struct lttng_snapshot_output *
lttng_snapshot_output_list_get_next(struct lttng_snapshot_output_list *list);

/*
 * Free an output list object.
 */
LTTNG_EXPORT extern void
lttng_snapshot_output_list_destroy(struct lttng_snapshot_output_list *list);

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
LTTNG_EXPORT extern int
lttng_snapshot_record(const char *session_name, struct lttng_snapshot_output *output, int wait);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_SNAPSHOT_H */
