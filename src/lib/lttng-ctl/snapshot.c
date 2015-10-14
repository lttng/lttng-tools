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

#define _LGPL_SOURCE
#include <assert.h>
#include <string.h>

#include <common/sessiond-comm/sessiond-comm.h>
#include <lttng/lttng-error.h>
#include <lttng/snapshot.h>
#include <lttng/snapshot-internal.h>

#include "lttng-ctl-helper.h"

/*
 * Add an output object to a session identified by name.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
int lttng_snapshot_add_output(const char *session_name,
		struct lttng_snapshot_output *output)
{
	int ret;
	struct lttcomm_session_msg lsm;
	struct lttcomm_lttng_output_id *reply;

	if (!session_name || !output) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_SNAPSHOT_ADD_OUTPUT;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));
	memcpy(&lsm.u.snapshot_output.output, output,
			sizeof(lsm.u.snapshot_output.output));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &reply);
	if (ret < 0) {
		return ret;
	}

	output->id = reply->id;
	free(reply);

	return 0;
}

/*
 * Delete an output object to a session identified by name.
 *
 * Return 0 on success or else a negative LTTNG_ERR code.
 */
int lttng_snapshot_del_output(const char *session_name,
		struct lttng_snapshot_output *output)
{
	struct lttcomm_session_msg lsm;

	if (!session_name || !output) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_SNAPSHOT_DEL_OUTPUT;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));
	memcpy(&lsm.u.snapshot_output.output, output,
			sizeof(lsm.u.snapshot_output.output));

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * List all snapshot output(s) of a session identified by name. The output list
 * object is populated and can be iterated over with the get_next call below.
 *
 * Return 0 on success or else a negative LTTNG_ERR code and the list pointer
 * is untouched.
 */
int lttng_snapshot_list_output(const char *session_name,
		struct lttng_snapshot_output_list **list)
{
	int ret;
	struct lttcomm_session_msg lsm;
	struct lttng_snapshot_output_list *new_list = NULL;

	if (!session_name || !list) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_SNAPSHOT_LIST_OUTPUT;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	new_list = zmalloc(sizeof(*new_list));
	if (!new_list) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &new_list->array);
	if (ret < 0) {
		goto free_error;
	}

	new_list->count = ret / sizeof(struct lttng_snapshot_output);
	*list = new_list;
	return 0;

free_error:
	free(new_list);
error:
	return ret;
}

/*
 * Return the next available snapshot output object in the given list. A list
 * output command MUST have been done before.
 *
 * Return the next object on success or else NULL indicating the end of the
 * list.
 */
struct lttng_snapshot_output *lttng_snapshot_output_list_get_next(
		struct lttng_snapshot_output_list *list)
{
	struct lttng_snapshot_output *output = NULL;

	if (!list) {
		goto error;
	}

	/* We've reached the end. */
	if (list->index == list->count) {
		goto end;
	}

	output = &list->array[list->index];
	list->index++;

end:
error:
	return output;
}

/*
 * Free an output list object.
 */
void lttng_snapshot_output_list_destroy(struct lttng_snapshot_output_list *list)
{
	if (!list) {
		return;
	}

	free(list->array);
	free(list);
}

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
		struct lttng_snapshot_output *output, int wait)
{
	struct lttcomm_session_msg lsm;

	if (!session_name) {
		return -LTTNG_ERR_INVALID;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_SNAPSHOT_RECORD;

	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	/*
	 * Not having an output object will use the default one of the session that
	 * would need to be set by a call to add output prior to calling snapshot
	 * record.
	 */
	if (output) {
		memcpy(&lsm.u.snapshot_record.output, output,
				sizeof(lsm.u.snapshot_record.output));
	}

	/* The wait param is ignored. */

	return lttng_ctl_ask_sessiond(&lsm, NULL);
}

/*
 * Return an newly allocated snapshot output object or NULL on error.
 */
struct lttng_snapshot_output *lttng_snapshot_output_create(void)
{
	struct lttng_snapshot_output *output;

	output = zmalloc(sizeof(struct lttng_snapshot_output));
	if (!output) {
		goto error;
	}

	output->max_size = (uint64_t) -1ULL;

error:
	return output;
}

/*
 * Free a given snapshot output object.
 */
void lttng_snapshot_output_destroy(struct lttng_snapshot_output *obj)
{
	if (obj) {
		free(obj);
	}
}

/*
 * Getter family functions of snapshot output.
 */

uint32_t lttng_snapshot_output_get_id(struct lttng_snapshot_output *output)
{
	return output->id;
}

const char *lttng_snapshot_output_get_name(
		struct lttng_snapshot_output *output)
{
	return output->name;
}

const char *lttng_snapshot_output_get_data_url(struct lttng_snapshot_output *output)
{
	return output->data_url;
}

const char *lttng_snapshot_output_get_ctrl_url(struct lttng_snapshot_output *output)
{
	return output->ctrl_url;
}

uint64_t lttng_snapshot_output_get_maxsize(
		struct lttng_snapshot_output *output)
{
	return output->max_size;
}

/*
 * Setter family functions for snapshot output.
 */

int lttng_snapshot_output_set_id(uint32_t id,
		struct lttng_snapshot_output *output)
{
	if (!output || id == 0) {
		return -LTTNG_ERR_INVALID;
	}

	output->id = id;
	return 0;
}

int lttng_snapshot_output_set_size(uint64_t size,
		struct lttng_snapshot_output *output)
{
	if (!output) {
		return -LTTNG_ERR_INVALID;
	}

	output->max_size = size;
	return 0;
}

int lttng_snapshot_output_set_name(const char *name,
		struct lttng_snapshot_output *output)
{
	if (!output || !name) {
		return -LTTNG_ERR_INVALID;
	}

	lttng_ctl_copy_string(output->name, name, sizeof(output->name));
	return 0;
}

int lttng_snapshot_output_set_ctrl_url(const char *url,
		struct lttng_snapshot_output *output)
{
	if (!output || !url) {
		return -LTTNG_ERR_INVALID;
	}

	lttng_ctl_copy_string(output->ctrl_url, url, sizeof(output->ctrl_url));
	return 0;
}

int lttng_snapshot_output_set_data_url(const char *url,
		struct lttng_snapshot_output *output)
{
	if (!output || !url) {
		return -LTTNG_ERR_INVALID;
	}

	lttng_ctl_copy_string(output->data_url, url, sizeof(output->data_url));
	return 0;
}
