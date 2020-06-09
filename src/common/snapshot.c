/*
 * Copyright (C) 2020 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <common/snapshot.h>
#include <lttng/snapshot-internal.h>
#include <lttng/snapshot.h>

#include <assert.h>
#include <stdlib.h>

LTTNG_HIDDEN
bool lttng_snapshot_output_validate(const struct lttng_snapshot_output *output)
{
	bool valid = false;
	size_t len;

	/*
	 * It is mandatory to have a ctrl_url. If there is only one output
	 * URL (in the net://, net6:// or file:// form), it will be in this
	 * field.
	 */
	len = lttng_strnlen(output->ctrl_url, sizeof(output->ctrl_url));
	if (len == 0 || len >= sizeof(output->ctrl_url)) {
		goto end;
	}

	len = lttng_strnlen(output->data_url, sizeof(output->data_url));
	if (len >= sizeof(output->data_url)) {
		goto end;
	}

	len = lttng_strnlen(output->name, sizeof(output->name));
	if (len >= sizeof(output->name)) {
		goto end;
	}

	valid = true;

end:
	return valid;
}

LTTNG_HIDDEN
bool lttng_snapshot_output_is_equal(
		const struct lttng_snapshot_output *a,
		const struct lttng_snapshot_output *b)
{
	bool equal = false;

	assert(a);
	assert(b);

	if (a->max_size != b->max_size) {
		goto end;
	}

	if (strcmp(a->name, b->name) != 0) {
		goto end;
	}

	if (strcmp(a->ctrl_url, b->ctrl_url) != 0) {
		goto end;
	}

	if (strcmp(a->data_url, b->data_url) != 0) {
		goto end;
	}

	equal = true;

end:
	return equal;
}

/*
 * This is essentially the same as `struct lttng_snapshot_output`, but packed.
 */
struct lttng_snapshot_output_comm {
	uint32_t id;
	uint64_t max_size;
	char name[LTTNG_NAME_MAX];
	char ctrl_url[PATH_MAX];
	char data_url[PATH_MAX];
} LTTNG_PACKED;

LTTNG_HIDDEN
int lttng_snapshot_output_serialize(
		const struct lttng_snapshot_output *output,
		struct lttng_dynamic_buffer *buf)
{
	struct lttng_snapshot_output_comm comm;
	int ret;

	comm.id = output->id;
	comm.max_size = output->max_size;

	ret = lttng_strncpy(comm.name, output->name, sizeof(comm.name));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(comm.ctrl_url, output->ctrl_url, sizeof(comm.ctrl_url));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(comm.data_url, output->data_url, sizeof(comm.data_url));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(buf, &comm, sizeof(comm));
	if (ret) {
		goto end;
	}

end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_snapshot_output_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_snapshot_output **output_p)
{
	const struct lttng_snapshot_output_comm *comm;
	struct lttng_snapshot_output *output = NULL;
	int ret;

	if (view->size != sizeof(*comm)) {
		ret = -1;
		goto end;
	}

	output = lttng_snapshot_output_create();
	if (!output) {
		ret = -1;
		goto end;
	}

	comm = (const struct lttng_snapshot_output_comm *) view->data;

	output->id = comm->id;
	output->max_size = comm->max_size;

	ret = lttng_strncpy(output->name, comm->name, sizeof(output->name));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(output->ctrl_url, comm->ctrl_url, sizeof(output->ctrl_url));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(output->data_url, comm->data_url, sizeof(output->data_url));
	if (ret) {
		goto end;
	}

	*output_p = output;
	output = NULL;
	ret = sizeof(*comm);

end:
	lttng_snapshot_output_destroy(output);
	return ret;
}
