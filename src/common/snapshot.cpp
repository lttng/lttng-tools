/*
 * Copyright (C) 2020 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/mi-lttng.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/snapshot.hpp>
#include <lttng/snapshot-internal.hpp>
#include <lttng/snapshot.h>

#include <stdlib.h>

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

bool lttng_snapshot_output_is_equal(
		const struct lttng_snapshot_output *a,
		const struct lttng_snapshot_output *b)
{
	bool equal = false;

	LTTNG_ASSERT(a);
	LTTNG_ASSERT(b);

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

int lttng_snapshot_output_serialize(
		const struct lttng_snapshot_output *output,
		struct lttng_payload *payload)
{
	struct lttng_snapshot_output_comm comm;
	int ret;

	comm.id = output->id;
	comm.max_size = output->max_size;

	ret = lttng_strncpy(comm.name, output->name, sizeof(comm.name));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(
			comm.ctrl_url, output->ctrl_url, sizeof(comm.ctrl_url));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(
			comm.data_url, output->data_url, sizeof(comm.data_url));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		goto end;
	}

end:
	return ret;
}

ssize_t lttng_snapshot_output_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_snapshot_output **output_p)
{
	const struct lttng_snapshot_output_comm *comm;
	struct lttng_snapshot_output *output = NULL;
	int ret;

	if (view->buffer.size != sizeof(*comm)) {
		ret = -1;
		goto end;
	}

	output = lttng_snapshot_output_create();
	if (!output) {
		ret = -1;
		goto end;
	}

	comm = (typeof(comm)) view->buffer.data;

	output->id = comm->id;
	output->max_size = comm->max_size;

	ret = lttng_strncpy(output->name, comm->name, sizeof(output->name));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(output->ctrl_url, comm->ctrl_url,
			sizeof(output->ctrl_url));
	if (ret) {
		goto end;
	}

	ret = lttng_strncpy(output->data_url, comm->data_url,
			sizeof(output->data_url));
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

enum lttng_error_code lttng_snapshot_output_mi_serialize(
		const struct lttng_snapshot_output *output,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(output);
	LTTNG_ASSERT(writer);

	/* Open output element. */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_action_snapshot_session_output);
	if (ret) {
		goto mi_error;
	}

	/* Name. */
	if (strnlen(output->name, LTTNG_NAME_MAX) != 0) {
		ret = mi_lttng_writer_write_element_string(
				writer, config_element_name, output->name);
		if (ret) {
			goto mi_error;
		}
	}

	/* Control url (always present). */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_snapshot_ctrl_url, output->ctrl_url);
	if (ret) {
		goto mi_error;
	}

	/* Data url (optional). */
	if (strnlen(output->data_url, PATH_MAX) != 0) {
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_snapshot_data_url,
				output->data_url);
		if (ret) {
			goto mi_error;
		}
	}

	/*
	 * Maximum size in bytes of the snapshot meaning the total size of all
	 * streams combined. A value of 0 means unlimited. The default value is
	 * UINT64_MAX which also means unlimited in practice.
	 *
	 * The value is not serialized when it is set to either of those values
	 * to normalize them to '0'.
	 */
	if (output->max_size > 0 && output->max_size != UINT64_MAX) {
		/* Total size of all stream combined. */
		ret = mi_lttng_writer_write_element_unsigned_int(writer,
				mi_lttng_element_snapshot_max_size,
				output->max_size);
		if (ret) {
			goto mi_error;
		}
	}

	/* Close output element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}
