/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/align.hpp>
#include <common/buffer-view.hpp>
#include <common/compat/string.hpp>
#include <common/dynamic-array.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/constant.h>
#include <lttng/event-internal.hpp>
#include <lttng/event.h>
#include <lttng/lttng-error.h>
#include <lttng/userspace-probe-internal.hpp>

namespace {
struct event_list_element {
	struct lttng_event *event;
	struct lttng_event_exclusion *exclusions;
	char *filter_expression;
};
} /* namespace */

static void event_list_destructor(void *ptr)
{
	struct event_list_element *element = (struct event_list_element *) ptr;

	free(element->filter_expression);
	free(element->exclusions);
	lttng_event_destroy(element->event);
	free(element);
}

struct lttng_event *lttng_event_copy(const struct lttng_event *event)
{
	struct lttng_event *new_event;
	struct lttng_event_extended *new_event_extended;

	new_event = zmalloc<lttng_event>();
	if (!new_event) {
		PERROR("Error allocating event structure");
		goto end;
	}

	/* Copy the content of the old event. */
	memcpy(new_event, event, sizeof(*event));

	/*
	 * We need to create a new extended since the previous pointer is now
	 * invalid.
	 */
	new_event_extended = zmalloc<lttng_event_extended>();
	if (!new_event_extended) {
		PERROR("Error allocating event extended structure");
		goto error;
	}

	new_event->extended.ptr = new_event_extended;
end:
	return new_event;
error:
	free(new_event);
	new_event = nullptr;
	goto end;
}

static int lttng_event_probe_attr_serialize(const struct lttng_event_probe_attr *probe,
					    struct lttng_payload *payload)
{
	int ret;
	size_t symbol_name_len;
	struct lttng_event_probe_attr_comm comm = {};

	symbol_name_len = lttng_strnlen(probe->symbol_name, sizeof(probe->symbol_name));
	if (symbol_name_len == sizeof(probe->symbol_name)) {
		/* Not null-termintated. */
		ret = -1;
		goto end;
	}

	/* Include the null terminator. */
	symbol_name_len += 1;

	comm.symbol_name_len = (uint32_t) symbol_name_len;
	comm.addr = probe->addr;
	comm.offset = probe->addr;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
	if (ret < 0) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, probe->symbol_name, symbol_name_len);
end:
	return ret;
}

static int lttng_event_function_attr_serialize(const struct lttng_event_function_attr *function,
					       struct lttng_payload *payload)
{
	int ret;
	size_t symbol_name_len;
	struct lttng_event_function_attr_comm comm;

	comm.symbol_name_len = 0;

	symbol_name_len = lttng_strnlen(function->symbol_name, sizeof(function->symbol_name));
	if (symbol_name_len == sizeof(function->symbol_name)) {
		/* Not null-termintated. */
		ret = -1;
		goto end;
	}

	/* Include the null terminator. */
	symbol_name_len += 1;

	comm.symbol_name_len = (uint32_t) symbol_name_len;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
	if (ret < 0) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, function->symbol_name, symbol_name_len);
end:
	return ret;
}

static ssize_t
lttng_event_probe_attr_create_from_payload(struct lttng_payload_view *view,
					   struct lttng_event_probe_attr **probe_attr)
{
	ssize_t ret, offset = 0;
	const struct lttng_event_probe_attr_comm *comm;
	struct lttng_event_probe_attr *local_attr = nullptr;
	struct lttng_payload_view comm_view =
		lttng_payload_view_from_view(view, offset, sizeof(*comm));

	if (!lttng_payload_view_is_valid(&comm_view)) {
		ret = -1;
		goto end;
	}

	comm = (typeof(comm)) comm_view.buffer.data;
	offset += sizeof(*comm);

	local_attr = zmalloc<lttng_event_probe_attr>();
	if (local_attr == nullptr) {
		ret = -1;
		goto end;
	}

	local_attr->addr = comm->addr;
	local_attr->offset = comm->offset;

	{
		const char *name;
		struct lttng_payload_view name_view =
			lttng_payload_view_from_view(view, offset, comm->symbol_name_len);

		if (!lttng_payload_view_is_valid(&name_view)) {
			ret = -1;
			goto end;
		}

		name = name_view.buffer.data;

		if (!lttng_buffer_view_contains_string(
			    &name_view.buffer, name, comm->symbol_name_len)) {
			ret = -1;
			goto end;
		}

		ret = lttng_strncpy(local_attr->symbol_name, name, sizeof(local_attr->symbol_name));
		if (ret) {
			ret = -1;
			goto end;
		}

		offset += comm->symbol_name_len;
	}

	*probe_attr = local_attr;
	local_attr = nullptr;
	ret = offset;
end:
	free(local_attr);
	return ret;
}

static ssize_t
lttng_event_function_attr_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_event_function_attr **function_attr)
{
	ssize_t ret, offset = 0;
	const struct lttng_event_function_attr_comm *comm;
	struct lttng_event_function_attr *local_attr = nullptr;
	struct lttng_payload_view comm_view =
		lttng_payload_view_from_view(view, offset, sizeof(*comm));

	if (!lttng_payload_view_is_valid(&comm_view)) {
		ret = -1;
		goto end;
	}

	comm = (typeof(comm)) view->buffer.data;
	offset += sizeof(*comm);

	local_attr = zmalloc<lttng_event_function_attr>();
	if (local_attr == nullptr) {
		ret = -1;
		goto end;
	}

	{
		const char *name;
		struct lttng_payload_view name_view =
			lttng_payload_view_from_view(view, offset, comm->symbol_name_len);

		if (!lttng_payload_view_is_valid(&name_view)) {
			ret = -1;
			goto end;
		}

		name = name_view.buffer.data;

		if (!lttng_buffer_view_contains_string(
			    &name_view.buffer, name, comm->symbol_name_len)) {
			ret = -1;
			goto end;
		}

		ret = lttng_strncpy(local_attr->symbol_name, name, sizeof(local_attr->symbol_name));
		if (ret) {
			ret = -1;
			goto end;
		}

		offset += comm->symbol_name_len;
	}

	*function_attr = local_attr;
	local_attr = nullptr;
	ret = offset;
end:
	free(local_attr);
	return ret;
}

static ssize_t lttng_event_exclusions_create_from_payload(struct lttng_payload_view *view,
							  uint32_t count,
							  struct lttng_event_exclusion **exclusions)
{
	ssize_t ret, offset = 0;
	const size_t size = (count * LTTNG_SYMBOL_NAME_LEN);
	uint32_t i;
	const struct lttng_event_exclusion_comm *comm;
	struct lttng_event_exclusion *local_exclusions;

	local_exclusions =
		zmalloc<lttng_event_exclusion>(sizeof(struct lttng_event_exclusion) + size);
	if (!local_exclusions) {
		ret = -1;
		goto end;
	}

	local_exclusions->count = count;

	for (i = 0; i < count; i++) {
		const char *string;
		struct lttng_buffer_view string_view;
		const struct lttng_buffer_view comm_view =
			lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*comm));

		if (!lttng_buffer_view_is_valid(&comm_view)) {
			ret = -1;
			goto end;
		}

		comm = (typeof(comm)) comm_view.data;
		offset += sizeof(*comm);

		string_view = lttng_buffer_view_from_view(&view->buffer, offset, comm->len);

		if (!lttng_buffer_view_is_valid(&string_view)) {
			ret = -1;
			goto end;
		}

		string = string_view.data;

		if (!lttng_buffer_view_contains_string(&string_view, string, comm->len)) {
			ret = -1;
			goto end;
		}

		ret = lttng_strncpy(LTTNG_EVENT_EXCLUSION_NAME_AT(local_exclusions, i),
				    string,
				    sizeof(LTTNG_EVENT_EXCLUSION_NAME_AT(local_exclusions, i)));
		if (ret) {
			ret = -1;
			goto end;
		}

		offset += comm->len;
	}

	*exclusions = local_exclusions;
	local_exclusions = nullptr;
	ret = offset;
end:
	free(local_exclusions);
	return ret;
}

ssize_t lttng_event_create_from_payload(struct lttng_payload_view *view,
					struct lttng_event **out_event,
					struct lttng_event_exclusion **out_exclusion,
					char **out_filter_expression,
					struct lttng_bytecode **out_bytecode)
{
	ssize_t ret, offset = 0;
	struct lttng_event *local_event = nullptr;
	struct lttng_event_exclusion *local_exclusions = nullptr;
	struct lttng_bytecode *local_bytecode = nullptr;
	char *local_filter_expression = nullptr;
	const struct lttng_event_comm *event_comm;
	struct lttng_event_function_attr *local_function_attr = nullptr;
	struct lttng_event_probe_attr *local_probe_attr = nullptr;
	struct lttng_userspace_probe_location *local_userspace_probe_location = nullptr;

	/*
	 * Only event is obligatory, the other output argument are optional and
	 * depends on what the caller is interested in.
	 */
	assert(out_event);
	assert(view);

	{
		struct lttng_payload_view comm_view =
			lttng_payload_view_from_view(view, offset, sizeof(*event_comm));

		if (!lttng_payload_view_is_valid(&comm_view)) {
			ret = -1;
			goto end;
		}

		/* lttng_event_comm header */
		event_comm = (typeof(event_comm)) comm_view.buffer.data;
		offset += sizeof(*event_comm);
	}

	local_event = lttng_event_create();
	if (local_event == nullptr) {
		ret = -1;
		goto end;
	}

	local_event->type = (enum lttng_event_type) event_comm->event_type;
	local_event->loglevel_type = (enum lttng_loglevel_type) event_comm->loglevel_type;
	local_event->loglevel = event_comm->loglevel;
	local_event->enabled = !!event_comm->enabled;
	local_event->pid = event_comm->pid;
	local_event->flags = (enum lttng_event_flag) event_comm->flags;

	{
		const char *name;
		const struct lttng_buffer_view name_view =
			lttng_buffer_view_from_view(&view->buffer, offset, event_comm->name_len);

		if (!lttng_buffer_view_is_valid(&name_view)) {
			ret = -1;
			goto end;
		}

		name = (const char *) name_view.data;

		if (!lttng_buffer_view_contains_string(&name_view, name, event_comm->name_len)) {
			ret = -1;
			goto end;
		}

		ret = lttng_strncpy(local_event->name, name, sizeof(local_event->name));
		if (ret) {
			ret = -1;
			goto end;
		}

		offset += event_comm->name_len;
	}

	/* Exclusions */
	if (event_comm->exclusion_count == 0) {
		goto deserialize_filter_expression;
	}

	{
		struct lttng_payload_view exclusions_view =
			lttng_payload_view_from_view(view, offset, -1);

		if (!lttng_payload_view_is_valid(&exclusions_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_event_exclusions_create_from_payload(
			&exclusions_view, event_comm->exclusion_count, &local_exclusions);
		if (ret < 0) {
			ret = -1;
			goto end;
		}
		offset += ret;

		local_event->exclusion = 1;
	}

deserialize_filter_expression:

	if (event_comm->filter_expression_len == 0) {
		if (event_comm->bytecode_len != 0) {
			/*
			 * This is an invalid event payload.
			 *
			 * Filter expression without bytecode is possible but
			 * not the other way around.
			 * */
			ret = -1;
			goto end;
		}
		goto deserialize_event_type_payload;
	}

	{
		const char *filter_expression_buffer;
		struct lttng_buffer_view filter_expression_view = lttng_buffer_view_from_view(
			&view->buffer, offset, event_comm->filter_expression_len);

		if (!lttng_buffer_view_is_valid(&filter_expression_view)) {
			ret = -1;
			goto end;
		}

		filter_expression_buffer = filter_expression_view.data;

		if (!lttng_buffer_view_contains_string(&filter_expression_view,
						       filter_expression_buffer,
						       event_comm->filter_expression_len)) {
			ret = -1;
			goto end;
		}

		local_filter_expression =
			lttng_strndup(filter_expression_buffer, event_comm->filter_expression_len);
		if (!local_filter_expression) {
			ret = -1;
			goto end;
		}

		local_event->filter = 1;

		offset += event_comm->filter_expression_len;
	}

	if (event_comm->bytecode_len == 0) {
		/*
		 * Filter expression can be present but without bytecode
		 * when dealing with event listing.
		 */
		goto deserialize_event_type_payload;
	}

	/* Bytecode */
	{
		struct lttng_payload_view bytecode_view =
			lttng_payload_view_from_view(view, offset, event_comm->bytecode_len);

		if (!lttng_payload_view_is_valid(&bytecode_view)) {
			ret = -1;
			goto end;
		}

		local_bytecode = zmalloc<lttng_bytecode>(event_comm->bytecode_len);
		if (!local_bytecode) {
			ret = -1;
			goto end;
		}

		memcpy(local_bytecode, bytecode_view.buffer.data, event_comm->bytecode_len);
		if ((local_bytecode->len + sizeof(*local_bytecode)) != event_comm->bytecode_len) {
			ret = -1;
			goto end;
		}

		offset += event_comm->bytecode_len;
	}

deserialize_event_type_payload:
	/* Event type specific payload */
	switch (local_event->type) {
	case LTTNG_EVENT_FUNCTION:
		/* Fallthrough */
	case LTTNG_EVENT_PROBE:
	{
		struct lttng_payload_view probe_attr_view = lttng_payload_view_from_view(
			view, offset, event_comm->lttng_event_probe_attr_len);

		if (event_comm->lttng_event_probe_attr_len == 0) {
			ret = -1;
			goto end;
		}

		if (!lttng_payload_view_is_valid(&probe_attr_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_event_probe_attr_create_from_payload(&probe_attr_view,
								 &local_probe_attr);
		if (ret < 0 || ret != event_comm->lttng_event_probe_attr_len) {
			ret = -1;
			goto end;
		}

		/* Copy to the local event. */
		memcpy(&local_event->attr.probe, local_probe_attr, sizeof(local_event->attr.probe));

		offset += ret;
		break;
	}
	case LTTNG_EVENT_FUNCTION_ENTRY:
	{
		struct lttng_payload_view function_attr_view = lttng_payload_view_from_view(
			view, offset, event_comm->lttng_event_function_attr_len);

		if (event_comm->lttng_event_function_attr_len == 0) {
			ret = -1;
			goto end;
		}

		if (!lttng_payload_view_is_valid(&function_attr_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_event_function_attr_create_from_payload(&function_attr_view,
								    &local_function_attr);
		if (ret < 0 || ret != event_comm->lttng_event_function_attr_len) {
			ret = -1;
			goto end;
		}

		/* Copy to the local event. */
		memcpy(&local_event->attr.ftrace,
		       local_function_attr,
		       sizeof(local_event->attr.ftrace));

		offset += ret;

		break;
	}
	case LTTNG_EVENT_USERSPACE_PROBE:
	{
		struct lttng_payload_view userspace_probe_location_view =
			lttng_payload_view_from_view(
				view, offset, event_comm->userspace_probe_location_len);

		if (event_comm->userspace_probe_location_len == 0) {
			ret = -1;
			goto end;
		}

		if (!lttng_payload_view_is_valid(&userspace_probe_location_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_userspace_probe_location_create_from_payload(
			&userspace_probe_location_view, &local_userspace_probe_location);
		if (ret < 0) {
			WARN("Failed to create a userspace probe location from the received buffer");
			ret = -1;
			goto end;
		}

		if (ret != event_comm->userspace_probe_location_len) {
			WARN("Userspace probe location from the received buffer is not the advertised length: header length = %" PRIu32
			     ", payload length = %zd",
			     event_comm->userspace_probe_location_len,
			     ret);
			ret = -1;
			goto end;
		}

		/* Attach the probe location to the event. */
		ret = lttng_event_set_userspace_probe_location(local_event,
							       local_userspace_probe_location);
		if (ret) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto end;
		}

		/*
		 * Userspace probe location object ownership transfered to the
		 * event object.
		 */
		local_userspace_probe_location = nullptr;
		offset += event_comm->userspace_probe_location_len;
		break;
	}
	case LTTNG_EVENT_TRACEPOINT:
		/* Fallthrough */
	case LTTNG_EVENT_ALL:
		/* Fallthrough */
	case LTTNG_EVENT_SYSCALL:
		/* Fallthrough */
	case LTTNG_EVENT_NOOP:
		/* Nothing to do here */
		break;
	default:
		ret = LTTNG_ERR_UND;
		goto end;
		break;
	}

	/* Transfer ownership to the caller. */
	*out_event = local_event;
	local_event = nullptr;

	if (out_bytecode) {
		*out_bytecode = local_bytecode;
		local_bytecode = nullptr;
	}

	if (out_exclusion) {
		*out_exclusion = local_exclusions;
		local_exclusions = nullptr;
	}

	if (out_filter_expression) {
		*out_filter_expression = local_filter_expression;
		local_filter_expression = nullptr;
	}

	ret = offset;
end:
	lttng_event_destroy(local_event);
	lttng_userspace_probe_location_destroy(local_userspace_probe_location);
	free(local_filter_expression);
	free(local_exclusions);
	free(local_bytecode);
	free(local_function_attr);
	free(local_probe_attr);
	return ret;
}

int lttng_event_serialize(const struct lttng_event *event,
			  unsigned int exclusion_count,
			  const char *const *exclusion_list,
			  const char *filter_expression,
			  size_t bytecode_len,
			  struct lttng_bytecode *bytecode,
			  struct lttng_payload *payload)
{
	int ret;
	unsigned int i;
	size_t header_offset, size_before_payload;
	size_t name_len;
	struct lttng_event_comm event_comm = {};
	struct lttng_event_comm *header;

	assert(event);
	assert(payload);
	assert(exclusion_count == 0 || exclusion_list);

	/* Save the header location for later in-place header update. */
	header_offset = payload->buffer.size;

	name_len = lttng_strnlen(event->name, sizeof(event->name));
	if (name_len == sizeof(event->name)) {
		/* Event name is not NULL-terminated. */
		ret = -1;
		goto end;
	}

	/* Add null termination. */
	name_len += 1;

	if (exclusion_count > UINT32_MAX) {
		/* Possible overflow. */
		ret = -1;
		goto end;
	}

	if (bytecode_len > UINT32_MAX) {
		/* Possible overflow. */
		ret = -1;
		goto end;
	}

	event_comm.name_len = (uint32_t) name_len;
	event_comm.event_type = (int8_t) event->type;
	event_comm.loglevel_type = (int8_t) event->loglevel_type;
	event_comm.loglevel = (int32_t) event->loglevel;
	event_comm.enabled = (int8_t) event->enabled;
	event_comm.pid = (int32_t) event->pid;
	event_comm.exclusion_count = (uint32_t) exclusion_count;
	event_comm.bytecode_len = (uint32_t) bytecode_len;
	event_comm.flags = (int32_t) event->flags;

	if (filter_expression) {
		event_comm.filter_expression_len = strlen(filter_expression) + 1;
	}

	/* Header */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &event_comm, sizeof(event_comm));
	if (ret) {
		goto end;
	}

	/* Event name */
	ret = lttng_dynamic_buffer_append(&payload->buffer, event->name, name_len);
	if (ret) {
		goto end;
	}

	/* Exclusions */
	for (i = 0; i < exclusion_count; i++) {
		const size_t exclusion_len =
			lttng_strnlen(*(exclusion_list + i), LTTNG_SYMBOL_NAME_LEN);
		struct lttng_event_exclusion_comm exclusion_header = {};

		exclusion_header.len = (uint32_t) exclusion_len + 1;

		if (exclusion_len == LTTNG_SYMBOL_NAME_LEN) {
			/* Exclusion is not NULL-terminated. */
			ret = -1;
			goto end;
		}

		ret = lttng_dynamic_buffer_append(
			&payload->buffer, &exclusion_header, sizeof(exclusion_header));
		if (ret) {
			goto end;
		}

		ret = lttng_dynamic_buffer_append(
			&payload->buffer, *(exclusion_list + i), exclusion_len + 1);
		if (ret) {
			goto end;
		}
	}

	/* Filter expression and its bytecode */
	if (filter_expression) {
		ret = lttng_dynamic_buffer_append(
			&payload->buffer, filter_expression, event_comm.filter_expression_len);
		if (ret) {
			goto end;
		}

		/*
		 * Bytecode can be absent when we serialize to the client
		 * for listing.
		 */
		if (bytecode) {
			ret = lttng_dynamic_buffer_append(&payload->buffer, bytecode, bytecode_len);
			if (ret) {
				goto end;
			}
		}
	}

	size_before_payload = payload->buffer.size;

	/* Event type specific payload */
	switch (event->type) {
	case LTTNG_EVENT_FUNCTION:
		/* Fallthrough */
	case LTTNG_EVENT_PROBE:
		ret = lttng_event_probe_attr_serialize(&event->attr.probe, payload);
		if (ret) {
			ret = -1;
			goto end;
		}

		header =
			(struct lttng_event_comm *) ((char *) payload->buffer.data + header_offset);
		header->lttng_event_probe_attr_len = payload->buffer.size - size_before_payload;

		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		ret = lttng_event_function_attr_serialize(&event->attr.ftrace, payload);
		if (ret) {
			ret = -1;
			goto end;
		}

		/* Update the lttng_event_function_attr len. */
		header =
			(struct lttng_event_comm *) ((char *) payload->buffer.data + header_offset);
		header->lttng_event_function_attr_len = payload->buffer.size - size_before_payload;

		break;
	case LTTNG_EVENT_USERSPACE_PROBE:
	{
		const struct lttng_event_extended *ev_ext =
			(const struct lttng_event_extended *) event->extended.ptr;

		assert(event->extended.ptr);
		assert(ev_ext->probe_location);

		size_before_payload = payload->buffer.size;
		if (ev_ext->probe_location) {
			/*
			 * lttng_userspace_probe_location_serialize returns the
			 * number of bytes that were appended to the buffer.
			 */
			ret = lttng_userspace_probe_location_serialize(ev_ext->probe_location,
								       payload);
			if (ret < 0) {
				goto end;
			}

			ret = 0;

			/* Update the userspace probe location len. */
			header = (struct lttng_event_comm *) ((char *) payload->buffer.data +
							      header_offset);
			header->userspace_probe_location_len =
				payload->buffer.size - size_before_payload;
		}
		break;
	}
	case LTTNG_EVENT_TRACEPOINT:
		/* Fallthrough */
	case LTTNG_EVENT_ALL:
		/* Fallthrough */
	default:
		/* Nothing to do here. */
		break;
	}

end:
	return ret;
}

static ssize_t lttng_event_context_app_populate_from_payload(const struct lttng_payload_view *view,
							     struct lttng_event_context *event_ctx)
{
	ssize_t ret, offset = 0;
	const struct lttng_event_context_app_comm *comm;
	char *provider_name = nullptr, *context_name = nullptr;
	size_t provider_name_len, context_name_len;
	const struct lttng_buffer_view comm_view =
		lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*comm));

	assert(event_ctx->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT);

	if (!lttng_buffer_view_is_valid(&comm_view)) {
		ret = -1;
		goto end;
	}

	comm = (typeof(comm)) comm_view.data;
	offset += sizeof(*comm);

	provider_name_len = comm->provider_name_len;
	context_name_len = comm->ctx_name_len;

	if (provider_name_len == 0 || context_name_len == 0) {
		/*
		 * Application provider and context names MUST
		 * be provided.
		 */
		ret = -1;
		goto end;
	}

	{
		const char *name;
		const struct lttng_buffer_view provider_name_view =
			lttng_buffer_view_from_view(&view->buffer, offset, provider_name_len);

		if (!lttng_buffer_view_is_valid(&provider_name_view)) {
			ret = -1;
			goto end;
		}

		name = provider_name_view.data;

		if (!lttng_buffer_view_contains_string(
			    &provider_name_view, name, provider_name_len)) {
			ret = -1;
			goto end;
		}

		provider_name = lttng_strndup(name, provider_name_len);
		if (!provider_name) {
			ret = -1;
			goto end;
		}

		offset += provider_name_len;
	}

	{
		const char *name;
		const struct lttng_buffer_view context_name_view =
			lttng_buffer_view_from_view(&view->buffer, offset, context_name_len);

		if (!lttng_buffer_view_is_valid(&context_name_view)) {
			ret = -1;
			goto end;
		}

		name = context_name_view.data;

		if (!lttng_buffer_view_contains_string(&context_name_view, name, context_name_len)) {
			ret = -1;
			goto end;
		}

		context_name = lttng_strndup(name, context_name_len);
		if (!context_name) {
			ret = -1;
			goto end;
		}

		offset += context_name_len;
	}

	/* Transfer ownership of the strings */
	event_ctx->u.app_ctx.provider_name = provider_name;
	event_ctx->u.app_ctx.ctx_name = context_name;
	provider_name = nullptr;
	context_name = nullptr;

	ret = offset;
end:
	free(provider_name);
	free(context_name);

	return ret;
}

static ssize_t
lttng_event_context_perf_counter_populate_from_payload(const struct lttng_payload_view *view,
						       struct lttng_event_context *event_ctx)
{
	int ret;
	ssize_t consumed, offset = 0;
	const struct lttng_event_context_perf_counter_comm *comm;
	size_t name_len;
	const struct lttng_buffer_view comm_view =
		lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*comm));

	assert(event_ctx->ctx == LTTNG_EVENT_CONTEXT_PERF_COUNTER ||
	       event_ctx->ctx == LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER ||
	       event_ctx->ctx == LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER);

	if (!lttng_buffer_view_is_valid(&comm_view)) {
		consumed = -1;
		goto end;
	}

	comm = (typeof(comm)) comm_view.data;
	offset += sizeof(*comm);

	name_len = comm->name_len;

	{
		const char *name;
		const struct lttng_buffer_view provider_name_view =
			lttng_buffer_view_from_view(&view->buffer, offset, name_len);

		if (!lttng_buffer_view_is_valid(&provider_name_view)) {
			consumed = -1;
			goto end;
		}

		name = provider_name_view.data;

		if (!lttng_buffer_view_contains_string(&provider_name_view, name, name_len)) {
			consumed = -1;
			goto end;
		}

		ret = lttng_strncpy(event_ctx->u.perf_counter.name,
				    name,
				    sizeof(event_ctx->u.perf_counter.name));
		if (ret) {
			consumed = -1;
			goto end;
		}
		offset += name_len;
	}

	event_ctx->u.perf_counter.config = comm->config;
	event_ctx->u.perf_counter.type = comm->type;

	consumed = offset;

end:
	return consumed;
}

ssize_t lttng_event_context_create_from_payload(struct lttng_payload_view *view,
						struct lttng_event_context **event_ctx)
{
	ssize_t ret, offset = 0;
	const struct lttng_event_context_comm *comm;
	struct lttng_event_context *local_context = nullptr;
	struct lttng_buffer_view comm_view =
		lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*comm));

	assert(event_ctx);
	assert(view);

	if (!lttng_buffer_view_is_valid(&comm_view)) {
		ret = -1;
		goto end;
	}

	comm = (typeof(comm)) comm_view.data;
	offset += sizeof(*comm);

	local_context = zmalloc<lttng_event_context>();
	if (!local_context) {
		ret = -1;
		goto end;
	}

	local_context->ctx = (lttng_event_context_type) comm->type;

	{
		struct lttng_payload_view subtype_view =
			lttng_payload_view_from_view(view, offset, -1);

		switch (local_context->ctx) {
		case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
			ret = lttng_event_context_app_populate_from_payload(&subtype_view,
									    local_context);
			break;
		case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
		case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
		case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
			ret = lttng_event_context_perf_counter_populate_from_payload(&subtype_view,
										     local_context);
			break;
		default:
			/* Nothing else to deserialize. */
			ret = 0;
			break;
		}
	}

	if (ret < 0) {
		goto end;
	}

	offset += ret;

	*event_ctx = local_context;
	local_context = nullptr;
	ret = offset;

end:
	free(local_context);
	return ret;
}

static int lttng_event_context_app_serialize(struct lttng_event_context *context,
					     struct lttng_payload *payload)
{
	int ret;
	struct lttng_event_context_app_comm comm = {};
	size_t provider_len, ctx_len;
	const char *provider_name;
	const char *ctx_name;

	assert(payload);
	assert(context);
	assert(context->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT);

	provider_name = context->u.app_ctx.provider_name;
	ctx_name = context->u.app_ctx.ctx_name;

	if (!provider_name || !ctx_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	provider_len = strlen(provider_name);
	if (provider_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/* Include the null terminator. */
	provider_len += 1;
	comm.provider_name_len = provider_len;

	ctx_len = strlen(ctx_name);
	if (ctx_len == 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/* Include the null terminator. */
	ctx_len += 1;
	comm.ctx_name_len = ctx_len;

	/* Header */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, provider_name, provider_len);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, ctx_name, ctx_len);
	if (ret) {
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static int lttng_event_context_perf_counter_serialize(struct lttng_event_perf_counter_ctx *context,
						      struct lttng_payload *payload)
{
	int ret;
	struct lttng_event_context_perf_counter_comm comm = {};

	assert(payload);
	assert(context);

	comm.config = context->config;
	comm.type = context->type;
	comm.name_len = lttng_strnlen(context->name, sizeof(context->name));

	if (comm.name_len == sizeof(context->name)) {
		ret = -1;
		goto end;
	}

	/* Include the null terminator. */
	comm.name_len += 1;

	/* Header */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, context->name, comm.name_len);
	if (ret) {
		ret = -1;
		goto end;
	}

end:
	return ret;
}

int lttng_event_context_serialize(struct lttng_event_context *context,
				  struct lttng_payload *payload)
{
	int ret;
	struct lttng_event_context_comm context_comm;

	context_comm.type = 0;

	assert(context);
	assert(payload);

	context_comm.type = (uint32_t) context->ctx;

	/* Header */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &context_comm, sizeof(context_comm));
	if (ret) {
		goto end;
	}

	switch (context->ctx) {
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
		ret = lttng_event_context_app_serialize(context, payload);
		break;
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
		ret = lttng_event_context_perf_counter_serialize(&context->u.perf_counter, payload);
		break;
	default:
		/* Nothing else to serialize. */
		break;
	}

	if (ret) {
		goto end;
	}

end:
	return ret;
}

void lttng_event_context_destroy(struct lttng_event_context *context)
{
	if (!context) {
		return;
	}

	if (context->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		free(context->u.app_ctx.provider_name);
		free(context->u.app_ctx.ctx_name);
	}

	free(context);
}

/*
 * This is a specialized populate for lttng_event_field since it ignores
 * the extension field of the lttng_event struct and simply copies what it can
 * to the internal struct lttng_event of a lttng_event_field.
 */
static void lttng_event_field_populate_lttng_event_from_event(const struct lttng_event *src,
							      struct lttng_event *destination)
{
	memcpy(destination, src, sizeof(*destination));

	/* Remove all possible dynamic data from the destination event rule. */
	destination->extended.ptr = nullptr;
}

ssize_t lttng_event_field_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_event_field **field)
{
	ssize_t ret, offset = 0;
	struct lttng_event_field *local_event_field = nullptr;
	struct lttng_event *event = nullptr;
	const struct lttng_event_field_comm *comm;
	const char *name = nullptr;

	assert(field);
	assert(view);

	{
		const struct lttng_buffer_view comm_view =
			lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*comm));

		if (!lttng_buffer_view_is_valid(&comm_view)) {
			ret = -1;
			goto end;
		}

		/* lttng_event_field_comm header */
		comm = (const lttng_event_field_comm *) comm_view.data;
		offset += sizeof(*comm);
	}

	local_event_field = zmalloc<lttng_event_field>();
	if (!local_event_field) {
		ret = -1;
		goto end;
	}

	local_event_field->type = (lttng_event_field_type) comm->type;
	local_event_field->nowrite = comm->nowrite;

	/* Field name */
	{
		const struct lttng_buffer_view name_view =
			lttng_buffer_view_from_view(&view->buffer, offset, comm->name_len);

		if (!lttng_buffer_view_is_valid(&name_view)) {
			ret = -1;
			goto end;
		}

		name = name_view.data;

		if (!lttng_buffer_view_contains_string(&name_view, name_view.data, comm->name_len)) {
			ret = -1;
			goto end;
		}

		if (comm->name_len > LTTNG_SYMBOL_NAME_LEN - 1) {
			/* Name is too long.*/
			ret = -1;
			goto end;
		}

		offset += comm->name_len;
	}

	/* Event */
	{
		struct lttng_payload_view event_view =
			lttng_payload_view_from_view(view, offset, comm->event_len);

		if (!lttng_payload_view_is_valid(&event_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_event_create_from_payload(
			&event_view, &event, nullptr, nullptr, nullptr);
		if (ret != comm->event_len) {
			ret = -1;
			goto end;
		}

		offset += ret;
	}

	assert(name);
	assert(event);

	if (lttng_strncpy(
		    local_event_field->field_name, name, sizeof(local_event_field->field_name))) {
		ret = -1;
		goto end;
	}

	lttng_event_field_populate_lttng_event_from_event(event, &local_event_field->event);

	*field = local_event_field;
	local_event_field = nullptr;
	ret = offset;
end:
	lttng_event_destroy(event);
	free(local_event_field);
	return ret;
}

int lttng_event_field_serialize(const struct lttng_event_field *field,
				struct lttng_payload *payload)
{
	int ret;
	size_t header_offset, size_before_event;
	size_t name_len;
	struct lttng_event_field_comm event_field_comm = {};
	struct lttng_event_field_comm *header;

	assert(field);
	assert(payload);

	/* Save the header location for later in-place header update. */
	header_offset = payload->buffer.size;

	name_len = strnlen(field->field_name, sizeof(field->field_name));
	if (name_len == sizeof(field->field_name)) {
		/* Event name is not NULL-terminated. */
		ret = -1;
		goto end;
	}

	/* Add null termination. */
	name_len += 1;

	event_field_comm.type = field->type;
	event_field_comm.nowrite = (uint8_t) field->nowrite;
	event_field_comm.name_len = name_len;

	/* Header */
	ret = lttng_dynamic_buffer_append(
		&payload->buffer, &event_field_comm, sizeof(event_field_comm));
	if (ret) {
		goto end;
	}

	/* Field name */
	ret = lttng_dynamic_buffer_append(&payload->buffer, field->field_name, name_len);
	if (ret) {
		goto end;
	}

	size_before_event = payload->buffer.size;
	ret = lttng_event_serialize(&field->event, 0, nullptr, nullptr, 0, nullptr, payload);
	if (ret) {
		ret = -1;
		goto end;
	}

	/* Update the event len. */
	header = (struct lttng_event_field_comm *) ((char *) payload->buffer.data + header_offset);
	header->event_len = payload->buffer.size - size_before_event;

end:
	return ret;
}

static enum lttng_error_code compute_flattened_size(struct lttng_dynamic_pointer_array *events,
						    size_t *size)
{
	enum lttng_error_code ret_code;
	int ret = 0;
	size_t storage_req, event_count, i;

	assert(size);
	assert(events);

	event_count = lttng_dynamic_pointer_array_get_count(events);

	/* The basic struct lttng_event */
	storage_req = event_count * sizeof(struct lttng_event);

	/* The struct·lttng_event_extended */
	storage_req += event_count * sizeof(struct lttng_event_extended);

	for (i = 0; i < event_count; i++) {
		int probe_storage_req = 0;
		const struct event_list_element *element =
			(const struct event_list_element *) lttng_dynamic_pointer_array_get_pointer(
				events, i);
		const struct lttng_userspace_probe_location *location = nullptr;

		location = lttng_event_get_userspace_probe_location(element->event);
		if (location) {
			ret = lttng_userspace_probe_location_flatten(location, nullptr);
			if (ret < 0) {
				ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
				goto end;
			}

			probe_storage_req = ret;
		}

		if (element->filter_expression) {
			storage_req += strlen(element->filter_expression) + 1;
		}

		if (element->exclusions) {
			storage_req += element->exclusions->count * LTTNG_SYMBOL_NAME_LEN;
		}

		/* Padding to ensure the flat probe is aligned. */
		storage_req = lttng_align_ceil(storage_req, sizeof(uint64_t));
		storage_req += probe_storage_req;
	}

	*size = storage_req;
	ret_code = LTTNG_OK;

end:
	return ret_code;
}

/*
 * Flatten a list of struct lttng_event.
 *
 * The buffer that is returned to the API client  must contain a "flat" version
 * of the events that are returned. In other words, all pointers within an
 * lttng_event must point to a location within the returned buffer so that the
 * user may free everything by simply calling free() on the returned buffer.
 * This is needed in order to maintain API compatibility.
 *
 * A first pass is performed to compute the size of the buffer that must be
 * allocated. A second pass is then performed to setup the returned events so
 * that their members always point within the buffer.
 *
 * The layout of the returned buffer is as follows:
 *   - struct lttng_event[nb_events],
 *   - nb_events times the following:
 *     - struct lttng_event_extended,
 *     - filter_expression
 *     - exclusions
 *     - padding to align to 64-bits
 *     - flattened version of userspace_probe_location
 */
static enum lttng_error_code flatten_lttng_events(struct lttng_dynamic_pointer_array *events,
						  struct lttng_event **flattened_events)
{
	enum lttng_error_code ret_code;
	int ret, i;
	size_t storage_req;
	struct lttng_dynamic_buffer local_flattened_events;
	int nb_events;

	assert(events);
	assert(flattened_events);

	lttng_dynamic_buffer_init(&local_flattened_events);
	nb_events = lttng_dynamic_pointer_array_get_count(events);

	ret_code = compute_flattened_size(events, &storage_req);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/*
	 * We must ensure that "local_flattened_events" is never resized so as
	 * to preserve the validity of the flattened objects.
	 */
	ret = lttng_dynamic_buffer_set_capacity(&local_flattened_events, storage_req);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Start by laying the struct lttng_event */
	for (i = 0; i < nb_events; i++) {
		const struct event_list_element *element =
			(const struct event_list_element *) lttng_dynamic_pointer_array_get_pointer(
				events, i);

		if (!element) {
			ret_code = LTTNG_ERR_FATAL;
			goto end;
		}

		ret = lttng_dynamic_buffer_append(
			&local_flattened_events, element->event, sizeof(struct lttng_event));
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	for (i = 0; i < nb_events; i++) {
		const struct event_list_element *element =
			(const struct event_list_element *) lttng_dynamic_pointer_array_get_pointer(
				events, i);
		struct lttng_event *event =
			(struct lttng_event *) (local_flattened_events.data +
						(sizeof(struct lttng_event) * i));
		struct lttng_event_extended *event_extended =
			(struct lttng_event_extended *) (local_flattened_events.data +
							 local_flattened_events.size);
		const struct lttng_userspace_probe_location *location = nullptr;

		assert(element);

		/* Insert struct lttng_event_extended. */
		ret = lttng_dynamic_buffer_set_size(&local_flattened_events,
						    local_flattened_events.size +
							    sizeof(*event_extended));
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
		event->extended.ptr = event_extended;

		/* Insert filter expression. */
		if (element->filter_expression) {
			const size_t len = strlen(element->filter_expression) + 1;

			event_extended->filter_expression =
				local_flattened_events.data + local_flattened_events.size;
			ret = lttng_dynamic_buffer_append(
				&local_flattened_events, element->filter_expression, len);
			if (ret) {
				ret_code = LTTNG_ERR_NOMEM;
				goto end;
			}
		}

		/* Insert exclusions. */
		if (element->exclusions) {
			event_extended->exclusions.count = element->exclusions->count;
			event_extended->exclusions.strings =
				local_flattened_events.data + local_flattened_events.size;

			ret = lttng_dynamic_buffer_append(&local_flattened_events,
							  element->exclusions->names,
							  element->exclusions->count *
								  LTTNG_SYMBOL_NAME_LEN);
			if (ret) {
				ret_code = LTTNG_ERR_NOMEM;
				goto end;
			}
		}

		/* Insert padding to align to 64-bits. */
		ret = lttng_dynamic_buffer_set_size(&local_flattened_events,
						    lttng_align_ceil(local_flattened_events.size,
								     sizeof(uint64_t)));
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		location = lttng_event_get_userspace_probe_location(element->event);
		if (location) {
			event_extended->probe_location = (struct lttng_userspace_probe_location
								  *) (local_flattened_events.data +
								      local_flattened_events.size);
			ret = lttng_userspace_probe_location_flatten(location,
								     &local_flattened_events);
			if (ret < 0) {
				ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
				goto end;
			}
		}
	}

	/* Don't reset local_flattened_events buffer as we return its content. */
	*flattened_events = (struct lttng_event *) local_flattened_events.data;
	lttng_dynamic_buffer_init(&local_flattened_events);
	ret_code = LTTNG_OK;
end:
	lttng_dynamic_buffer_reset(&local_flattened_events);
	return ret_code;
}

static enum lttng_error_code
event_list_create_from_payload(struct lttng_payload_view *view,
			       unsigned int count,
			       struct lttng_dynamic_pointer_array *event_list)
{
	enum lttng_error_code ret_code;
	int ret;
	unsigned int i;
	int offset = 0;

	assert(view);
	assert(event_list);

	for (i = 0; i < count; i++) {
		ssize_t event_size;
		struct lttng_payload_view event_view =
			lttng_payload_view_from_view(view, offset, -1);
		struct event_list_element *element = zmalloc<event_list_element>();

		if (!element) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		/*
		 * Lifetime and management of the object is now bound to the
		 * array.
		 */
		ret = lttng_dynamic_pointer_array_add_pointer(event_list, element);
		if (ret) {
			event_list_destructor(element);
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		/*
		 * Bytecode is not transmitted on listing in any case we do not
		 * care about it.
		 */
		event_size = lttng_event_create_from_payload(&event_view,
							     &element->event,
							     &element->exclusions,
							     &element->filter_expression,
							     nullptr);
		if (event_size < 0) {
			ret_code = LTTNG_ERR_INVALID;
			goto end;
		}

		offset += event_size;
	}

	if (view->buffer.size != offset) {
		ret_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end;
	}

	ret_code = LTTNG_OK;

end:
	return ret_code;
}

enum lttng_error_code lttng_events_create_and_flatten_from_payload(
	struct lttng_payload_view *payload, unsigned int count, struct lttng_event **events)
{
	enum lttng_error_code ret = LTTNG_OK;
	struct lttng_dynamic_pointer_array local_events;

	lttng_dynamic_pointer_array_init(&local_events, event_list_destructor);

	/* Deserialize the events. */
	{
		struct lttng_payload_view events_view =
			lttng_payload_view_from_view(payload, 0, -1);

		ret = event_list_create_from_payload(&events_view, count, &local_events);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	ret = flatten_lttng_events(&local_events, events);
	if (ret != LTTNG_OK) {
		goto end;
	}

end:
	lttng_dynamic_pointer_array_reset(&local_events);
	return ret;
}

static enum lttng_error_code
flatten_lttng_event_fields(struct lttng_dynamic_pointer_array *event_fields,
			   struct lttng_event_field **flattened_event_fields)
{
	int ret, i;
	enum lttng_error_code ret_code;
	size_t storage_req = 0;
	struct lttng_dynamic_buffer local_flattened_event_fields;
	int nb_event_field;

	assert(event_fields);
	assert(flattened_event_fields);

	lttng_dynamic_buffer_init(&local_flattened_event_fields);
	nb_event_field = lttng_dynamic_pointer_array_get_count(event_fields);

	/*
	 * Here even if the event field contains a `struct lttng_event` that
	 * could contain dynamic data, in reality it is not the case.
	 * Dynamic data is not present. Here the flattening is mostly a direct
	 * memcpy. This is less than ideal but this code is still better than
	 * direct usage of an unpacked lttng_event_field array.
	 */
	storage_req += sizeof(struct lttng_event_field) * nb_event_field;

	lttng_dynamic_buffer_init(&local_flattened_event_fields);

	/*
	 * We must ensure that "local_flattened_event_fields" is never resized
	 * so as to preserve the validity of the flattened objects.
	 */
	ret = lttng_dynamic_buffer_set_capacity(&local_flattened_event_fields, storage_req);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	for (i = 0; i < nb_event_field; i++) {
		const struct lttng_event_field *element =
			(const struct lttng_event_field *) lttng_dynamic_pointer_array_get_pointer(
				event_fields, i);

		if (!element) {
			ret_code = LTTNG_ERR_FATAL;
			goto end;
		}
		ret = lttng_dynamic_buffer_append(
			&local_flattened_event_fields, element, sizeof(struct lttng_event_field));
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	/* Don't reset local_flattened_channels buffer as we return its content. */
	*flattened_event_fields = (struct lttng_event_field *) local_flattened_event_fields.data;
	lttng_dynamic_buffer_init(&local_flattened_event_fields);
	ret_code = LTTNG_OK;
end:
	lttng_dynamic_buffer_reset(&local_flattened_event_fields);
	return ret_code;
}

static enum lttng_error_code
event_field_list_create_from_payload(struct lttng_payload_view *view,
				     unsigned int count,
				     struct lttng_dynamic_pointer_array **event_field_list)
{
	enum lttng_error_code ret_code;
	int ret, offset = 0;
	unsigned int i;
	struct lttng_dynamic_pointer_array *list = nullptr;

	assert(view);
	assert(event_field_list);

	list = zmalloc<lttng_dynamic_pointer_array>();
	if (!list) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	lttng_dynamic_pointer_array_init(list, free);

	for (i = 0; i < count; i++) {
		ssize_t event_field_size;
		struct lttng_event_field *field = nullptr;
		struct lttng_payload_view event_field_view =
			lttng_payload_view_from_view(view, offset, -1);

		event_field_size = lttng_event_field_create_from_payload(&event_field_view, &field);
		if (event_field_size < 0) {
			ret_code = LTTNG_ERR_INVALID;
			goto end;
		}

		/* Lifetime and management of the object is now bound to the array. */
		ret = lttng_dynamic_pointer_array_add_pointer(list, field);
		if (ret) {
			free(field);
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		offset += event_field_size;
	}

	if (view->buffer.size != offset) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	*event_field_list = list;
	list = nullptr;
	ret_code = LTTNG_OK;

end:
	if (list) {
		lttng_dynamic_pointer_array_reset(list);
		free(list);
	}

	return ret_code;
}

enum lttng_error_code lttng_event_fields_create_and_flatten_from_payload(
	struct lttng_payload_view *view, unsigned int count, struct lttng_event_field **fields)
{
	enum lttng_error_code ret_code;
	struct lttng_dynamic_pointer_array *local_event_fields = nullptr;

	ret_code = event_field_list_create_from_payload(view, count, &local_event_fields);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	ret_code = flatten_lttng_event_fields(local_event_fields, fields);
	if (ret_code != LTTNG_OK) {
		goto end;
	}
end:
	if (local_event_fields) {
		lttng_dynamic_pointer_array_reset(local_event_fields);
		free(local_event_fields);
	}

	return ret_code;
}
