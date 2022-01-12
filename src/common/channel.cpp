/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/macros.h>
#include <lttng/channel.h>
#include <lttng/constant.h>
#include <lttng/channel-internal.h>
#include <lttng/userspace-probe-internal.h>
#include <common/dynamic-buffer.h>
#include <common/error.h>
#include <assert.h>
#include <string.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/dynamic-array.h>
#include <common/buffer-view.h>

static enum lttng_error_code flatten_lttng_channels(
		struct lttng_dynamic_pointer_array *channels,
		struct lttng_channel **flattened_channels);

static enum lttng_error_code channel_list_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		uint32_t count,
		struct lttng_dynamic_pointer_array *channel_list);

static void channel_list_destructor(void *ptr)
{
	struct lttng_channel *element = (struct lttng_channel *) ptr;

	lttng_channel_destroy(element);
}

struct lttng_channel *lttng_channel_copy(const struct lttng_channel *src)
{
	struct lttng_channel_extended *extended = nullptr;
	struct lttng_channel *channel = nullptr, *ret = nullptr;

	channel = (struct lttng_channel *) zmalloc(sizeof(*channel));
	if (!channel) {
		goto end;
	}

	*channel = *src;

	if (src->attr.extended.ptr) {
		extended = (struct lttng_channel_extended *) zmalloc(
				sizeof(*extended));
		if (!extended) {
			goto end;
		}
		memcpy(extended, src->attr.extended.ptr, sizeof(*extended));
		channel->attr.extended.ptr = extended;
		extended = nullptr;
	}

	ret = channel;
	channel = nullptr;
end:
	free(channel);
	free(extended);
	return ret;
}

/*
 * The channel object is NOT populated.
 */
struct lttng_channel *lttng_channel_create_internal(void)
{
	struct lttng_channel *local_channel = nullptr, *ret = nullptr;
	struct lttng_channel_extended *extended = nullptr;

	local_channel = (struct lttng_channel *) zmalloc(
			sizeof(struct lttng_channel));
	if (!local_channel) {
		goto end;
	}

	/* Extended struct */
	extended = (struct lttng_channel_extended *) zmalloc(
			sizeof(*extended));
	if (!extended) {
		goto end;
	}

	local_channel->attr.extended.ptr = extended;
	extended = nullptr;

	ret = local_channel;
	local_channel = nullptr;
end:
	free(extended);
	free(local_channel);
	return ret;
}

ssize_t lttng_channel_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_channel **channel)
{
	ssize_t ret, offset = 0;
	struct lttng_channel *local_channel = nullptr;
	const struct lttng_channel_comm *channel_comm;
	struct lttng_channel_extended *extended = nullptr;

	assert(channel);

	if (!view || !channel) {
		ret = -1;
		goto end;
	}

	/*
	 * Create an 'internal' channel since `lttng_create_channel` requires a
	 * domain and we cannot infer the domain from the payload.
	 */
	local_channel = lttng_channel_create_internal();
	if (!local_channel) {
		ret = -1;
		goto end;
	}

	extended = (typeof(extended)) local_channel->attr.extended.ptr;

	/* lttng_trigger_comm header */
	{
		const struct lttng_buffer_view comm_view =
				lttng_buffer_view_from_view(view, offset,
						sizeof(*channel_comm));

		if (!lttng_buffer_view_is_valid(&comm_view)) {
			ret = -1;
			goto end;
		}

		channel_comm = (const struct lttng_channel_comm *)
					       comm_view.data;
		offset += sizeof(*channel_comm);
	}

	{
		const char *name;
		const struct lttng_buffer_view name_view =
				lttng_buffer_view_from_view(view, offset,
						channel_comm->name_len);

		if (channel_comm->name_len > LTTNG_SYMBOL_NAME_LEN - 1) {
			ret = -1;
			goto end;
		}

		name = name_view.data;
		if (!lttng_buffer_view_contains_string(
				    &name_view, name, channel_comm->name_len)) {
			ret = -1;
			goto end;
		}

		strcpy(local_channel->name, name);
		offset += channel_comm->name_len;
	}

	/* Populate the channel */
	local_channel->enabled = channel_comm->enabled;

	/* attr */
	local_channel->attr.overwrite = channel_comm->overwrite;
	local_channel->attr.subbuf_size = channel_comm->subbuf_size;
	local_channel->attr.num_subbuf = channel_comm->num_subbuf;
	local_channel->attr.switch_timer_interval =
			channel_comm->switch_timer_interval;
	local_channel->attr.read_timer_interval =
			channel_comm->read_timer_interval;
	local_channel->attr.output = (enum lttng_event_output) channel_comm->output;
	local_channel->attr.tracefile_size = channel_comm->tracefile_size;
	local_channel->attr.tracefile_count = channel_comm->tracefile_count;
	local_channel->attr.live_timer_interval =
			channel_comm->live_timer_interval;

	extended->discarded_events = channel_comm->discarded_events;
	extended->lost_packets = channel_comm->lost_packets;
	extended->monitor_timer_interval = channel_comm->monitor_timer_interval;
	extended->blocking_timeout = channel_comm->blocking_timeout;

	*channel = local_channel;
	local_channel = nullptr;

	ret = offset;
end:
	lttng_channel_destroy(local_channel);
	return ret;
}

int lttng_channel_serialize(
		struct lttng_channel *channel, struct lttng_dynamic_buffer *buf)
{
	int ret;
	size_t name_len;
	struct lttng_channel_comm channel_comm = { 0 };
	struct lttng_channel_extended *extended;

	assert(channel);
	assert(buf);

	extended = (struct lttng_channel_extended *) channel->attr.extended.ptr;

	name_len = lttng_strnlen(channel->name, LTTNG_SYMBOL_NAME_LEN);
	if (name_len == LTTNG_SYMBOL_NAME_LEN) {
		/* channel name is not nullptr-terminated. */
		ret = -1;
		goto end;
	}

	/* Include string termination. */
	name_len += 1;

	/* Base field */
	channel_comm.name_len = (uint32_t) name_len;
	channel_comm.enabled = channel->enabled;

	/* attr */
	channel_comm.overwrite = channel->attr.overwrite;
	channel_comm.subbuf_size = channel->attr.subbuf_size;
	channel_comm.num_subbuf = channel->attr.num_subbuf;
	channel_comm.switch_timer_interval =
			channel->attr.switch_timer_interval;
	channel_comm.read_timer_interval = channel->attr.read_timer_interval;
	channel_comm.output = channel->attr.output;
	channel_comm.tracefile_size = channel->attr.tracefile_size;
	channel_comm.tracefile_count = channel->attr.tracefile_count;
	channel_comm.live_timer_interval = channel->attr.live_timer_interval;

	/* Extended struct */
	channel_comm.discarded_events = extended->discarded_events;
	channel_comm.lost_packets = extended->lost_packets;
	channel_comm.monitor_timer_interval = extended->monitor_timer_interval;
	channel_comm.blocking_timeout = extended->blocking_timeout;

	/* Header */
	ret = lttng_dynamic_buffer_append(
			buf, &channel_comm, sizeof(channel_comm));
	if (ret) {
		goto end;
	}

	/* channel name */
	ret = lttng_dynamic_buffer_append(buf, channel->name, name_len);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

void lttng_channel_set_default_extended_attr(struct lttng_domain *domain,
		struct lttng_channel_extended *extended_attr)
{
	assert(domain);
	assert(extended_attr);

	memset(extended_attr, 0, sizeof(*extended_attr));

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
		extended_attr->monitor_timer_interval =
				DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER;
		extended_attr->blocking_timeout =
				DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT;
		break;
	case LTTNG_DOMAIN_UST:
		switch (domain->buf_type) {
		case LTTNG_BUFFER_PER_UID:
			extended_attr->monitor_timer_interval =
					DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER;
			extended_attr->blocking_timeout =
					DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT;
			break;
		case LTTNG_BUFFER_PER_PID:
		default:
			if (extended_attr) {
				extended_attr->monitor_timer_interval =
						DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER;
				extended_attr->blocking_timeout =
						DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT;
			}
			break;
		}
	default:
		/* Default behavior: leave set to 0. */
		break;
	}
}

static enum lttng_error_code channel_list_create_from_buffer(
		const struct lttng_buffer_view *view,
		unsigned int count,
		struct lttng_dynamic_pointer_array *channel_list)
{
	enum lttng_error_code ret_code;
	int ret, i;
	int offset = 0;

	assert(view);
	assert(channel_list);

	for (i = 0; i < count; i++) {
		ssize_t channel_size;
		struct lttng_channel *channel = nullptr;
		const struct lttng_buffer_view channel_view =
				lttng_buffer_view_from_view(view, offset, -1);

		channel_size = lttng_channel_create_from_buffer(
				&channel_view, &channel);
		if (channel_size < 0) {
			ret_code = LTTNG_ERR_INVALID;
			goto end;
		}

		/* Lifetime and management of the object is now bound to the array. */
		ret = lttng_dynamic_pointer_array_add_pointer(channel_list, channel);
		if (ret) {
			lttng_channel_destroy(channel);
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
		offset += channel_size;
	}

	if (view->size != offset) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	ret_code = LTTNG_OK;

end:
	return ret_code;
}

static enum lttng_error_code flatten_lttng_channels(struct lttng_dynamic_pointer_array *channels,
		struct lttng_channel **flattened_channels)
{
	enum lttng_error_code ret_code;
	int ret, i;
	size_t storage_req = 0;
	struct lttng_dynamic_buffer local_flattened_channels;
	int nb_channels;

	assert(channels);
	assert(flattened_channels);

	lttng_dynamic_buffer_init(&local_flattened_channels);
	nb_channels = lttng_dynamic_pointer_array_get_count(channels);

	storage_req += sizeof(struct lttng_channel) * nb_channels;
	storage_req += sizeof(struct lttng_channel_extended) * nb_channels;

	/*
	 * We must ensure that "local_flattened_channels" is never resized so as
	 * to preserve the validity of the flattened objects.
	 */
	ret = lttng_dynamic_buffer_set_capacity(
			&local_flattened_channels, storage_req);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Start by laying the struct lttng_channel */
	for (i = 0; i < nb_channels; i++) {
		const auto *element = (const struct lttng_channel *)
				lttng_dynamic_pointer_array_get_pointer(
						channels, i);

		if (!element) {
			ret_code = LTTNG_ERR_FATAL;
			goto end;
		}

		ret = lttng_dynamic_buffer_append(&local_flattened_channels,
				element, sizeof(struct lttng_channel));
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	/* Flatten the extended data */
	for (i = 0; i < nb_channels; i++) {
		const auto *element = (const struct lttng_channel *)
				lttng_dynamic_pointer_array_get_pointer(
						channels, i);
		/*
		 * Sample the location of the flattened channel we are about
		 * to modify.
		 */
		auto *channel = (struct lttng_channel *)
				(local_flattened_channels.data + (sizeof(struct lttng_channel) * i));
		/*
		 * Sample the location of the extended attributes we are about
		 * to add.
		 */
		const auto *channel_extended = (struct lttng_channel_extended *)
				(local_flattened_channels.data + local_flattened_channels.size);

		if (!element) {
			ret_code = LTTNG_ERR_FATAL;
			goto end;
		}

		ret = lttng_dynamic_buffer_append(&local_flattened_channels,
				element->attr.extended.ptr,
				sizeof(struct lttng_channel_extended));
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		/*
		 * Update the flattened lttng_channel object with its flattened
		 * extended object location.
		 */
		channel->attr.extended.ptr = (void *) channel_extended;
	}

	/* Don't reset local_flattened_channels buffer as we return its content. */
	*flattened_channels = (struct lttng_channel *) local_flattened_channels.data;
	lttng_dynamic_buffer_init(&local_flattened_channels);
	ret_code = LTTNG_OK;
end:
	lttng_dynamic_buffer_reset(&local_flattened_channels);
	return ret_code;
}

enum lttng_error_code lttng_channels_create_and_flatten_from_buffer(
		const struct lttng_buffer_view *view,
		uint32_t count,
		struct lttng_channel **channels)
{
	enum lttng_error_code ret_code;
	struct lttng_dynamic_pointer_array local_channels;

	lttng_dynamic_pointer_array_init(&local_channels, channel_list_destructor);

	/* Deserialize the channels */
	{
		const struct lttng_buffer_view channels_view =
				lttng_buffer_view_from_view(view, 0, -1);

		ret_code = channel_list_create_from_buffer(
				&channels_view, count, &local_channels);
		if (ret_code != LTTNG_OK) {
			goto end;
		}
	}

	ret_code = flatten_lttng_channels(&local_channels, channels);

end:
	lttng_dynamic_pointer_array_reset(&local_channels);
	return ret_code;
}
