/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lttng/event.h>
#include <lttng/lttng-error.h>
#include <lttng/kernel-probe.h>
#include <lttng/userspace-probe.h>
#include <lttng/userspace-probe-internal.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/kprobe.h>
#include <lttng/event-rule/kprobe-internal.h>
#include <lttng/event-rule/syscall.h>
#include <lttng/event-rule/syscall-internal.h>
#include <lttng/event-rule/tracepoint.h>
#include <lttng/event-rule/tracepoint-internal.h>
#include <lttng/event-rule/uprobe-internal.h>
#include <common/common.h>
#include <common/defaults.h>
#include <common/trace-chunk.h>
#include <common/macros.h>

#include "consumer.h"
#include "trace-kernel.h"
#include "lttng-sessiond.h"
#include "notification-thread-commands.h"

/*
 * Find the channel name for the given kernel session.
 */
struct ltt_kernel_channel *trace_kernel_get_channel_by_name(
		const char *name, struct ltt_kernel_session *session)
{
	struct ltt_kernel_channel *chan;

	assert(session);
	assert(name);

	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (name[0] == '\0')
		name = DEFAULT_CHANNEL_NAME;

	DBG("Trying to find channel %s", name);

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		if (strcmp(name, chan->channel->name) == 0) {
			DBG("Found channel by name %s", name);
			return chan;
		}
	}

	return NULL;
}

/*
 * Find the event for the given channel.
 */
struct ltt_kernel_event *trace_kernel_find_event(
		char *name, struct ltt_kernel_channel *channel,
		enum lttng_event_type type,
		struct lttng_bytecode *filter)
{
	struct ltt_kernel_event *ev;
	int found = 0;

	assert(name);
	assert(channel);

	cds_list_for_each_entry(ev, &channel->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && ev->type != type) {
			continue;
		}
		if (strcmp(name, ev->event->name)) {
			continue;
		}
		if ((ev->filter && !filter) || (!ev->filter && filter)) {
			continue;
		}
		if (ev->filter && filter) {
			if (ev->filter->len != filter->len ||
					memcmp(ev->filter->data, filter->data,
						filter->len) != 0) {
				continue;
			}
		}
		found = 1;
		break;
	}
	if (found) {
		DBG("Found event %s for channel %s", name,
			channel->channel->name);
		return ev;
	} else {
		return NULL;
	}
}

/*
 * Find the event name for the given channel.
 */
struct ltt_kernel_event *trace_kernel_get_event_by_name(
		char *name, struct ltt_kernel_channel *channel,
		enum lttng_event_type type)
{
	struct ltt_kernel_event *ev;
	int found = 0;

	assert(name);
	assert(channel);

	cds_list_for_each_entry(ev, &channel->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && ev->type != type) {
			continue;
		}
		if (strcmp(name, ev->event->name)) {
			continue;
		}
		found = 1;
		break;
	}
	if (found) {
		DBG("Found event %s for channel %s", name,
			channel->channel->name);
		return ev;
	} else {
		return NULL;
	}
}

/*
 * Allocate and initialize a kernel session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_session *trace_kernel_create_session(void)
{
	struct ltt_kernel_session *lks = NULL;

	/* Allocate a new ltt kernel session */
	lks = zmalloc(sizeof(struct ltt_kernel_session));
	if (lks == NULL) {
		PERROR("create kernel session zmalloc");
		goto alloc_error;
	}

	/* Init data structure */
	lks->fd = -1;
	lks->metadata_stream_fd = -1;
	lks->channel_count = 0;
	lks->stream_count_global = 0;
	lks->metadata = NULL;
	CDS_INIT_LIST_HEAD(&lks->channel_list.head);

	lks->tracker_pid = process_attr_tracker_create();
	if (!lks->tracker_pid) {
		goto error;
	}
	lks->tracker_vpid = process_attr_tracker_create();
	if (!lks->tracker_vpid) {
		goto error;
	}
	lks->tracker_uid = process_attr_tracker_create();
	if (!lks->tracker_uid) {
		goto error;
	}
	lks->tracker_vuid = process_attr_tracker_create();
	if (!lks->tracker_vuid) {
		goto error;
	}
	lks->tracker_gid = process_attr_tracker_create();
	if (!lks->tracker_gid) {
		goto error;
	}
	lks->tracker_vgid = process_attr_tracker_create();
	if (!lks->tracker_vgid) {
		goto error;
	}
	lks->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (lks->consumer == NULL) {
		goto error;
	}

	return lks;

error:
	process_attr_tracker_destroy(lks->tracker_pid);
	process_attr_tracker_destroy(lks->tracker_vpid);
	process_attr_tracker_destroy(lks->tracker_uid);
	process_attr_tracker_destroy(lks->tracker_vuid);
	process_attr_tracker_destroy(lks->tracker_gid);
	process_attr_tracker_destroy(lks->tracker_vgid);
	free(lks);

alloc_error:
	return NULL;
}

/*
 * Allocate and initialize a kernel channel data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_channel *trace_kernel_create_channel(
		struct lttng_channel *chan)
{
	struct ltt_kernel_channel *lkc;
	struct lttng_channel_extended *extended = NULL;

	assert(chan);

	lkc = zmalloc(sizeof(struct ltt_kernel_channel));
	if (lkc == NULL) {
		PERROR("ltt_kernel_channel zmalloc");
		goto error;
	}

	lkc->channel = zmalloc(sizeof(struct lttng_channel));
	if (lkc->channel == NULL) {
		PERROR("lttng_channel zmalloc");
		goto error;
	}

	extended = zmalloc(sizeof(struct lttng_channel_extended));
	if (!extended) {
		PERROR("lttng_channel_channel zmalloc");
		goto error;
	}
	memcpy(lkc->channel, chan, sizeof(struct lttng_channel));
	memcpy(extended, chan->attr.extended.ptr, sizeof(struct lttng_channel_extended));
	lkc->channel->attr.extended.ptr = extended;
	extended = NULL;

	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (chan->name[0] == '\0') {
		strncpy(lkc->channel->name, DEFAULT_CHANNEL_NAME,
			sizeof(lkc->channel->name));
	}
	lkc->channel->name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';

	lkc->fd = -1;
	lkc->stream_count = 0;
	lkc->event_count = 0;
	lkc->enabled = 1;
	lkc->published_to_notification_thread = false;
	/* Init linked list */
	CDS_INIT_LIST_HEAD(&lkc->events_list.head);
	CDS_INIT_LIST_HEAD(&lkc->stream_list.head);
	CDS_INIT_LIST_HEAD(&lkc->ctx_list);

	return lkc;

error:
	if (lkc) {
		free(lkc->channel);
	}
	free(extended);
	free(lkc);
	return NULL;
}

/*
 * Allocate and init a kernel context object.
 *
 * Return the allocated object or NULL on error.
 */
struct ltt_kernel_context *trace_kernel_create_context(
		struct lttng_kernel_context *ctx)
{
	struct ltt_kernel_context *kctx;

	kctx = zmalloc(sizeof(*kctx));
	if (!kctx) {
		PERROR("zmalloc kernel context");
		goto error;
	}

	if (ctx) {
		memcpy(&kctx->ctx, ctx, sizeof(kctx->ctx));
	}
error:
	return kctx;
}

/*
 * Allocate and init a kernel context object from an existing kernel context
 * object.
 *
 * Return the allocated object or NULL on error.
 */
struct ltt_kernel_context *trace_kernel_copy_context(
		struct ltt_kernel_context *kctx)
{
	struct ltt_kernel_context *kctx_copy;

	assert(kctx);
	kctx_copy = zmalloc(sizeof(*kctx_copy));
	if (!kctx_copy) {
		PERROR("zmalloc ltt_kernel_context");
		goto error;
	}

	memcpy(kctx_copy, kctx, sizeof(*kctx_copy));
	memset(&kctx_copy->list, 0, sizeof(kctx_copy->list));

error:
	return kctx_copy;
}

/*
 * Allocate and initialize a kernel event. Set name and event type.
 * We own filter_expression, and filter.
 *
 * Return pointer to structure or NULL.
 */
enum lttng_error_code trace_kernel_create_event(
		struct lttng_event *ev, char *filter_expression,
		struct lttng_bytecode *filter,
		struct ltt_kernel_event **kernel_event)
{
	enum lttng_error_code ret;
	struct lttng_kernel_event *attr;
	struct ltt_kernel_event *local_kernel_event;
	struct lttng_userspace_probe_location *userspace_probe_location = NULL;

	assert(ev);

	local_kernel_event = zmalloc(sizeof(struct ltt_kernel_event));
	attr = zmalloc(sizeof(struct lttng_kernel_event));
	if (local_kernel_event == NULL || attr == NULL) {
		PERROR("kernel event zmalloc");
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		attr->instrumentation = LTTNG_KERNEL_KPROBE;
		attr->u.kprobe.addr = ev->attr.probe.addr;
		attr->u.kprobe.offset = ev->attr.probe.offset;
		strncpy(attr->u.kprobe.symbol_name,
				ev->attr.probe.symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);
		attr->u.kprobe.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_EVENT_USERSPACE_PROBE:
	{
		const struct lttng_userspace_probe_location* location = NULL;
		const struct lttng_userspace_probe_location_lookup_method *lookup = NULL;

		location = lttng_event_get_userspace_probe_location(ev);
		if (!location) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		/*
		 * From this point on, the specific term 'uprobe' is used
		 * instead of the generic 'userspace probe' because it's the
		 * technology used at the moment for this instrumentation.
		 * LTTng currently implements userspace probes using uprobes.
		 * In the interactions with the kernel tracer, we use the
		 * uprobe term.
		 */
		attr->instrumentation = LTTNG_KERNEL_UPROBE;

		lookup = lttng_userspace_probe_location_get_lookup_method(
				location);
		if (!lookup) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		/*
		 * From the kernel tracer's perspective, all userspace probe
		 * event types are all the same: a file and an offset.
		 */
		switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			/* Get the file descriptor on the target binary. */
			attr->u.uprobe.fd =
					lttng_userspace_probe_location_function_get_binary_fd(location);

			/*
			 * Save a reference to the probe location used during
			 * the listing of events.
			 */
			userspace_probe_location =
					lttng_userspace_probe_location_copy(location);
			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			/* Get the file descriptor on the target binary. */
			attr->u.uprobe.fd =
					lttng_userspace_probe_location_tracepoint_get_binary_fd(location);

			/*
			 * Save a reference to the probe location used during the listing of
			 * events.
			 */
			userspace_probe_location =
					lttng_userspace_probe_location_copy(location);
			break;
		default:
			DBG("Unsupported lookup method type");
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
		attr->instrumentation = LTTNG_KERNEL_KRETPROBE;
		attr->u.kretprobe.addr = ev->attr.probe.addr;
		attr->u.kretprobe.offset = ev->attr.probe.offset;
		strncpy(attr->u.kretprobe.symbol_name,
				ev->attr.probe.symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);
		attr->u.kretprobe.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		attr->instrumentation = LTTNG_KERNEL_FUNCTION;
		strncpy(attr->u.ftrace.symbol_name,
				ev->attr.ftrace.symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);
		attr->u.ftrace.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_EVENT_TRACEPOINT:
		attr->instrumentation = LTTNG_KERNEL_TRACEPOINT;
		break;
	case LTTNG_EVENT_SYSCALL:
		attr->instrumentation = LTTNG_KERNEL_SYSCALL;
		attr->u.syscall.abi = LTTNG_KERNEL_SYSCALL_ABI_ALL;
		attr->u.syscall.entryexit = LTTNG_KERNEL_SYSCALL_ENTRYEXIT;
		attr->u.syscall.match = LTTNG_KERNEL_SYSCALL_MATCH_NAME;
		break;
	case LTTNG_EVENT_ALL:
		attr->instrumentation = LTTNG_KERNEL_ALL;
		break;
	default:
		ERR("Unknown kernel instrumentation type (%d)", ev->type);
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/* Copy event name */
	strncpy(attr->name, ev->name, LTTNG_KERNEL_SYM_NAME_LEN);
	attr->name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';

	/* Setting up a kernel event */
	local_kernel_event->fd = -1;
	local_kernel_event->event = attr;
	local_kernel_event->enabled = 1;
	local_kernel_event->filter_expression = filter_expression;
	local_kernel_event->filter = filter;
	local_kernel_event->userspace_probe_location = userspace_probe_location;

	*kernel_event = local_kernel_event;

	return LTTNG_OK;

error:
	free(filter_expression);
	free(filter);
	free(local_kernel_event);
	free(attr);
	return ret;
}

/*
 * Allocate and initialize a kernel token event rule.
 *
 * Return pointer to structure or NULL.
 */
enum lttng_error_code trace_kernel_create_event_notifier_rule(
		struct lttng_trigger *trigger,
		uint64_t token,
		struct ltt_kernel_event_notifier_rule **event_notifier_rule)
{
	enum lttng_error_code ret = LTTNG_OK;
	enum lttng_condition_type condition_type;
	enum lttng_event_rule_type event_rule_type;
	enum lttng_condition_status condition_status;
	struct ltt_kernel_event_notifier_rule *local_kernel_token_event_rule;
	const struct lttng_condition *condition = NULL;
	const struct lttng_event_rule *event_rule = NULL;

	assert(event_notifier_rule);

	condition = lttng_trigger_get_condition(trigger);
	assert(condition);

	condition_type = lttng_condition_get_type(condition);
	assert(condition_type == LTTNG_CONDITION_TYPE_EVENT_RULE_HIT);

	condition_status = lttng_condition_event_rule_get_rule(
			condition, &event_rule);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
	assert(event_rule);

	event_rule_type = lttng_event_rule_get_type(event_rule);
	assert(event_rule_type != LTTNG_EVENT_RULE_TYPE_UNKNOWN);

	local_kernel_token_event_rule =
			zmalloc(sizeof(struct ltt_kernel_event_notifier_rule));
	if (local_kernel_token_event_rule == NULL) {
		PERROR("Failed to allocate ltt_kernel_token_event_rule structure");
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	local_kernel_token_event_rule->fd = -1;
	local_kernel_token_event_rule->enabled = 1;
	local_kernel_token_event_rule->token = token;

	/* Get the reference of the event rule. */
	lttng_trigger_get(trigger);

	local_kernel_token_event_rule->trigger = trigger;
	/* The event rule still owns the filter and bytecode. */
	local_kernel_token_event_rule->filter =
			lttng_event_rule_get_filter_bytecode(event_rule);

	DBG3("Created kernel event notifier rule: token =  %" PRIu64,
			local_kernel_token_event_rule->token);
error:
	*event_notifier_rule = local_kernel_token_event_rule;
	return ret;
}

/*
 * Initialize a kernel trigger from an event rule.
 */
enum lttng_error_code trace_kernel_init_event_notifier_from_event_rule(
		const struct lttng_event_rule *rule,
		struct lttng_kernel_event_notifier *kernel_event_notifier)
{
	enum lttng_error_code ret_code;
	const char *name;
	int strncpy_ret;

	switch (lttng_event_rule_get_type(rule)) {
	case LTTNG_EVENT_RULE_TYPE_KPROBE:
	{
		uint64_t address = 0, offset = 0;
		const char *symbol_name = NULL;
		const struct lttng_kernel_probe_location *location = NULL;
		enum lttng_kernel_probe_location_status k_status;
		enum lttng_event_rule_status status;

		status = lttng_event_rule_kprobe_get_location(rule, &location);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		switch (lttng_kernel_probe_location_get_type(location)) {
		case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
		{
			k_status = lttng_kernel_probe_location_address_get_address(
					location, &address);
			assert(k_status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);
			break;
		}
		case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
		{
			k_status = lttng_kernel_probe_location_symbol_get_offset(
					location, &offset);
			assert(k_status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);
			symbol_name = lttng_kernel_probe_location_symbol_get_name(
					location);
			break;
		}
		default:
			abort();
		}

		kernel_event_notifier->event.instrumentation = LTTNG_KERNEL_KPROBE;
		kernel_event_notifier->event.u.kprobe.addr = address;
		kernel_event_notifier->event.u.kprobe.offset = offset;
		if (symbol_name) {
			strncpy_ret = lttng_strncpy(
					kernel_event_notifier->event.u.kprobe.symbol_name,
					symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);

			if (strncpy_ret) {
				ret_code = LTTNG_ERR_INVALID;
				goto error;
			}
		}

		kernel_event_notifier->event.u.kprobe.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		status = lttng_event_rule_kprobe_get_name(rule, &name);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);
		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_UPROBE:
	{
		const struct lttng_userspace_probe_location* location = NULL;
		const struct lttng_userspace_probe_location_lookup_method *lookup = NULL;
		enum lttng_event_rule_status status;

		status = lttng_event_rule_uprobe_get_location(rule, &location);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		kernel_event_notifier->event.instrumentation = LTTNG_KERNEL_UPROBE;

		lookup = lttng_userspace_probe_location_get_lookup_method(
				location);
		if (!lookup) {
			ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		/*
		 * From the kernel tracer's perspective, all userspace probe
		 * event types are all the same: a file and an offset.
		 */
		switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			/* Get the file descriptor on the target binary. */
			kernel_event_notifier->event.u.uprobe.fd =
					lttng_userspace_probe_location_function_get_binary_fd(location);

			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			/* Get the file descriptor on the target binary. */
			kernel_event_notifier->event.u.uprobe.fd =
					lttng_userspace_probe_location_tracepoint_get_binary_fd(location);
			break;
		default:
			abort();
		}

		status = lttng_event_rule_uprobe_get_name(rule, &name);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);
		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
	{
		const enum lttng_domain_type domain =
				lttng_event_rule_get_domain_type(rule);
		const enum lttng_event_rule_status status =
				lttng_event_rule_tracepoint_get_pattern(
						rule, &name);

		assert(domain == LTTNG_DOMAIN_KERNEL);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);
		kernel_event_notifier->event.instrumentation =
				LTTNG_KERNEL_TRACEPOINT;

		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
	{
		const enum lttng_event_rule_status status =
				lttng_event_rule_syscall_get_pattern(
						rule, &name);

		assert(status == LTTNG_EVENT_RULE_STATUS_OK);

		kernel_event_notifier->event.instrumentation =
				LTTNG_KERNEL_SYSCALL;
		kernel_event_notifier->event.u.syscall.abi =
				LTTNG_KERNEL_SYSCALL_ABI_ALL;
		kernel_event_notifier->event.u.syscall.entryexit =
				LTTNG_KERNEL_SYSCALL_ENTRY;
		kernel_event_notifier->event.u.syscall.match =
				LTTNG_KERNEL_SYSCALL_MATCH_NAME;
		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KRETPROBE:
	default:
		abort();
		break;
	}

	strncpy_ret = lttng_strncpy(kernel_event_notifier->event.name, name,
			LTTNG_KERNEL_SYM_NAME_LEN);
	if (strncpy_ret) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

error:
	return ret_code;
}
/*
 * Allocate and initialize a kernel metadata.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_metadata *trace_kernel_create_metadata(void)
{
	int ret;
	struct ltt_kernel_metadata *lkm;
	struct lttng_channel *chan;

	lkm = zmalloc(sizeof(struct ltt_kernel_metadata));
	chan = zmalloc(sizeof(struct lttng_channel));
	if (lkm == NULL || chan == NULL) {
		PERROR("kernel metadata zmalloc");
		goto error;
	}

	ret = lttng_strncpy(
			chan->name, DEFAULT_METADATA_NAME, sizeof(chan->name));
	if (ret) {
		ERR("Failed to initialize metadata channel name to `%s`",
				DEFAULT_METADATA_NAME);
		goto error;
	}

	/* Set default attributes */
	chan->attr.overwrite = DEFAULT_METADATA_OVERWRITE;
	chan->attr.subbuf_size = default_get_metadata_subbuf_size();
	chan->attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	chan->attr.switch_timer_interval = DEFAULT_METADATA_SWITCH_TIMER;
	chan->attr.read_timer_interval = DEFAULT_METADATA_READ_TIMER;;


	/*
	 * The metadata channel of kernel sessions must use the "mmap"
	 * back-end since the consumer daemon accumulates complete
	 * metadata units before sending them to the relay daemon in
	 * live mode. The consumer daemon also needs to extract the contents
	 * of the metadata cache when computing a rotation position.
	 *
	 * In both cases, it is not possible to rely on the splice
	 * back-end as the consumer daemon may need to accumulate more
	 * content than can be backed by the ring buffer's underlying
	 * pages.
	 */
	chan->attr.output = LTTNG_EVENT_MMAP;
	chan->attr.tracefile_size = 0;
	chan->attr.tracefile_count = 0;
	chan->attr.live_timer_interval = 0;

	/* Init metadata */
	lkm->fd = -1;
	lkm->conf = chan;

	return lkm;

error:
	free(lkm);
	free(chan);
	return NULL;
}

/*
 * Allocate and initialize a kernel stream. The stream is set to ACTIVE_FD by
 * default.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_stream *trace_kernel_create_stream(const char *name,
		unsigned int count)
{
	int ret;
	struct ltt_kernel_stream *lks;

	assert(name);

	lks = zmalloc(sizeof(struct ltt_kernel_stream));
	if (lks == NULL) {
		PERROR("kernel stream zmalloc");
		goto error;
	}

	/* Set name */
	ret = snprintf(lks->name, sizeof(lks->name), "%s_%u", name, count);
	if (ret < 0) {
		PERROR("snprintf stream name");
		goto error;
	}
	lks->name[sizeof(lks->name) - 1] = '\0';

	/* Init stream */
	lks->fd = -1;
	lks->state = 0;
	lks->cpu = count;

	return lks;

error:
	return NULL;
}

/*
 * Cleanup kernel stream structure.
 */
void trace_kernel_destroy_stream(struct ltt_kernel_stream *stream)
{
	assert(stream);

	DBG("[trace] Closing stream fd %d", stream->fd);
	/* Close kernel fd */
	if (stream->fd >= 0) {
		int ret;

		ret = close(stream->fd);
		if (ret) {
			PERROR("close");
		}
	}
	/* Remove from stream list */
	cds_list_del(&stream->list);

	free(stream);
}

/*
 * Cleanup kernel event structure.
 */
void trace_kernel_destroy_event(struct ltt_kernel_event *event)
{
	assert(event);

	if (event->fd >= 0) {
		int ret;

		DBG("[trace] Closing event fd %d", event->fd);
		/* Close kernel fd */
		ret = close(event->fd);
		if (ret) {
			PERROR("close");
		}
	} else {
		DBG("[trace] Tearing down event (no associated file descriptor)");
	}

	/* Remove from event list */
	cds_list_del(&event->list);

	free(event->filter_expression);
	free(event->filter);

	free(event->event);
	free(event);
}

/*
 * Cleanup kernel event structure.
 */
static void free_token_event_rule_rcu(struct rcu_head *rcu_node)
{
	struct ltt_kernel_event_notifier_rule *rule = caa_container_of(rcu_node,
			struct ltt_kernel_event_notifier_rule, rcu_node);

	free(rule);
}

void trace_kernel_destroy_event_notifier_rule(
		struct ltt_kernel_event_notifier_rule *event)
{
	assert(event);

	if (event->fd >= 0) {
		const int ret = close(event->fd);

		DBG("Closing kernel event notifier rule file descriptor: fd = %d",
				event->fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier file descriptor: fd = %d",
					event->fd);
		}
	} else {
		DBG("Destroying kernel event notifier rule (no associated file descriptor)");
	}

	lttng_trigger_put(event->trigger);
	call_rcu(&event->rcu_node, free_token_event_rule_rcu);
}
/*
 * Cleanup kernel context structure.
 */
void trace_kernel_destroy_context(struct ltt_kernel_context *ctx)
{
	assert(ctx);

	if (ctx->in_list) {
		cds_list_del(&ctx->list);
	}
	free(ctx);
}

/*
 * Cleanup kernel channel structure.
 */
void trace_kernel_destroy_channel(struct ltt_kernel_channel *channel)
{
	struct ltt_kernel_stream *stream, *stmp;
	struct ltt_kernel_event *event, *etmp;
	struct ltt_kernel_context *ctx, *ctmp;
	int ret;
	enum lttng_error_code status;

	assert(channel);

	DBG("[trace] Closing channel fd %d", channel->fd);
	/* Close kernel fd */
	if (channel->fd >= 0) {
		ret = close(channel->fd);
		if (ret) {
			PERROR("close");
		}
	}

	/* For each stream in the channel list */
	cds_list_for_each_entry_safe(stream, stmp, &channel->stream_list.head, list) {
		trace_kernel_destroy_stream(stream);
	}

	/* For each event in the channel list */
	cds_list_for_each_entry_safe(event, etmp, &channel->events_list.head, list) {
		trace_kernel_destroy_event(event);
	}

	/* For each context in the channel list */
	cds_list_for_each_entry_safe(ctx, ctmp, &channel->ctx_list, list) {
		trace_kernel_destroy_context(ctx);
	}

	/* Remove from channel list */
	cds_list_del(&channel->list);

	if (notification_thread_handle
			&& channel->published_to_notification_thread) {
		status = notification_thread_command_remove_channel(
				notification_thread_handle,
				channel->key, LTTNG_DOMAIN_KERNEL);
		assert(status == LTTNG_OK);
	}
	free(channel->channel->attr.extended.ptr);
	free(channel->channel);
	free(channel);
}

/*
 * Cleanup kernel metadata structure.
 */
void trace_kernel_destroy_metadata(struct ltt_kernel_metadata *metadata)
{
	assert(metadata);

	DBG("[trace] Closing metadata fd %d", metadata->fd);
	/* Close kernel fd */
	if (metadata->fd >= 0) {
		int ret;

		ret = close(metadata->fd);
		if (ret) {
			PERROR("close");
		}
	}

	free(metadata->conf);
	free(metadata);
}

/*
 * Cleanup kernel session structure
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
void trace_kernel_destroy_session(struct ltt_kernel_session *session)
{
	struct ltt_kernel_channel *channel, *ctmp;
	int ret;

	assert(session);

	DBG("[trace] Closing session fd %d", session->fd);
	/* Close kernel fds */
	if (session->fd >= 0) {
		ret = close(session->fd);
		if (ret) {
			PERROR("close");
		}
	}

	if (session->metadata_stream_fd >= 0) {
		DBG("[trace] Closing metadata stream fd %d", session->metadata_stream_fd);
		ret = close(session->metadata_stream_fd);
		if (ret) {
			PERROR("close");
		}
	}

	if (session->metadata != NULL) {
		trace_kernel_destroy_metadata(session->metadata);
	}

	cds_list_for_each_entry_safe(channel, ctmp, &session->channel_list.head, list) {
		trace_kernel_destroy_channel(channel);
	}
}

/* Free elements needed by destroy notifiers. */
void trace_kernel_free_session(struct ltt_kernel_session *session)
{
	/* Wipe consumer output object */
	consumer_output_put(session->consumer);

	process_attr_tracker_destroy(session->tracker_pid);
	process_attr_tracker_destroy(session->tracker_vpid);
	process_attr_tracker_destroy(session->tracker_uid);
	process_attr_tracker_destroy(session->tracker_vuid);
	process_attr_tracker_destroy(session->tracker_gid);
	process_attr_tracker_destroy(session->tracker_vgid);

	free(session);
}
