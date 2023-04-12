/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "condition-internal.hpp"
#include "consumer.hpp"
#include "event-notifier-error-accounting.hpp"
#include "kern-modules.hpp"
#include "kernel-consumer.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-syscall.hpp"
#include "modprobe.hpp"
#include "notification-thread-commands.hpp"
#include "sessiond-config.hpp"
#include "tracker.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/hashtable/utils.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/kernel-ctl/kernel-ioctl.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/trace-chunk.hpp>
#include <common/tracker.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <lttng/condition/event-rule-matches-internal.hpp>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/kernel-uprobe-internal.hpp>
#include <lttng/event.h>
#include <lttng/lttng-error.h>
#include <lttng/tracker.h>
#include <lttng/userspace-probe-internal.hpp>
#include <lttng/userspace-probe.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Key used to reference a channel between the sessiond and the consumer. This
 * is only read and updated with the session_list lock held.
 */
static uint64_t next_kernel_channel_key;

static const char *module_proc_lttng = "/proc/lttng";

static int kernel_tracer_fd = -1;
static int kernel_tracer_event_notifier_group_fd = -1;
static int kernel_tracer_event_notifier_group_notification_fd = -1;
static struct cds_lfht *kernel_token_to_event_notifier_rule_ht;

namespace {
/*
 * On some architectures, calling convention details are embedded in the symbol
 * addresses. Uprobe requires a "clean" symbol offset (or at least, an address
 * where an instruction boundary would be legal) to add
 * instrumentation. sanitize_uprobe_offset implements that sanitization logic on
 * a per-architecture basis.
 */
#if defined(__arm__) || defined(__aarch64__)
static inline uint64_t sanitize_uprobe_offset(uint64_t raw_offset)
{
	/*
	 * The least significant bit is used when branching to switch to thumb
	 * ISA. However, it's an invalid address for us; mask the least
	 * significant bit.
	 */
	return raw_offset &= ~0b1;
}
#else /* defined(__arm__) || defined(__aarch64__) */
static inline uint64_t sanitize_uprobe_offset(uint64_t raw_offset)
{
	return raw_offset;
}
#endif
} /* namespace */

/*
 * Add context on a kernel channel.
 *
 * Assumes the ownership of ctx.
 */
int kernel_add_channel_context(struct ltt_kernel_channel *chan, struct ltt_kernel_context *ctx)
{
	int ret;

	LTTNG_ASSERT(chan);
	LTTNG_ASSERT(ctx);

	DBG("Adding context to channel %s", chan->channel->name);
	ret = kernctl_add_context(chan->fd, &ctx->ctx);
	if (ret < 0) {
		switch (-ret) {
		case ENOSYS:
			/* Exists but not available for this kernel */
			ret = LTTNG_ERR_KERN_CONTEXT_UNAVAILABLE;
			goto error;
		case EEXIST:
			/* If EEXIST, we just ignore the error */
			ret = 0;
			goto end;
		default:
			PERROR("add context ioctl");
			ret = LTTNG_ERR_KERN_CONTEXT_FAIL;
			goto error;
		}
	}
	ret = 0;

end:
	cds_list_add_tail(&ctx->list, &chan->ctx_list);
	ctx->in_list = true;
	ctx = nullptr;
error:
	if (ctx) {
		trace_kernel_destroy_context(ctx);
	}
	return ret;
}

/*
 * Create a new kernel session, register it to the kernel tracer and add it to
 * the session daemon session.
 */
int kernel_create_session(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_session *lks;

	LTTNG_ASSERT(session);

	/* Allocate data structure */
	lks = trace_kernel_create_session();
	if (lks == nullptr) {
		ret = -1;
		goto error;
	}

	/* Kernel tracer session creation */
	ret = kernctl_create_session(kernel_tracer_fd);
	if (ret < 0) {
		PERROR("ioctl kernel create session");
		goto error;
	}

	lks->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	lks->id = session->id;
	lks->consumer_fds_sent = 0;
	session->kernel_session = lks;

	DBG("Kernel session created (fd: %d)", lks->fd);

	/*
	 * This is necessary since the creation time is present in the session
	 * name when it is generated.
	 */
	if (session->has_auto_generated_name) {
		ret = kernctl_session_set_name(lks->fd, DEFAULT_SESSION_NAME);
	} else {
		ret = kernctl_session_set_name(lks->fd, session->name);
	}
	if (ret) {
		WARN("Could not set kernel session name for session %" PRIu64 " name: %s",
		     session->id,
		     session->name);
	}

	ret = kernctl_session_set_creation_time(lks->fd, session->creation_time);
	if (ret) {
		WARN("Could not set kernel session creation time for session %" PRIu64 " name: %s",
		     session->id,
		     session->name);
	}

	return 0;

error:
	if (lks) {
		trace_kernel_destroy_session(lks);
		trace_kernel_free_session(lks);
	}
	return ret;
}

/*
 * Create a kernel channel, register it to the kernel tracer and add it to the
 * kernel session.
 */
int kernel_create_channel(struct ltt_kernel_session *session, struct lttng_channel *chan)
{
	int ret;
	struct ltt_kernel_channel *lkc;

	LTTNG_ASSERT(session);
	LTTNG_ASSERT(chan);

	/* Allocate kernel channel */
	lkc = trace_kernel_create_channel(chan);
	if (lkc == nullptr) {
		goto error;
	}

	DBG3("Kernel create channel %s with attr: %d, %" PRIu64 ", %" PRIu64 ", %u, %u, %d, %d",
	     chan->name,
	     lkc->channel->attr.overwrite,
	     lkc->channel->attr.subbuf_size,
	     lkc->channel->attr.num_subbuf,
	     lkc->channel->attr.switch_timer_interval,
	     lkc->channel->attr.read_timer_interval,
	     lkc->channel->attr.live_timer_interval,
	     lkc->channel->attr.output);

	/* Kernel tracer channel creation */
	ret = kernctl_create_channel(session->fd, &lkc->channel->attr);
	if (ret < 0) {
		PERROR("ioctl kernel create channel");
		goto error;
	}

	/* Setup the channel fd */
	lkc->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lkc->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	/* Add channel to session */
	cds_list_add(&lkc->list, &session->channel_list.head);
	session->channel_count++;
	lkc->session = session;
	lkc->key = ++next_kernel_channel_key;

	DBG("Kernel channel %s created (fd: %d, key: %" PRIu64 ")",
	    lkc->channel->name,
	    lkc->fd,
	    lkc->key);

	return 0;

error:
	if (lkc) {
		free(lkc->channel);
		free(lkc);
	}
	return -1;
}

/*
 * Create a kernel event notifier group, register it to the kernel tracer and
 * add it to the kernel session.
 */
static int kernel_create_event_notifier_group(int *event_notifier_group_fd)
{
	int ret;
	int local_fd = -1;

	LTTNG_ASSERT(event_notifier_group_fd);

	/* Kernel event notifier group creation. */
	ret = kernctl_create_event_notifier_group(kernel_tracer_fd);
	if (ret < 0) {
		PERROR("Failed to create kernel event notifier group");
		ret = -1;
		goto error;
	}

	local_fd = ret;

	/* Prevent fd duplication after execlp(). */
	ret = fcntl(local_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to set FD_CLOEXEC on kernel event notifier group file descriptor: fd = %d",
		       local_fd);
		goto error;
	}

	DBG("Created kernel event notifier group: fd = %d", local_fd);
	*event_notifier_group_fd = local_fd;
	local_fd = -1;
	ret = 0;
error:
	if (local_fd >= 0) {
		ret = close(local_fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier group file descriptor: fd = %d",
			       local_fd);
		}
	}

	return ret;
}

/*
 * Compute the offset of the instrumentation byte in the binary based on the
 * function probe location using the ELF lookup method.
 *
 * Returns 0 on success and set the offset out parameter to the offset of the
 * elf symbol
 * Returns -1 on error
 */
static int extract_userspace_probe_offset_function_elf(
	const struct lttng_userspace_probe_location *probe_location,
	uid_t uid,
	gid_t gid,
	uint64_t *offset)
{
	int fd;
	int ret = 0;
	const char *symbol = nullptr;
	const struct lttng_userspace_probe_location_lookup_method *lookup = nullptr;
	enum lttng_userspace_probe_location_lookup_method_type lookup_method_type;

	LTTNG_ASSERT(lttng_userspace_probe_location_get_type(probe_location) ==
		     LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

	lookup = lttng_userspace_probe_location_get_lookup_method(probe_location);
	if (!lookup) {
		ret = -1;
		goto end;
	}

	lookup_method_type = lttng_userspace_probe_location_lookup_method_get_type(lookup);

	LTTNG_ASSERT(lookup_method_type ==
		     LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF);

	symbol = lttng_userspace_probe_location_function_get_function_name(probe_location);
	if (!symbol) {
		ret = -1;
		goto end;
	}

	fd = lttng_userspace_probe_location_function_get_binary_fd(probe_location);
	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = run_as_extract_elf_symbol_offset(fd, symbol, uid, gid, offset);
	if (ret < 0) {
		DBG("userspace probe offset calculation failed for "
		    "function %s",
		    symbol);
		goto end;
	}

	DBG("userspace probe elf offset for %s is 0x%jd", symbol, (intmax_t) (*offset));
end:
	return ret;
}

/*
 * Compute the offsets of the instrumentation bytes in the binary based on the
 * tracepoint probe location using the SDT lookup method. This function
 * allocates the offsets buffer, the caller must free it.
 *
 * Returns 0 on success and set the offset out parameter to the offsets of the
 * SDT tracepoint.
 * Returns -1 on error.
 */
static int extract_userspace_probe_offset_tracepoint_sdt(
	const struct lttng_userspace_probe_location *probe_location,
	uid_t uid,
	gid_t gid,
	uint64_t **offsets,
	uint32_t *offsets_count)
{
	enum lttng_userspace_probe_location_lookup_method_type lookup_method_type;
	const struct lttng_userspace_probe_location_lookup_method *lookup = nullptr;
	const char *probe_name = nullptr, *provider_name = nullptr;
	int ret = 0;
	int fd, i;

	LTTNG_ASSERT(lttng_userspace_probe_location_get_type(probe_location) ==
		     LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);

	lookup = lttng_userspace_probe_location_get_lookup_method(probe_location);
	if (!lookup) {
		ret = -1;
		goto end;
	}

	lookup_method_type = lttng_userspace_probe_location_lookup_method_get_type(lookup);

	LTTNG_ASSERT(lookup_method_type ==
		     LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT);

	probe_name = lttng_userspace_probe_location_tracepoint_get_probe_name(probe_location);
	if (!probe_name) {
		ret = -1;
		goto end;
	}

	provider_name = lttng_userspace_probe_location_tracepoint_get_provider_name(probe_location);
	if (!provider_name) {
		ret = -1;
		goto end;
	}

	fd = lttng_userspace_probe_location_tracepoint_get_binary_fd(probe_location);
	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = run_as_extract_sdt_probe_offsets(
		fd, provider_name, probe_name, uid, gid, offsets, offsets_count);
	if (ret < 0) {
		DBG("userspace probe offset calculation failed for sdt "
		    "probe %s:%s",
		    provider_name,
		    probe_name);
		goto end;
	}

	if (*offsets_count == 0) {
		DBG("no userspace probe offset found");
		goto end;
	}

	DBG("%u userspace probe SDT offsets found for %s:%s at:",
	    *offsets_count,
	    provider_name,
	    probe_name);
	for (i = 0; i < *offsets_count; i++) {
		DBG("\t0x%jd", (intmax_t) ((*offsets)[i]));
	}
end:
	return ret;
}

static int userspace_probe_add_callsite(const struct lttng_userspace_probe_location *location,
					uid_t uid,
					gid_t gid,
					int fd)
{
	const struct lttng_userspace_probe_location_lookup_method *lookup_method = nullptr;
	enum lttng_userspace_probe_location_lookup_method_type type;
	int ret;

	lookup_method = lttng_userspace_probe_location_get_lookup_method(location);
	if (!lookup_method) {
		ret = -1;
		goto end;
	}

	type = lttng_userspace_probe_location_lookup_method_get_type(lookup_method);
	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
	{
		struct lttng_kernel_abi_event_callsite callsite;
		uint64_t offset;

		ret = extract_userspace_probe_offset_function_elf(location, uid, gid, &offset);
		if (ret) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto end;
		}

		callsite.u.uprobe.offset = sanitize_uprobe_offset(offset);
		ret = kernctl_add_callsite(fd, &callsite);
		if (ret) {
			WARN("Failed to add callsite to ELF userspace probe.");
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto end;
		}
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
	{
		int i;
		uint64_t *offsets = nullptr;
		uint32_t offsets_count;
		struct lttng_kernel_abi_event_callsite callsite;

		/*
		 * This call allocates the offsets buffer. This buffer must be freed
		 * by the caller
		 */
		ret = extract_userspace_probe_offset_tracepoint_sdt(
			location, uid, gid, &offsets, &offsets_count);
		if (ret) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto end;
		}
		for (i = 0; i < offsets_count; i++) {
			callsite.u.uprobe.offset = sanitize_uprobe_offset(offsets[i]);
			ret = kernctl_add_callsite(fd, &callsite);
			if (ret) {
				WARN("Failed to add callsite to SDT userspace probe");
				ret = LTTNG_ERR_KERN_ENABLE_FAIL;
				free(offsets);
				goto end;
			}
		}
		free(offsets);
		break;
	}
	default:
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto end;
	}
end:
	return ret;
}

/*
 * Extract the offsets of the instrumentation point for the different lookup
 * methods.
 */
static int userspace_probe_event_add_callsites(struct lttng_event *ev,
					       struct ltt_kernel_session *session,
					       int fd)
{
	int ret;
	const struct lttng_userspace_probe_location *location = nullptr;

	LTTNG_ASSERT(ev);
	LTTNG_ASSERT(ev->type == LTTNG_EVENT_USERSPACE_PROBE);

	location = lttng_event_get_userspace_probe_location(ev);
	if (!location) {
		ret = -1;
		goto end;
	}

	ret = userspace_probe_add_callsite(location, session->uid, session->gid, fd);
	if (ret) {
		WARN("Failed to add callsite to userspace probe event '%s'", ev->name);
	}

end:
	return ret;
}

/*
 * Extract the offsets of the instrumentation point for the different look-up
 * methods.
 */
static int userspace_probe_event_rule_add_callsites(const struct lttng_event_rule *rule,
						    const struct lttng_credentials *creds,
						    int fd)
{
	int ret;
	enum lttng_event_rule_status status;
	enum lttng_event_rule_type event_rule_type;
	const struct lttng_userspace_probe_location *location = nullptr;

	LTTNG_ASSERT(rule);
	LTTNG_ASSERT(creds);

	event_rule_type = lttng_event_rule_get_type(rule);
	LTTNG_ASSERT(event_rule_type == LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE);

	status = lttng_event_rule_kernel_uprobe_get_location(rule, &location);
	if (status != LTTNG_EVENT_RULE_STATUS_OK || !location) {
		ret = -1;
		goto end;
	}

	ret = userspace_probe_add_callsite(
		location, lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds), fd);
	if (ret) {
		WARN("Failed to add callsite to user space probe object: fd = %d", fd);
	}

end:
	return ret;
}

/*
 * Create a kernel event, enable it to the kernel tracer and add it to the
 * channel event list of the kernel session.
 * We own filter_expression and filter.
 */
int kernel_create_event(struct lttng_event *ev,
			struct ltt_kernel_channel *channel,
			char *filter_expression,
			struct lttng_bytecode *filter)
{
	int err, fd;
	enum lttng_error_code ret;
	struct ltt_kernel_event *event;

	LTTNG_ASSERT(ev);
	LTTNG_ASSERT(channel);

	/* We pass ownership of filter_expression and filter */
	ret = trace_kernel_create_event(ev, filter_expression, filter, &event);
	if (ret != LTTNG_OK) {
		goto error;
	}

	fd = kernctl_create_event(channel->fd, event->event);
	if (fd < 0) {
		switch (-fd) {
		case EEXIST:
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		case ENOSYS:
			WARN("Event type not implemented");
			ret = LTTNG_ERR_KERN_EVENT_ENOSYS;
			break;
		case ENOENT:
			WARN("Event %s not found!", ev->name);
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			break;
		default:
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			PERROR("create event ioctl");
		}
		goto free_event;
	}

	event->type = ev->type;
	event->fd = fd;
	/* Prevent fd duplication after execlp() */
	err = fcntl(event->fd, F_SETFD, FD_CLOEXEC);
	if (err < 0) {
		PERROR("fcntl session fd");
	}

	if (filter) {
		err = kernctl_filter(event->fd, filter);
		if (err < 0) {
			switch (-err) {
			case ENOMEM:
				ret = LTTNG_ERR_FILTER_NOMEM;
				break;
			default:
				ret = LTTNG_ERR_FILTER_INVAL;
				break;
			}
			goto filter_error;
		}
	}

	if (ev->type == LTTNG_EVENT_USERSPACE_PROBE) {
		ret = (lttng_error_code) userspace_probe_event_add_callsites(
			ev, channel->session, event->fd);
		if (ret) {
			goto add_callsite_error;
		}
	}

	err = kernctl_enable(event->fd);
	if (err < 0) {
		switch (-err) {
		case EEXIST:
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("enable kernel event");
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			break;
		}
		goto enable_error;
	}

	/* Add event to event list */
	cds_list_add(&event->list, &channel->events_list.head);
	channel->event_count++;

	DBG("Event %s created (fd: %d)", ev->name, event->fd);

	return 0;

add_callsite_error:
enable_error:
filter_error:
{
	int closeret;

	closeret = close(event->fd);
	if (closeret) {
		PERROR("close event fd");
	}
}
free_event:
	free(event);
error:
	return ret;
}

/*
 * Disable a kernel channel.
 */
int kernel_disable_channel(struct ltt_kernel_channel *chan)
{
	int ret;

	LTTNG_ASSERT(chan);

	ret = kernctl_disable(chan->fd);
	if (ret < 0) {
		PERROR("disable chan ioctl");
		goto error;
	}

	chan->enabled = false;
	DBG("Kernel channel %s disabled (fd: %d, key: %" PRIu64 ")",
	    chan->channel->name,
	    chan->fd,
	    chan->key);

	return 0;

error:
	return ret;
}

/*
 * Enable a kernel channel.
 */
int kernel_enable_channel(struct ltt_kernel_channel *chan)
{
	int ret;

	LTTNG_ASSERT(chan);

	ret = kernctl_enable(chan->fd);
	if (ret < 0 && ret != -EEXIST) {
		PERROR("Enable kernel chan");
		goto error;
	}

	chan->enabled = true;
	DBG("Kernel channel %s enabled (fd: %d, key: %" PRIu64 ")",
	    chan->channel->name,
	    chan->fd,
	    chan->key);

	return 0;

error:
	return ret;
}

/*
 * Enable a kernel event.
 */
int kernel_enable_event(struct ltt_kernel_event *event)
{
	int ret;

	LTTNG_ASSERT(event);

	ret = kernctl_enable(event->fd);
	if (ret < 0) {
		switch (-ret) {
		case EEXIST:
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("enable kernel event");
			break;
		}
		goto error;
	}

	event->enabled = true;
	DBG("Kernel event %s enabled (fd: %d)", event->event->name, event->fd);

	return 0;

error:
	return ret;
}

/*
 * Disable a kernel event.
 */
int kernel_disable_event(struct ltt_kernel_event *event)
{
	int ret;

	LTTNG_ASSERT(event);

	ret = kernctl_disable(event->fd);
	if (ret < 0) {
		PERROR("Failed to disable kernel event: name = '%s', fd = %d",
		       event->event->name,
		       event->fd);
		goto error;
	}

	event->enabled = false;
	DBG("Kernel event %s disabled (fd: %d)", event->event->name, event->fd);

	return 0;

error:
	return ret;
}

/*
 * Disable a kernel event notifier.
 */
static int kernel_disable_event_notifier_rule(struct ltt_kernel_event_notifier_rule *event)
{
	int ret;

	LTTNG_ASSERT(event);

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_del(kernel_token_to_event_notifier_rule_ht, &event->ht_node);

	ret = kernctl_disable(event->fd);
	if (ret < 0) {
		PERROR("Failed to disable kernel event notifier: fd = %d, token = %" PRIu64,
		       event->fd,
		       event->token);
		goto error;
	}

	event->enabled = false;
	DBG("Disabled kernel event notifier: fd = %d, token = %" PRIu64, event->fd, event->token);

error:
	return ret;
}

static struct process_attr_tracker *
_kernel_get_process_attr_tracker(struct ltt_kernel_session *session,
				 enum lttng_process_attr process_attr)
{
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		return session->tracker_pid;
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		return session->tracker_vpid;
	case LTTNG_PROCESS_ATTR_USER_ID:
		return session->tracker_uid;
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		return session->tracker_vuid;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		return session->tracker_gid;
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		return session->tracker_vgid;
	default:
		return nullptr;
	}
}

const struct process_attr_tracker *
kernel_get_process_attr_tracker(struct ltt_kernel_session *session,
				enum lttng_process_attr process_attr)
{
	return (const struct process_attr_tracker *) _kernel_get_process_attr_tracker(session,
										      process_attr);
}

enum lttng_error_code
kernel_process_attr_tracker_set_tracking_policy(struct ltt_kernel_session *session,
						enum lttng_process_attr process_attr,
						enum lttng_tracking_policy policy)
{
	int ret;
	enum lttng_error_code ret_code = LTTNG_OK;
	struct process_attr_tracker *tracker =
		_kernel_get_process_attr_tracker(session, process_attr);
	enum lttng_tracking_policy previous_policy;

	if (!tracker) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	previous_policy = process_attr_tracker_get_tracking_policy(tracker);
	ret = process_attr_tracker_set_tracking_policy(tracker, policy);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	if (previous_policy == policy) {
		goto end;
	}

	switch (policy) {
	case LTTNG_TRACKING_POLICY_INCLUDE_ALL:
		if (process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID) {
			/*
			 * Maintain a special case for the process ID process
			 * attribute tracker as it was the only supported
			 * attribute prior to 2.12.
			 */
			ret = kernctl_track_pid(session->fd, -1);
		} else {
			ret = kernctl_track_id(session->fd, process_attr, -1);
		}
		break;
	case LTTNG_TRACKING_POLICY_EXCLUDE_ALL:
	case LTTNG_TRACKING_POLICY_INCLUDE_SET:
		/* fall-through. */
		if (process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID) {
			/*
			 * Maintain a special case for the process ID process
			 * attribute tracker as it was the only supported
			 * attribute prior to 2.12.
			 */
			ret = kernctl_untrack_pid(session->fd, -1);
		} else {
			ret = kernctl_untrack_id(session->fd, process_attr, -1);
		}
		break;
	default:
		abort();
	}
	/* kern-ctl error handling */
	switch (-ret) {
	case 0:
		ret_code = LTTNG_OK;
		break;
	case EINVAL:
		ret_code = LTTNG_ERR_INVALID;
		break;
	case ENOMEM:
		ret_code = LTTNG_ERR_NOMEM;
		break;
	case EEXIST:
		ret_code = LTTNG_ERR_PROCESS_ATTR_EXISTS;
		break;
	default:
		ret_code = LTTNG_ERR_UNK;
		break;
	}
end:
	return ret_code;
}

enum lttng_error_code
kernel_process_attr_tracker_inclusion_set_add_value(struct ltt_kernel_session *session,
						    enum lttng_process_attr process_attr,
						    const struct process_attr_value *value)
{
	int ret, integral_value;
	enum lttng_error_code ret_code;
	struct process_attr_tracker *tracker;
	enum process_attr_tracker_status status;

	/*
	 * Convert process attribute tracker value to the integral
	 * representation required by the kern-ctl API.
	 */
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		integral_value = (int) value->value.pid;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			uid_t uid;

			ret_code = utils_user_id_from_name(value->value.user_name, &uid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) uid;
		} else {
			integral_value = (int) value->value.uid;
		}
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			gid_t gid;

			ret_code = utils_group_id_from_name(value->value.group_name, &gid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) gid;
		} else {
			integral_value = (int) value->value.gid;
		}
		break;
	default:
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	tracker = _kernel_get_process_attr_tracker(session, process_attr);
	if (!tracker) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	status = process_attr_tracker_inclusion_set_add_value(tracker, value);
	if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
		switch (status) {
		case PROCESS_ATTR_TRACKER_STATUS_EXISTS:
			ret_code = LTTNG_ERR_PROCESS_ATTR_EXISTS;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY:
			ret_code = LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_ERROR:
		default:
			ret_code = LTTNG_ERR_UNK;
			break;
		}
		goto end;
	}

	DBG("Kernel track %s %d for session id %" PRIu64,
	    lttng_process_attr_to_string(process_attr),
	    integral_value,
	    session->id);
	if (process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID) {
		/*
		 * Maintain a special case for the process ID process attribute
		 * tracker as it was the only supported attribute prior to 2.12.
		 */
		ret = kernctl_track_pid(session->fd, integral_value);
	} else {
		ret = kernctl_track_id(session->fd, process_attr, integral_value);
	}
	if (ret == 0) {
		ret_code = LTTNG_OK;
		goto end;
	}

	kernel_wait_quiescent();

	/* kern-ctl error handling */
	switch (-ret) {
	case 0:
		ret_code = LTTNG_OK;
		break;
	case EINVAL:
		ret_code = LTTNG_ERR_INVALID;
		break;
	case ENOMEM:
		ret_code = LTTNG_ERR_NOMEM;
		break;
	case EEXIST:
		ret_code = LTTNG_ERR_PROCESS_ATTR_EXISTS;
		break;
	default:
		ret_code = LTTNG_ERR_UNK;
		break;
	}

	/* Attempt to remove the value from the tracker. */
	status = process_attr_tracker_inclusion_set_remove_value(tracker, value);
	if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
		ERR("Failed to roll-back the tracking of kernel %s process attribute %d while handling a kern-ctl error",
		    lttng_process_attr_to_string(process_attr),
		    integral_value);
	}
end:
	return ret_code;
}

enum lttng_error_code
kernel_process_attr_tracker_inclusion_set_remove_value(struct ltt_kernel_session *session,
						       enum lttng_process_attr process_attr,
						       const struct process_attr_value *value)
{
	int ret, integral_value;
	enum lttng_error_code ret_code;
	struct process_attr_tracker *tracker;
	enum process_attr_tracker_status status;

	/*
	 * Convert process attribute tracker value to the integral
	 * representation required by the kern-ctl API.
	 */
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		integral_value = (int) value->value.pid;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			uid_t uid;

			ret_code = utils_user_id_from_name(value->value.user_name, &uid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) uid;
		} else {
			integral_value = (int) value->value.uid;
		}
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			gid_t gid;

			ret_code = utils_group_id_from_name(value->value.group_name, &gid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) gid;
		} else {
			integral_value = (int) value->value.gid;
		}
		break;
	default:
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	tracker = _kernel_get_process_attr_tracker(session, process_attr);
	if (!tracker) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	status = process_attr_tracker_inclusion_set_remove_value(tracker, value);
	if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
		switch (status) {
		case PROCESS_ATTR_TRACKER_STATUS_MISSING:
			ret_code = LTTNG_ERR_PROCESS_ATTR_MISSING;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY:
			ret_code = LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_ERROR:
		default:
			ret_code = LTTNG_ERR_UNK;
			break;
		}
		goto end;
	}

	DBG("Kernel track %s %d for session id %" PRIu64,
	    lttng_process_attr_to_string(process_attr),
	    integral_value,
	    session->id);
	if (process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID) {
		/*
		 * Maintain a special case for the process ID process attribute
		 * tracker as it was the only supported attribute prior to 2.12.
		 */
		ret = kernctl_untrack_pid(session->fd, integral_value);
	} else {
		ret = kernctl_untrack_id(session->fd, process_attr, integral_value);
	}
	if (ret == 0) {
		ret_code = LTTNG_OK;
		goto end;
	}
	kernel_wait_quiescent();

	/* kern-ctl error handling */
	switch (-ret) {
	case 0:
		ret_code = LTTNG_OK;
		break;
	case EINVAL:
		ret_code = LTTNG_ERR_INVALID;
		break;
	case ENOMEM:
		ret_code = LTTNG_ERR_NOMEM;
		break;
	case ENOENT:
		ret_code = LTTNG_ERR_PROCESS_ATTR_MISSING;
		break;
	default:
		ret_code = LTTNG_ERR_UNK;
		break;
	}

	/* Attempt to add the value to the tracker. */
	status = process_attr_tracker_inclusion_set_add_value(tracker, value);
	if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
		ERR("Failed to roll-back the tracking of kernel %s process attribute %d while handling a kern-ctl error",
		    lttng_process_attr_to_string(process_attr),
		    integral_value);
	}
end:
	return ret_code;
}

/*
 * Create kernel metadata, open from the kernel tracer and add it to the
 * kernel session.
 */
int kernel_open_metadata(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_metadata *lkm = nullptr;

	LTTNG_ASSERT(session);

	/* Allocate kernel metadata */
	lkm = trace_kernel_create_metadata();
	if (lkm == nullptr) {
		goto error;
	}

	/* Kernel tracer metadata creation */
	ret = kernctl_open_metadata(session->fd, &lkm->conf->attr);
	if (ret < 0) {
		goto error_open;
	}

	lkm->fd = ret;
	lkm->key = ++next_kernel_channel_key;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lkm->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	session->metadata = lkm;

	DBG("Kernel metadata opened (fd: %d)", lkm->fd);

	return 0;

error_open:
	trace_kernel_destroy_metadata(lkm);
error:
	return -1;
}

/*
 * Start tracing session.
 */
int kernel_start_session(struct ltt_kernel_session *session)
{
	int ret;

	LTTNG_ASSERT(session);

	ret = kernctl_start_session(session->fd);
	if (ret < 0) {
		PERROR("ioctl start session");
		goto error;
	}

	DBG("Kernel session started");

	return 0;

error:
	return ret;
}

/*
 * Make a kernel wait to make sure in-flight probe have completed.
 */
void kernel_wait_quiescent()
{
	int ret;
	int fd = kernel_tracer_fd;

	DBG("Kernel quiescent wait on %d", fd);

	ret = kernctl_wait_quiescent(fd);
	if (ret < 0) {
		PERROR("wait quiescent ioctl");
		ERR("Kernel quiescent wait failed");
	}
}

/*
 *  Force flush buffer of metadata.
 */
int kernel_metadata_flush_buffer(int fd)
{
	int ret;

	DBG("Kernel flushing metadata buffer on fd %d", fd);

	ret = kernctl_buffer_flush(fd);
	if (ret < 0) {
		ERR("Fail to flush metadata buffers %d (ret: %d)", fd, ret);
	}

	return 0;
}

/*
 * Force flush buffer for channel.
 */
int kernel_flush_buffer(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *stream;

	LTTNG_ASSERT(channel);

	DBG("Flush buffer for channel %s", channel->channel->name);

	cds_list_for_each_entry (stream, &channel->stream_list.head, list) {
		DBG("Flushing channel stream %d", stream->fd);
		ret = kernctl_buffer_flush(stream->fd);
		if (ret < 0) {
			PERROR("ioctl");
			ERR("Fail to flush buffer for stream %d (ret: %d)", stream->fd, ret);
		}
	}

	return 0;
}

/*
 * Stop tracing session.
 */
int kernel_stop_session(struct ltt_kernel_session *session)
{
	int ret;

	LTTNG_ASSERT(session);

	ret = kernctl_stop_session(session->fd);
	if (ret < 0) {
		goto error;
	}

	DBG("Kernel session stopped");

	return 0;

error:
	return ret;
}

/*
 * Open stream of channel, register it to the kernel tracer and add it
 * to the stream list of the channel.
 *
 * Note: given that the streams may appear in random order wrt CPU
 * number (e.g. cpu hotplug), the index value of the stream number in
 * the stream name is not necessarily linked to the CPU number.
 *
 * Return the number of created stream. Else, a negative value.
 */
int kernel_open_channel_stream(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *lks;

	LTTNG_ASSERT(channel);

	while ((ret = kernctl_create_stream(channel->fd)) >= 0) {
		lks = trace_kernel_create_stream(channel->channel->name, channel->stream_count);
		if (lks == nullptr) {
			ret = close(ret);
			if (ret) {
				PERROR("close");
			}
			goto error;
		}

		lks->fd = ret;
		/* Prevent fd duplication after execlp() */
		ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl session fd");
		}

		lks->tracefile_size = channel->channel->attr.tracefile_size;
		lks->tracefile_count = channel->channel->attr.tracefile_count;

		/* Add stream to channel stream list */
		cds_list_add(&lks->list, &channel->stream_list.head);
		channel->stream_count++;

		DBG("Kernel stream %s created (fd: %d, state: %d)", lks->name, lks->fd, lks->state);
	}

	return channel->stream_count;

error:
	return -1;
}

/*
 * Open the metadata stream and set it to the kernel session.
 */
int kernel_open_metadata_stream(struct ltt_kernel_session *session)
{
	int ret;

	LTTNG_ASSERT(session);

	ret = kernctl_create_stream(session->metadata->fd);
	if (ret < 0) {
		PERROR("kernel create metadata stream");
		goto error;
	}

	DBG("Kernel metadata stream created (fd: %d)", ret);
	session->metadata_stream_fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(session->metadata_stream_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	return 0;

error:
	return -1;
}

/*
 * Get the event list from the kernel tracer and return the number of elements.
 */
ssize_t kernel_list_events(struct lttng_event **events)
{
	int fd, ret;
	char *event;
	size_t nbmem, count = 0;
	FILE *fp;
	struct lttng_event *elist;

	LTTNG_ASSERT(events);

	fd = kernctl_tracepoint_list(kernel_tracer_fd);
	if (fd < 0) {
		PERROR("kernel tracepoint list");
		goto error;
	}

	fp = fdopen(fd, "r");
	if (fp == nullptr) {
		PERROR("kernel tracepoint list fdopen");
		goto error_fp;
	}

	/*
	 * Init memory size counter
	 * See kernel-ctl.h for explanation of this value
	 */
	nbmem = KERNEL_EVENT_INIT_LIST_SIZE;
	elist = calloc<lttng_event>(nbmem);
	if (elist == nullptr) {
		PERROR("alloc list events");
		count = -ENOMEM;
		goto end;
	}

	while (fscanf(fp, "event { name = %m[^;]; };\n", &event) == 1) {
		if (count >= nbmem) {
			struct lttng_event *new_elist;
			size_t new_nbmem;

			new_nbmem = nbmem << 1;
			DBG("Reallocating event list from %zu to %zu bytes", nbmem, new_nbmem);
			new_elist = (lttng_event *) realloc(elist,
							    new_nbmem * sizeof(struct lttng_event));
			if (new_elist == nullptr) {
				PERROR("realloc list events");
				free(event);
				free(elist);
				count = -ENOMEM;
				goto end;
			}
			/* Zero the new memory */
			memset(new_elist + nbmem,
			       0,
			       (new_nbmem - nbmem) * sizeof(struct lttng_event));
			nbmem = new_nbmem;
			elist = new_elist;
		}
		strncpy(elist[count].name, event, LTTNG_SYMBOL_NAME_LEN);
		elist[count].name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		elist[count].enabled = -1;
		count++;
		free(event);
	}

	*events = elist;
	DBG("Kernel list events done (%zu events)", count);
end:
	ret = fclose(fp); /* closes both fp and fd */
	if (ret) {
		PERROR("fclose");
	}
	return count;

error_fp:
	ret = close(fd);
	if (ret) {
		PERROR("close");
	}
error:
	return -1;
}

/*
 * Get kernel version and validate it.
 */
int kernel_validate_version(struct lttng_kernel_abi_tracer_version *version,
			    struct lttng_kernel_abi_tracer_abi_version *abi_version)
{
	int ret;

	ret = kernctl_tracer_version(kernel_tracer_fd, version);
	if (ret < 0) {
		ERR("Failed to retrieve the lttng-modules version");
		goto error;
	}

	/* Validate version */
	if (version->major != VERSION_MAJOR) {
		ERR("Kernel tracer major version (%d) is not compatible with lttng-tools major version (%d)",
		    version->major,
		    VERSION_MAJOR);
		goto error_version;
	}
	ret = kernctl_tracer_abi_version(kernel_tracer_fd, abi_version);
	if (ret < 0) {
		ERR("Failed to retrieve lttng-modules ABI version");
		goto error;
	}
	if (abi_version->major != LTTNG_KERNEL_ABI_MAJOR_VERSION) {
		ERR("Kernel tracer ABI version (%d.%d) does not match the expected ABI major version (%d.*)",
		    abi_version->major,
		    abi_version->minor,
		    LTTNG_KERNEL_ABI_MAJOR_VERSION);
		goto error;
	}
	DBG2("Kernel tracer version validated (%d.%d, ABI %d.%d)",
	     version->major,
	     version->minor,
	     abi_version->major,
	     abi_version->minor);
	return 0;

error_version:
	ret = -1;

error:
	ERR("Kernel tracer version check failed; kernel tracing will not be available");
	return ret;
}

/*
 * Kernel work-arounds called at the start of sessiond main().
 */
int init_kernel_workarounds()
{
	int ret;
	FILE *fp;

	/*
	 * boot_id needs to be read once before being used concurrently
	 * to deal with a Linux kernel race. A fix is proposed for
	 * upstream, but the work-around is needed for older kernels.
	 */
	fp = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (!fp) {
		goto end_boot_id;
	}
	while (!feof(fp)) {
		char buf[37] = "";

		ret = fread(buf, 1, sizeof(buf), fp);
		if (ret < 0) {
			/* Ignore error, we don't really care */
		}
	}
	ret = fclose(fp);
	if (ret) {
		PERROR("fclose");
	}
end_boot_id:
	return 0;
}

/*
 * Teardown of a kernel session, keeping data required by destroy notifiers.
 */
void kernel_destroy_session(struct ltt_kernel_session *ksess)
{
	struct lttng_trace_chunk *trace_chunk;

	if (ksess == nullptr) {
		DBG3("No kernel session when tearing down session");
		return;
	}

	DBG("Tearing down kernel session");
	trace_chunk = ksess->current_trace_chunk;

	/*
	 * Destroy channels on the consumer if at least one FD has been sent and we
	 * are in no output mode because the streams are in *no* monitor mode so we
	 * have to send a command to clean them up or else they leaked.
	 */
	if (!ksess->output_traces && ksess->consumer_fds_sent) {
		int ret;
		struct consumer_socket *socket;
		struct lttng_ht_iter iter;

		/* For each consumer socket. */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			ksess->consumer->socks->ht, &iter.iter, socket, node.node) {
			struct ltt_kernel_channel *chan;

			/* For each channel, ask the consumer to destroy it. */
			cds_list_for_each_entry (chan, &ksess->channel_list.head, list) {
				ret = kernel_consumer_destroy_channel(socket, chan);
				if (ret < 0) {
					/* Consumer is probably dead. Use next socket. */
					continue;
				}
			}
		}
	}

	/* Close any relayd session */
	consumer_output_send_destroy_relayd(ksess->consumer);

	trace_kernel_destroy_session(ksess);
	lttng_trace_chunk_put(trace_chunk);
}

/* Teardown of data required by destroy notifiers. */
void kernel_free_session(struct ltt_kernel_session *ksess)
{
	if (ksess == nullptr) {
		return;
	}
	trace_kernel_free_session(ksess);
}

/*
 * Destroy a kernel channel object. It does not do anything on the tracer side.
 */
void kernel_destroy_channel(struct ltt_kernel_channel *kchan)
{
	struct ltt_kernel_session *ksess = nullptr;

	LTTNG_ASSERT(kchan);
	LTTNG_ASSERT(kchan->channel);

	DBG3("Kernel destroy channel %s", kchan->channel->name);

	/* Update channel count of associated session. */
	if (kchan->session) {
		/* Keep pointer reference so we can update it after the destroy. */
		ksess = kchan->session;
	}

	trace_kernel_destroy_channel(kchan);

	/*
	 * At this point the kernel channel is not visible anymore. This is safe
	 * since in order to work on a visible kernel session, the tracing session
	 * lock (ltt_session.lock) MUST be acquired.
	 */
	if (ksess) {
		ksess->channel_count--;
	}
}

/*
 * Take a snapshot for a given kernel session.
 *
 * Return LTTNG_OK on success or else return a LTTNG_ERR code.
 */
enum lttng_error_code kernel_snapshot_record(struct ltt_kernel_session *ksess,
					     const struct consumer_output *output,
					     uint64_t nb_packets_per_stream)
{
	int err, ret, saved_metadata_fd;
	enum lttng_error_code status = LTTNG_OK;
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;
	struct ltt_kernel_metadata *saved_metadata;
	char *trace_path = nullptr;
	size_t consumer_path_offset = 0;

	LTTNG_ASSERT(ksess);
	LTTNG_ASSERT(ksess->consumer);
	LTTNG_ASSERT(output);

	DBG("Kernel snapshot record started");

	/* Save current metadata since the following calls will change it. */
	saved_metadata = ksess->metadata;
	saved_metadata_fd = ksess->metadata_stream_fd;

	ret = kernel_open_metadata(ksess);
	if (ret < 0) {
		status = LTTNG_ERR_KERN_META_FAIL;
		goto error;
	}

	ret = kernel_open_metadata_stream(ksess);
	if (ret < 0) {
		status = LTTNG_ERR_KERN_META_FAIL;
		goto error_open_stream;
	}

	trace_path = setup_channel_trace_path(ksess->consumer, "", &consumer_path_offset);
	if (!trace_path) {
		status = LTTNG_ERR_INVALID;
		goto error;
	}

	{
		/* Send metadata to consumer and snapshot everything. */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (output->socks->ht, &iter.iter, socket, node.node) {
			struct ltt_kernel_channel *chan;

			pthread_mutex_lock(socket->lock);
			/* This stream must not be monitored by the consumer. */
			ret = kernel_consumer_add_metadata(socket, ksess, 0);
			pthread_mutex_unlock(socket->lock);
			if (ret < 0) {
				status = LTTNG_ERR_KERN_META_FAIL;
				goto error_consumer;
			}

			/* For each channel, ask the consumer to snapshot it. */
			cds_list_for_each_entry (chan, &ksess->channel_list.head, list) {
				status =
					consumer_snapshot_channel(socket,
								  chan->key,
								  output,
								  0,
								  &trace_path[consumer_path_offset],
								  nb_packets_per_stream);
				if (status != LTTNG_OK) {
					(void) kernel_consumer_destroy_metadata(socket,
										ksess->metadata);
					goto error_consumer;
				}
			}

			/* Snapshot metadata, */
			status = consumer_snapshot_channel(socket,
							   ksess->metadata->key,
							   output,
							   1,
							   &trace_path[consumer_path_offset],
							   0);
			if (status != LTTNG_OK) {
				goto error_consumer;
			}

			/*
			 * The metadata snapshot is done, ask the consumer to destroy it since
			 * it's not monitored on the consumer side.
			 */
			(void) kernel_consumer_destroy_metadata(socket, ksess->metadata);
		}
	}

error_consumer:
	/* Close newly opened metadata stream. It's now on the consumer side. */
	err = close(ksess->metadata_stream_fd);
	if (err < 0) {
		PERROR("close snapshot kernel");
	}

error_open_stream:
	trace_kernel_destroy_metadata(ksess->metadata);
error:
	/* Restore metadata state.*/
	ksess->metadata = saved_metadata;
	ksess->metadata_stream_fd = saved_metadata_fd;
	free(trace_path);
	return status;
}

/*
 * Get the syscall mask array from the kernel tracer.
 *
 * Return 0 on success else a negative value. In both case, syscall_mask should
 * be freed.
 */
int kernel_syscall_mask(int chan_fd, char **syscall_mask, uint32_t *nr_bits)
{
	LTTNG_ASSERT(syscall_mask);
	LTTNG_ASSERT(nr_bits);

	return kernctl_syscall_mask(chan_fd, syscall_mask, nr_bits);
}

static int kernel_tracer_abi_greater_or_equal(unsigned int major, unsigned int minor)
{
	int ret;
	struct lttng_kernel_abi_tracer_abi_version abi;

	ret = kernctl_tracer_abi_version(kernel_tracer_fd, &abi);
	if (ret < 0) {
		ERR("Failed to retrieve lttng-modules ABI version");
		goto error;
	}

	ret = abi.major > major || (abi.major == major && abi.minor >= minor);
error:
	return ret;
}

/*
 * Check for the support of the RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS via abi
 * version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_ring_buffer_snapshot_sample_positions()
{
	/*
	 * RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS was introduced in 2.3
	 */
	return kernel_tracer_abi_greater_or_equal(2, 3);
}

/*
 * Check for the support of the packet sequence number via abi version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_ring_buffer_packet_sequence_number()
{
	/*
	 * Packet sequence number was introduced in LTTng 2.8,
	 * lttng-modules ABI 2.1.
	 */
	return kernel_tracer_abi_greater_or_equal(2, 1);
}

/*
 * Check for the support of event notifiers via abi version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_event_notifiers()
{
	/*
	 * Event notifiers were introduced in LTTng 2.13, lttng-modules ABI 2.6.
	 */
	return kernel_tracer_abi_greater_or_equal(2, 6);
}

/*
 * Rotate a kernel session.
 *
 * Return LTTNG_OK on success or else an LTTng error code.
 */
enum lttng_error_code kernel_rotate_session(struct ltt_session *session)
{
	int ret;
	enum lttng_error_code status = LTTNG_OK;
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;
	struct ltt_kernel_session *ksess = session->kernel_session;

	LTTNG_ASSERT(ksess);
	LTTNG_ASSERT(ksess->consumer);

	DBG("Rotate kernel session %s started (session %" PRIu64 ")", session->name, session->id);

	{
		/*
		 * Note that this loop will end after one iteration given that there is
		 * only one kernel consumer.
		 */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			ksess->consumer->socks->ht, &iter.iter, socket, node.node) {
			struct ltt_kernel_channel *chan;

			/* For each channel, ask the consumer to rotate it. */
			cds_list_for_each_entry (chan, &ksess->channel_list.head, list) {
				DBG("Rotate kernel channel %" PRIu64 ", session %s",
				    chan->key,
				    session->name);
				ret = consumer_rotate_channel(socket,
							      chan->key,
							      ksess->consumer,
							      /* is_metadata_channel */ false);
				if (ret < 0) {
					status = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
					goto error;
				}
			}

			/*
			 * Rotate the metadata channel.
			 */
			ret = consumer_rotate_channel(socket,
						      ksess->metadata->key,
						      ksess->consumer,
						      /* is_metadata_channel */ true);
			if (ret < 0) {
				status = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
				goto error;
			}
		}
	}

error:
	return status;
}

enum lttng_error_code kernel_create_channel_subdirectories(const struct ltt_kernel_session *ksess)
{
	enum lttng_error_code ret = LTTNG_OK;
	enum lttng_trace_chunk_status chunk_status;

	lttng::urcu::read_lock_guard read_lock;
	LTTNG_ASSERT(ksess->current_trace_chunk);

	/*
	 * Create the index subdirectory which will take care
	 * of implicitly creating the channel's path.
	 */
	chunk_status = lttng_trace_chunk_create_subdirectory(
		ksess->current_trace_chunk, DEFAULT_KERNEL_TRACE_DIR "/" DEFAULT_INDEX_DIR);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = LTTNG_ERR_CREATE_DIR_FAIL;
		goto error;
	}
error:
	return ret;
}

/*
 * Setup necessary data for kernel tracer action.
 */
int init_kernel_tracer()
{
	int ret;
	bool is_root = !getuid();

	/* Modprobe lttng kernel modules */
	ret = modprobe_lttng_control();
	if (ret < 0) {
		goto error;
	}

	/* Open debugfs lttng */
	kernel_tracer_fd = open(module_proc_lttng, O_RDWR);
	if (kernel_tracer_fd < 0) {
		DBG("Failed to open %s", module_proc_lttng);
		goto error_open;
	}

	/* Validate kernel version */
	ret = kernel_validate_version(&the_kernel_tracer_version, &the_kernel_tracer_abi_version);
	if (ret < 0) {
		goto error_version;
	}

	ret = modprobe_lttng_data();
	if (ret < 0) {
		goto error_modules;
	}

	ret = kernel_supports_ring_buffer_snapshot_sample_positions();
	if (ret < 0) {
		goto error_modules;
	}
	if (ret < 1) {
		WARN("Kernel tracer does not support buffer monitoring. "
		     "The monitoring timer of channels in the kernel domain "
		     "will be set to 0 (disabled).");
	}

	ret = kernel_supports_event_notifiers();
	if (ret < 0) {
		ERR("Failed to check for kernel tracer event notifier support");
		goto error_modules;
	}
	ret = kernel_create_event_notifier_group(&kernel_tracer_event_notifier_group_fd);
	if (ret < 0) {
		/* This is not fatal. */
		WARN("Failed to create kernel event notifier group");
		kernel_tracer_event_notifier_group_fd = -1;
	} else {
		enum event_notifier_error_accounting_status error_accounting_status;
		enum lttng_error_code error_code_ret =
			kernel_create_event_notifier_group_notification_fd(
				&kernel_tracer_event_notifier_group_notification_fd);

		if (error_code_ret != LTTNG_OK) {
			goto error_modules;
		}

		error_accounting_status = event_notifier_error_accounting_register_kernel(
			kernel_tracer_event_notifier_group_fd);
		if (error_accounting_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			ERR("Failed to initialize event notifier error accounting for kernel tracer");
			error_code_ret = LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING;
			goto error_modules;
		}

		kernel_token_to_event_notifier_rule_ht = cds_lfht_new(
			DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
		if (!kernel_token_to_event_notifier_rule_ht) {
			goto error_token_ht;
		}
	}

	DBG("Kernel tracer initialized: kernel tracer fd = %d, event notifier group fd = %d, event notifier group notification fd = %d",
	    kernel_tracer_fd,
	    kernel_tracer_event_notifier_group_fd,
	    kernel_tracer_event_notifier_group_notification_fd);

	ret = syscall_init_table(kernel_tracer_fd);
	if (ret < 0) {
		ERR("Unable to populate syscall table. Syscall tracing won't "
		    "work for this session daemon.");
	}

	return 0;

error_version:
	modprobe_remove_lttng_control();
	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer file descriptor: fd = %d", kernel_tracer_fd);
	}

	kernel_tracer_fd = -1;
	return LTTNG_ERR_KERN_VERSION;

error_token_ht:
	ret = close(kernel_tracer_event_notifier_group_notification_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer event notifier group notification file descriptor: fd = %d",
		       kernel_tracer_event_notifier_group_notification_fd);
	}

	kernel_tracer_event_notifier_group_notification_fd = -1;

error_modules:
	ret = close(kernel_tracer_event_notifier_group_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer event notifier group file descriptor: fd = %d",
		       kernel_tracer_event_notifier_group_fd);
	}

	kernel_tracer_event_notifier_group_fd = -1;

	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer file descriptor: fd = %d", kernel_tracer_fd);
	}

	kernel_tracer_fd = -1;

error_open:
	modprobe_remove_lttng_control();

error:
	WARN("No kernel tracer available");
	kernel_tracer_fd = -1;
	if (!is_root) {
		return LTTNG_ERR_NEED_ROOT_SESSIOND;
	} else {
		return LTTNG_ERR_KERN_NA;
	}
}

void cleanup_kernel_tracer()
{
	DBG2("Closing kernel event notifier group notification file descriptor");
	if (kernel_tracer_event_notifier_group_notification_fd >= 0) {
		int ret = notification_thread_command_remove_tracer_event_source(
			the_notification_thread_handle,
			kernel_tracer_event_notifier_group_notification_fd);
		if (ret != LTTNG_OK) {
			ERR("Failed to remove kernel event notifier notification from notification thread");
		}

		ret = close(kernel_tracer_event_notifier_group_notification_fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier group notification file descriptor: fd = %d",
			       kernel_tracer_event_notifier_group_notification_fd);
		}

		kernel_tracer_event_notifier_group_notification_fd = -1;
	}

	if (kernel_token_to_event_notifier_rule_ht) {
		const int ret = cds_lfht_destroy(kernel_token_to_event_notifier_rule_ht, nullptr);
		LTTNG_ASSERT(ret == 0);
	}

	DBG2("Closing kernel event notifier group file descriptor");
	if (kernel_tracer_event_notifier_group_fd >= 0) {
		const int ret = close(kernel_tracer_event_notifier_group_fd);

		if (ret) {
			PERROR("Failed to close kernel event notifier group file descriptor: fd = %d",
			       kernel_tracer_event_notifier_group_fd);
		}

		kernel_tracer_event_notifier_group_fd = -1;
	}

	DBG2("Closing kernel fd");
	if (kernel_tracer_fd >= 0) {
		const int ret = close(kernel_tracer_fd);

		if (ret) {
			PERROR("Failed to close kernel tracer file descriptor: fd = %d",
			       kernel_tracer_fd);
		}

		kernel_tracer_fd = -1;
	}

	free(syscall_table);
}

bool kernel_tracer_is_initialized()
{
	return kernel_tracer_fd >= 0;
}

/*
 *  Clear a kernel session.
 *
 * Return LTTNG_OK on success or else an LTTng error code.
 */
enum lttng_error_code kernel_clear_session(struct ltt_session *session)
{
	int ret;
	enum lttng_error_code status = LTTNG_OK;
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;
	struct ltt_kernel_session *ksess = session->kernel_session;

	LTTNG_ASSERT(ksess);
	LTTNG_ASSERT(ksess->consumer);

	DBG("Clear kernel session %s (session %" PRIu64 ")", session->name, session->id);

	if (ksess->active) {
		ERR("Expecting inactive session %s (%" PRIu64 ")", session->name, session->id);
		status = LTTNG_ERR_FATAL;
		goto end;
	}

	{
		/*
		 * Note that this loop will end after one iteration given that there is
		 * only one kernel consumer.
		 */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			ksess->consumer->socks->ht, &iter.iter, socket, node.node) {
			struct ltt_kernel_channel *chan;

			/* For each channel, ask the consumer to clear it. */
			cds_list_for_each_entry (chan, &ksess->channel_list.head, list) {
				DBG("Clear kernel channel %" PRIu64 ", session %s",
				    chan->key,
				    session->name);
				ret = consumer_clear_channel(socket, chan->key);
				if (ret < 0) {
					goto error;
				}
			}

			if (!ksess->metadata) {
				/*
				 * Nothing to do for the metadata.
				 * This is a snapshot session.
				 * The metadata is genererated on the fly.
				 */
				continue;
			}

			/*
			 * Clear the metadata channel.
			 * Metadata channel is not cleared per se but we still need to
			 * perform a rotation operation on it behind the scene.
			 */
			ret = consumer_clear_channel(socket, ksess->metadata->key);
			if (ret < 0) {
				goto error;
			}
		}
	}

	goto end;
error:
	switch (-ret) {
	case LTTCOMM_CONSUMERD_RELAYD_CLEAR_DISALLOWED:
		status = LTTNG_ERR_CLEAR_RELAY_DISALLOWED;
		break;
	default:
		status = LTTNG_ERR_CLEAR_FAIL_CONSUMER;
		break;
	}
end:
	return status;
}

enum lttng_error_code
kernel_create_event_notifier_group_notification_fd(int *event_notifier_group_notification_fd)
{
	int local_fd = -1, ret;
	enum lttng_error_code error_code_ret;

	LTTNG_ASSERT(event_notifier_group_notification_fd);

	ret = kernctl_create_event_notifier_group_notification_fd(
		kernel_tracer_event_notifier_group_fd);
	if (ret < 0) {
		PERROR("Failed to create kernel event notifier group notification file descriptor");
		error_code_ret = LTTNG_ERR_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD;
		goto error;
	}

	local_fd = ret;

	/* Prevent fd duplication after execlp(). */
	ret = fcntl(local_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to set FD_CLOEXEC on kernel event notifier group notification file descriptor: fd = %d",
		       local_fd);
		error_code_ret = LTTNG_ERR_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD;
		goto error;
	}

	DBG("Created kernel notifier group notification file descriptor: fd = %d", local_fd);
	error_code_ret = LTTNG_OK;
	*event_notifier_group_notification_fd = local_fd;
	local_fd = -1;

error:
	if (local_fd >= 0) {
		ret = close(local_fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier group notification file descriptor: fd = %d",
			       local_fd);
		}
	}

	return error_code_ret;
}

enum lttng_error_code
kernel_destroy_event_notifier_group_notification_fd(int event_notifier_group_notification_fd)
{
	enum lttng_error_code ret_code = LTTNG_OK;

	DBG("Closing event notifier group notification file descriptor: fd = %d",
	    event_notifier_group_notification_fd);
	if (event_notifier_group_notification_fd >= 0) {
		const int ret = close(event_notifier_group_notification_fd);
		if (ret) {
			PERROR("Failed to close event notifier group notification file descriptor: fd = %d",
			       event_notifier_group_notification_fd);
		}
	}

	return ret_code;
}

static unsigned long hash_trigger(const struct lttng_trigger *trigger)
{
	const struct lttng_condition *condition = lttng_trigger_get_const_condition(trigger);

	return lttng_condition_hash(condition);
}

static int match_trigger(struct cds_lfht_node *node, const void *key)
{
	const struct ltt_kernel_event_notifier_rule *event_notifier_rule;
	const struct lttng_trigger *trigger = (lttng_trigger *) key;

	event_notifier_rule =
		caa_container_of(node, const struct ltt_kernel_event_notifier_rule, ht_node);

	return lttng_trigger_is_equal(trigger, event_notifier_rule->trigger);
}

static enum lttng_error_code kernel_create_event_notifier_rule(
	struct lttng_trigger *trigger, const struct lttng_credentials *creds, uint64_t token)
{
	int err, fd, ret = 0;
	enum lttng_error_code error_code_ret;
	enum lttng_condition_status condition_status;
	enum lttng_condition_type condition_type;
	enum lttng_event_rule_type event_rule_type;
	struct ltt_kernel_event_notifier_rule *event_notifier_rule;
	struct lttng_kernel_abi_event_notifier kernel_event_notifier = {};
	unsigned int capture_bytecode_count = 0, i;
	const struct lttng_condition *condition = nullptr;
	const struct lttng_event_rule *event_rule = nullptr;
	enum lttng_condition_status cond_status;

	LTTNG_ASSERT(trigger);

	condition = lttng_trigger_get_const_condition(trigger);
	LTTNG_ASSERT(condition);

	condition_type = lttng_condition_get_type(condition);
	LTTNG_ASSERT(condition_type == LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	/* Does not acquire a reference. */
	condition_status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(condition_status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(event_rule);

	event_rule_type = lttng_event_rule_get_type(event_rule);
	LTTNG_ASSERT(event_rule_type != LTTNG_EVENT_RULE_TYPE_UNKNOWN);

	error_code_ret = trace_kernel_create_event_notifier_rule(
		trigger,
		token,
		lttng_condition_event_rule_matches_get_error_counter_index(condition),
		&event_notifier_rule);
	if (error_code_ret != LTTNG_OK) {
		goto error;
	}

	error_code_ret = trace_kernel_init_event_notifier_from_event_rule(event_rule,
									  &kernel_event_notifier);
	if (error_code_ret != LTTNG_OK) {
		goto free_event;
	}

	kernel_event_notifier.event.token = event_notifier_rule->token;
	kernel_event_notifier.error_counter_idx =
		lttng_condition_event_rule_matches_get_error_counter_index(condition);

	fd = kernctl_create_event_notifier(kernel_tracer_event_notifier_group_fd,
					   &kernel_event_notifier);
	if (fd < 0) {
		switch (-fd) {
		case EEXIST:
			error_code_ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		case ENOSYS:
			WARN("Failed to create kernel event notifier: not notifier type not implemented");
			error_code_ret = LTTNG_ERR_KERN_EVENT_ENOSYS;
			break;
		case ENOENT:
			WARN("Failed to create kernel event notifier: not found: name = '%s'",
			     kernel_event_notifier.event.name);
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			break;
		default:
			PERROR("Failed to create kernel event notifier: error code = %d, name = '%s'",
			       fd,
			       kernel_event_notifier.event.name);
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
		}
		goto free_event;
	}

	event_notifier_rule->fd = fd;
	/* Prevent fd duplication after execlp(). */
	err = fcntl(event_notifier_rule->fd, F_SETFD, FD_CLOEXEC);
	if (err < 0) {
		PERROR("Failed to set FD_CLOEXEC on kernel event notifier file descriptor: fd = %d",
		       fd);
		error_code_ret = LTTNG_ERR_FATAL;
		goto set_cloexec_error;
	}

	if (event_notifier_rule->filter) {
		err = kernctl_filter(event_notifier_rule->fd, event_notifier_rule->filter);
		if (err < 0) {
			switch (-err) {
			case ENOMEM:
				error_code_ret = LTTNG_ERR_FILTER_NOMEM;
				break;
			default:
				error_code_ret = LTTNG_ERR_FILTER_INVAL;
				break;
			}
			goto filter_error;
		}
	}

	if (lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE) {
		ret = userspace_probe_event_rule_add_callsites(
			event_rule, creds, event_notifier_rule->fd);
		if (ret) {
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto add_callsite_error;
		}
	}

	/* Set the capture bytecode if any. */
	cond_status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
		condition, &capture_bytecode_count);
	LTTNG_ASSERT(cond_status == LTTNG_CONDITION_STATUS_OK);

	for (i = 0; i < capture_bytecode_count; i++) {
		const struct lttng_bytecode *capture_bytecode =
			lttng_condition_event_rule_matches_get_capture_bytecode_at_index(condition,
											 i);

		if (capture_bytecode == nullptr) {
			ERR("Unexpected NULL capture bytecode on condition");
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto capture_error;
		}

		ret = kernctl_capture(event_notifier_rule->fd, capture_bytecode);
		if (ret < 0) {
			ERR("Failed to set capture bytecode on event notifier rule fd: fd = %d",
			    event_notifier_rule->fd);
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto capture_error;
		}
	}

	err = kernctl_enable(event_notifier_rule->fd);
	if (err < 0) {
		switch (-err) {
		case EEXIST:
			error_code_ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("enable kernel event notifier");
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			break;
		}
		goto enable_error;
	}

	/* Add trigger to kernel token mapping in the hash table. */
	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_add(kernel_token_to_event_notifier_rule_ht,
			     hash_trigger(trigger),
			     &event_notifier_rule->ht_node);
	}

	DBG("Created kernel event notifier: name = '%s', fd = %d",
	    kernel_event_notifier.event.name,
	    event_notifier_rule->fd);

	return LTTNG_OK;

capture_error:
add_callsite_error:
enable_error:
set_cloexec_error:
filter_error:
{
	const int close_ret = close(event_notifier_rule->fd);

	if (close_ret) {
		PERROR("Failed to close kernel event notifier file descriptor: fd = %d",
		       event_notifier_rule->fd);
	}
}
free_event:
	free(event_notifier_rule);
error:
	return error_code_ret;
}

enum lttng_error_code kernel_register_event_notifier(struct lttng_trigger *trigger,
						     const struct lttng_credentials *cmd_creds)
{
	enum lttng_error_code ret;
	enum lttng_condition_status status;
	enum lttng_domain_type domain_type;
	const struct lttng_event_rule *event_rule;
	const struct lttng_condition *const condition = lttng_trigger_get_const_condition(trigger);
	const uint64_t token = lttng_trigger_get_tracer_token(trigger);

	LTTNG_ASSERT(condition);

	/* Does not acquire a reference to the event rule. */
	status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);

	domain_type = lttng_event_rule_get_domain_type(event_rule);
	LTTNG_ASSERT(domain_type == LTTNG_DOMAIN_KERNEL);

	ret = kernel_create_event_notifier_rule(trigger, cmd_creds, token);
	if (ret != LTTNG_OK) {
		ERR("Failed to create kernel event notifier rule");
	}

	return ret;
}

enum lttng_error_code kernel_unregister_event_notifier(const struct lttng_trigger *trigger)
{
	struct ltt_kernel_event_notifier_rule *token_event_rule_element;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	enum lttng_error_code error_code_ret;
	int ret;

	lttng::urcu::read_lock_guard read_lock;

	cds_lfht_lookup(kernel_token_to_event_notifier_rule_ht,
			hash_trigger(trigger),
			match_trigger,
			trigger,
			&iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		error_code_ret = LTTNG_ERR_TRIGGER_NOT_FOUND;
		goto error;
	}

	token_event_rule_element =
		caa_container_of(node, struct ltt_kernel_event_notifier_rule, ht_node);

	ret = kernel_disable_event_notifier_rule(token_event_rule_element);
	if (ret) {
		error_code_ret = LTTNG_ERR_FATAL;
		goto error;
	}

	trace_kernel_destroy_event_notifier_rule(token_event_rule_element);
	error_code_ret = LTTNG_OK;

error:

	return error_code_ret;
}

int kernel_get_notification_fd()
{
	return kernel_tracer_event_notifier_group_notification_fd;
}
