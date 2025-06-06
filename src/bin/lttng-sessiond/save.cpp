/*
 * SPDX-FileCopyrightText: 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent.hpp"
#include "kernel.hpp"
#include "lttng-syscall.hpp"
#include "save.hpp"
#include "session.hpp"
#include "trace-ust.hpp"

#include <common/config/session-config.hpp>
#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/runas.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <lttng/save-internal.hpp>

#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <urcu/uatomic.h>

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_channel_attributes(struct config_writer *writer,
					  struct lttng_channel_attr *attr)
{
	int ret;

	ret = config_writer_write_element_string(writer,
						 config_element_overwrite_mode,
						 attr->overwrite ? config_overwrite_mode_overwrite :
								   config_overwrite_mode_discard);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_subbuf_size, attr->subbuf_size);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_num_subbuf, attr->num_subbuf);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_switch_timer_interval, attr->switch_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_read_timer_interval, attr->read_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer,
						 config_element_output_type,
						 attr->output == LTTNG_EVENT_SPLICE ?
							 config_output_type_splice :
							 config_output_type_mmap);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_tracefile_size, attr->tracefile_size);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_tracefile_count, attr->tracefile_count);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_live_timer_interval, attr->live_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (attr->extended.ptr) {
		struct lttng_channel_extended *ext = nullptr;

		ext = (struct lttng_channel_extended *) attr->extended.ptr;
		ret = config_writer_write_element_unsigned_int(
			writer, config_element_monitor_timer_interval, ext->monitor_timer_interval);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_signed_int(
			writer, config_element_blocking_timeout, ext->blocking_timeout);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_channel_attributes(struct config_writer *writer,
				       struct lttng_ust_abi_channel_attr *attr)
{
	int ret;
	struct ltt_ust_channel *channel = nullptr;

	ret = config_writer_write_element_string(writer,
						 config_element_overwrite_mode,
						 attr->overwrite ? config_overwrite_mode_overwrite :
								   config_overwrite_mode_discard);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_subbuf_size, attr->subbuf_size);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_num_subbuf, attr->num_subbuf);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_switch_timer_interval, attr->switch_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_read_timer_interval, attr->read_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer,
						 config_element_output_type,
						 attr->output == LTTNG_UST_ABI_MMAP ?
							 config_output_type_mmap :
							 config_output_type_splice);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_signed_int(
		writer, config_element_blocking_timeout, attr->u.s.blocking_timeout);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	const char *allocation_policy_str;

	switch (attr->u.s.type) {
	case LTTNG_UST_ABI_CHAN_PER_CPU:
		allocation_policy_str = config_element_channel_allocation_policy_per_cpu;
		break;
	case LTTNG_UST_ABI_CHAN_PER_CHANNEL:
		allocation_policy_str = config_element_channel_allocation_policy_per_channel;
		break;
	default:
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_channel_allocation_policy, allocation_policy_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/*
	 * Fetch the monitor timer which is located in the parent of
	 * lttng_ust_channel_attr
	 */
	channel = lttng::utils::container_of(attr, &ltt_ust_channel::attr);
	ret = config_writer_write_element_unsigned_int(
		writer, config_element_monitor_timer_interval, channel->monitor_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

static const char *
get_kernel_instrumentation_string(enum lttng_kernel_abi_instrumentation instrumentation)
{
	const char *instrumentation_string;

	switch (instrumentation) {
	case LTTNG_KERNEL_ABI_ALL:
		instrumentation_string = config_event_type_all;
		break;
	case LTTNG_KERNEL_ABI_TRACEPOINT:
		instrumentation_string = config_event_type_tracepoint;
		break;
	case LTTNG_KERNEL_ABI_KPROBE:
		instrumentation_string = config_event_type_probe;
		break;
	case LTTNG_KERNEL_ABI_UPROBE:
		instrumentation_string = config_event_type_userspace_probe;
		break;
	case LTTNG_KERNEL_ABI_FUNCTION:
		instrumentation_string = config_event_type_function_entry;
		break;
	case LTTNG_KERNEL_ABI_KRETPROBE:
		instrumentation_string = config_event_type_function;
		break;
	case LTTNG_KERNEL_ABI_NOOP:
		instrumentation_string = config_event_type_noop;
		break;
	case LTTNG_KERNEL_ABI_SYSCALL:
		instrumentation_string = config_event_type_syscall;
		break;
	default:
		instrumentation_string = nullptr;
	}

	return instrumentation_string;
}

static const char *get_kernel_context_type_string(enum lttng_kernel_abi_context_type context_type)
{
	const char *context_type_string;

	switch (context_type) {
	case LTTNG_KERNEL_ABI_CONTEXT_PID:
		context_type_string = config_event_context_pid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_PROCNAME:
		context_type_string = config_event_context_procname;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_PRIO:
		context_type_string = config_event_context_prio;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_NICE:
		context_type_string = config_event_context_nice;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VPID:
		context_type_string = config_event_context_vpid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_TID:
		context_type_string = config_event_context_tid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VTID:
		context_type_string = config_event_context_vtid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_PPID:
		context_type_string = config_event_context_ppid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VPPID:
		context_type_string = config_event_context_vppid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_HOSTNAME:
		context_type_string = config_event_context_hostname;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_INTERRUPTIBLE:
		context_type_string = config_event_context_interruptible;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_PREEMPTIBLE:
		context_type_string = config_event_context_preemptible;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_NEED_RESCHEDULE:
		context_type_string = config_event_context_need_reschedule;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_MIGRATABLE:
		context_type_string = config_event_context_migratable;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_USER:
		context_type_string = config_event_context_callstack_user;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_KERNEL:
		context_type_string = config_event_context_callstack_kernel;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_CGROUP_NS:
		context_type_string = config_event_context_cgroup_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_IPC_NS:
		context_type_string = config_event_context_ipc_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_MNT_NS:
		context_type_string = config_event_context_mnt_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_NET_NS:
		context_type_string = config_event_context_net_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_PID_NS:
		context_type_string = config_event_context_pid_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_TIME_NS:
		context_type_string = config_event_context_time_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_USER_NS:
		context_type_string = config_event_context_user_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_UTS_NS:
		context_type_string = config_event_context_uts_ns;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_UID:
		context_type_string = config_event_context_uid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_EUID:
		context_type_string = config_event_context_euid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_SUID:
		context_type_string = config_event_context_suid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_GID:
		context_type_string = config_event_context_gid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_EGID:
		context_type_string = config_event_context_egid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_SGID:
		context_type_string = config_event_context_sgid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VUID:
		context_type_string = config_event_context_vuid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VEUID:
		context_type_string = config_event_context_veuid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VSUID:
		context_type_string = config_event_context_vsuid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VGID:
		context_type_string = config_event_context_vgid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VEGID:
		context_type_string = config_event_context_vegid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_VSGID:
		context_type_string = config_event_context_vsgid;
		break;
	case LTTNG_KERNEL_ABI_CONTEXT_CPU_ID:
		/* fall-through */
	default:
		context_type_string = nullptr;
	}

	return context_type_string;
}

static const char *get_ust_context_type_string(enum lttng_ust_abi_context_type context_type)
{
	const char *context_type_string;

	switch (context_type) {
	case LTTNG_UST_ABI_CONTEXT_PROCNAME:
		context_type_string = config_event_context_procname;
		break;
	case LTTNG_UST_ABI_CONTEXT_VPID:
		context_type_string = config_event_context_vpid;
		break;
	case LTTNG_UST_ABI_CONTEXT_VTID:
		context_type_string = config_event_context_vtid;
		break;
	case LTTNG_UST_ABI_CONTEXT_IP:
		context_type_string = config_event_context_ip;
		break;
	case LTTNG_UST_ABI_CONTEXT_PTHREAD_ID:
		context_type_string = config_event_context_pthread_id;
		break;
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
		context_type_string = config_event_context_app;
		break;
	case LTTNG_UST_ABI_CONTEXT_CGROUP_NS:
		context_type_string = config_event_context_cgroup_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_IPC_NS:
		context_type_string = config_event_context_ipc_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_MNT_NS:
		context_type_string = config_event_context_mnt_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_NET_NS:
		context_type_string = config_event_context_net_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_TIME_NS:
		context_type_string = config_event_context_time_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_PID_NS:
		context_type_string = config_event_context_pid_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_USER_NS:
		context_type_string = config_event_context_user_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_UTS_NS:
		context_type_string = config_event_context_uts_ns;
		break;
	case LTTNG_UST_ABI_CONTEXT_VUID:
		context_type_string = config_event_context_vuid;
		break;
	case LTTNG_UST_ABI_CONTEXT_VEUID:
		context_type_string = config_event_context_veuid;
		break;
	case LTTNG_UST_ABI_CONTEXT_VSUID:
		context_type_string = config_event_context_vsuid;
		break;
	case LTTNG_UST_ABI_CONTEXT_VGID:
		context_type_string = config_event_context_vgid;
		break;
	case LTTNG_UST_ABI_CONTEXT_VEGID:
		context_type_string = config_event_context_vegid;
		break;
	case LTTNG_UST_ABI_CONTEXT_VSGID:
		context_type_string = config_event_context_vsgid;
		break;
	case LTTNG_UST_ABI_CONTEXT_CPU_ID:
		context_type_string = config_event_context_cpu_id;
		break;
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
		/*
		 * Error, should not be stored in the XML, perf contexts
		 * are stored as a node of type event_perf_context_type.
		 */
	default:
		context_type_string = nullptr;
		break;
	}

	return context_type_string;
}

static const char *get_buffer_type_string(enum lttng_buffer_type buffer_type)
{
	const char *buffer_type_string;

	switch (buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		buffer_type_string = config_buffer_type_per_pid;
		break;
	case LTTNG_BUFFER_PER_UID:
		buffer_type_string = config_buffer_type_per_uid;
		break;
	case LTTNG_BUFFER_GLOBAL:
		buffer_type_string = config_buffer_type_global;
		break;
	default:
		buffer_type_string = nullptr;
	}

	return buffer_type_string;
}

static const char *get_loglevel_type_string(enum lttng_ust_abi_loglevel_type loglevel_type)
{
	const char *loglevel_type_string;

	switch (loglevel_type) {
	case LTTNG_UST_ABI_LOGLEVEL_ALL:
		loglevel_type_string = config_loglevel_type_all;
		break;
	case LTTNG_UST_ABI_LOGLEVEL_RANGE:
		loglevel_type_string = config_loglevel_type_range;
		break;
	case LTTNG_UST_ABI_LOGLEVEL_SINGLE:
		loglevel_type_string = config_loglevel_type_single;
		break;
	default:
		loglevel_type_string = nullptr;
	}

	return loglevel_type_string;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_function_event(struct config_writer *writer, struct ltt_kernel_event *event)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_function_attributes);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_name, event->event->u.ftrace.symbol_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /function attributes */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static int save_kernel_kprobe_event(struct config_writer *writer, struct ltt_kernel_event *event)
{
	int ret;
	const char *symbol_name;
	uint64_t addr;
	uint64_t offset;

	switch (event->event->instrumentation) {
	case LTTNG_KERNEL_ABI_KPROBE:
		/*
		 * Comments in lttng-kernel.h mention that
		 * either addr or symbol_name are set, not both.
		 */
		addr = event->event->u.kprobe.addr;
		offset = event->event->u.kprobe.offset;
		symbol_name = addr ? nullptr : event->event->u.kprobe.symbol_name;
		break;
	case LTTNG_KERNEL_ABI_KRETPROBE:
		addr = event->event->u.kretprobe.addr;
		offset = event->event->u.kretprobe.offset;
		symbol_name = addr ? nullptr : event->event->u.kretprobe.symbol_name;
		break;
	default:
		ERR("Unsupported kernel instrumentation type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_probe_attributes);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (addr) {
		ret = config_writer_write_element_unsigned_int(
			writer, config_element_address, addr);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	} else if (symbol_name) {
		ret = config_writer_write_element_string(
			writer, config_element_symbol_name, symbol_name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		/* If the offset is non-zero, write it.*/
		if (offset) {
			ret = config_writer_write_element_unsigned_int(
				writer, config_element_offset, offset);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
	} else {
		/*
		 * This really should not happen as we are either setting the
		 * address or the symbol above.
		 */
		ERR("Invalid probe/function description.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

/*
 * Save the userspace probe tracepoint event associated with the event to the
 * config writer.
 */
static int save_kernel_userspace_probe_tracepoint_event(struct config_writer *writer,
							struct ltt_kernel_event *event)
{
	int ret = 0;
	const char *probe_name, *provider_name, *binary_path;
	const struct lttng_userspace_probe_location *userspace_probe_location;
	const struct lttng_userspace_probe_location_lookup_method *lookup_method;
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;

	/* Get userspace probe location from the event. */
	userspace_probe_location = event->userspace_probe_location;
	if (!userspace_probe_location) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Get lookup method and lookup method type. */
	lookup_method = lttng_userspace_probe_location_get_lookup_method(userspace_probe_location);
	if (!lookup_method) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(lookup_method);

	/* Get the binary path, probe name and provider name. */
	binary_path =
		lttng_userspace_probe_location_tracepoint_get_binary_path(userspace_probe_location);
	if (!binary_path) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	probe_name =
		lttng_userspace_probe_location_tracepoint_get_probe_name(userspace_probe_location);
	if (!probe_name) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	provider_name = lttng_userspace_probe_location_tracepoint_get_provider_name(
		userspace_probe_location);
	if (!provider_name) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Open a userspace probe tracepoint attribute. */
	ret = config_writer_open_element(writer,
					 config_element_userspace_probe_tracepoint_attributes);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	switch (lookup_type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
		ret = config_writer_write_element_string(
			writer,
			config_element_userspace_probe_lookup,
			config_element_userspace_probe_lookup_tracepoint_sdt);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	default:
		ERR("Unsupported kernel userspace probe tracepoint lookup method.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* Write the binary path, provider name and the probe name. */
	ret = config_writer_write_element_string(
		writer, config_element_userspace_probe_location_binary_path, binary_path);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer,
		config_element_userspace_probe_tracepoint_location_provider_name,
		provider_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_userspace_probe_tracepoint_location_probe_name, probe_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Close the userspace probe tracepoint attribute. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

end:
	return ret;
}

/*
 * Save the userspace probe function event associated with the event to the
 * config writer.
 */
static int save_kernel_userspace_probe_function_event(struct config_writer *writer,
						      struct ltt_kernel_event *event)
{
	int ret = 0;
	const char *function_name, *binary_path;
	const struct lttng_userspace_probe_location *userspace_probe_location;
	const struct lttng_userspace_probe_location_lookup_method *lookup_method;
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;

	/* Get userspace probe location from the event. */
	userspace_probe_location = event->userspace_probe_location;
	if (!userspace_probe_location) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Get lookup method and lookup method type. */
	lookup_method = lttng_userspace_probe_location_get_lookup_method(userspace_probe_location);
	if (!lookup_method) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Get the binary path and the function name. */
	binary_path =
		lttng_userspace_probe_location_function_get_binary_path(userspace_probe_location);
	if (!binary_path) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	function_name =
		lttng_userspace_probe_location_function_get_function_name(userspace_probe_location);
	if (!function_name) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Open a userspace probe function attribute. */
	ret = config_writer_open_element(writer,
					 config_element_userspace_probe_function_attributes);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(lookup_method);
	switch (lookup_type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		ret = config_writer_write_element_string(
			writer,
			config_element_userspace_probe_lookup,
			config_element_userspace_probe_lookup_function_elf);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
		ret = config_writer_write_element_string(
			writer,
			config_element_userspace_probe_lookup,
			config_element_userspace_probe_lookup_function_default);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	default:
		ERR("Unsupported kernel userspace probe function lookup method.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* Write the binary path and the function name. */
	ret = config_writer_write_element_string(
		writer, config_element_userspace_probe_location_binary_path, binary_path);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer,
		config_element_userspace_probe_function_location_function_name,
		function_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Close the userspace probe function attribute. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

end:
	return ret;
}

static int save_kernel_userspace_probe_event(struct config_writer *writer,
					     struct ltt_kernel_event *event)
{
	int ret;
	struct lttng_userspace_probe_location *userspace_probe_location;

	/* Get userspace probe location from the event. */
	userspace_probe_location = event->userspace_probe_location;
	if (!userspace_probe_location) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	switch (lttng_userspace_probe_location_get_type(userspace_probe_location)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		ret = save_kernel_userspace_probe_function_event(writer, event);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		ret = save_kernel_userspace_probe_tracepoint_event(writer, event);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN:
	default:
		ERR("Unsupported kernel userspace probe location type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

end:
	return ret;
}

static int save_kernel_event(struct config_writer *writer, struct ltt_kernel_event *event)
{
	int ret;
	const char *instrumentation_type;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->event->name[0]) {
		ret = config_writer_write_element_string(
			writer, config_element_name, event->event->name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled, event->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	instrumentation_type = get_kernel_instrumentation_string(event->event->instrumentation);
	if (!instrumentation_type) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_type, instrumentation_type);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->filter_expression) {
		ret = config_writer_write_element_string(
			writer, config_element_filter, event->filter_expression);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	if (event->event->instrumentation == LTTNG_KERNEL_ABI_FUNCTION ||
	    event->event->instrumentation == LTTNG_KERNEL_ABI_KPROBE ||
	    event->event->instrumentation == LTTNG_KERNEL_ABI_UPROBE ||
	    event->event->instrumentation == LTTNG_KERNEL_ABI_KRETPROBE) {
		ret = config_writer_open_element(writer, config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		switch (event->event->instrumentation) {
		case LTTNG_KERNEL_ABI_SYSCALL:
		case LTTNG_KERNEL_ABI_FUNCTION:
			ret = save_kernel_function_event(writer, event);
			if (ret) {
				goto end;
			}
			break;
		case LTTNG_KERNEL_ABI_KPROBE:
		case LTTNG_KERNEL_ABI_KRETPROBE:
			ret = save_kernel_kprobe_event(writer, event);
			if (ret) {
				goto end;
			}
			break;
		case LTTNG_KERNEL_ABI_UPROBE:
			ret = save_kernel_userspace_probe_event(writer, event);
			if (ret) {
				goto end;
			}
			break;
		default:
			ERR("Unsupported kernel instrumentation type.");
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		/* /attributes */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* /event */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_events(struct config_writer *writer, struct ltt_kernel_channel *kchan)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *event :
	     lttng::urcu::list_iteration_adapter<ltt_kernel_event, &ltt_kernel_event::list>(
		     kchan->events_list.head)) {
		ret = save_kernel_event(writer, event);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /events */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_event(struct config_writer *writer, struct ltt_ust_event *event)
{
	int ret;
	const char *loglevel_type_string;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->attr.name[0]) {
		ret = config_writer_write_element_string(
			writer, config_element_name, event->attr.name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled, event->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->attr.instrumentation != LTTNG_UST_ABI_TRACEPOINT) {
		ERR("Unsupported UST instrumentation type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}
	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_tracepoint);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	loglevel_type_string =
		get_loglevel_type_string((lttng_ust_abi_loglevel_type) event->attr.loglevel_type);
	if (!loglevel_type_string) {
		ERR("Unsupported UST loglevel type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_loglevel_type, loglevel_type_string);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* The log level is irrelevant if no "filtering" is enabled */
	if (event->attr.loglevel_type != LTTNG_UST_ABI_LOGLEVEL_ALL) {
		ret = config_writer_write_element_signed_int(
			writer, config_element_loglevel, event->attr.loglevel);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	if (event->filter_expression) {
		ret = config_writer_write_element_string(
			writer, config_element_filter, event->filter_expression);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	if (event->exclusion && event->exclusion->count) {
		uint32_t i;

		ret = config_writer_open_element(writer, config_element_exclusions);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		for (i = 0; i < event->exclusion->count; i++) {
			ret = config_writer_write_element_string(
				writer,
				config_element_exclusion,
				LTTNG_EVENT_EXCLUSION_NAME_AT(event->exclusion, i));
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}

		/* /exclusions */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* /event */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_events(struct config_writer *writer, struct lttng_ht *events)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *event : lttng::urcu::lfht_iteration_adapter<ltt_ust_event,
							       decltype(ltt_ust_event::node),
							       &ltt_ust_event::node>(*events->ht)) {
		if (event->internal) {
			/* Internal events must not be exposed to clients */
			continue;
		}

		ret = save_ust_event(writer, event);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /events */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int init_ust_event_from_agent_event(struct ltt_ust_event *ust_event,
					   struct agent_event *agent_event)
{
	int ret;
	enum lttng_ust_abi_loglevel_type ust_loglevel_type;

	ust_event->enabled = AGENT_EVENT_IS_ENABLED(agent_event);
	ust_event->attr.instrumentation = LTTNG_UST_ABI_TRACEPOINT;
	if (lttng_strncpy(ust_event->attr.name, agent_event->name, LTTNG_SYMBOL_NAME_LEN)) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}
	switch (agent_event->loglevel_type) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
		break;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_SINGLE;
		break;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_RANGE;
		break;
	default:
		ERR("Invalid agent_event loglevel_type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ust_event->attr.loglevel_type = ust_loglevel_type;
	ust_event->attr.loglevel = agent_event->loglevel_value;
	ust_event->filter_expression = agent_event->filter_expression;
	ust_event->exclusion = agent_event->exclusion;

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_agent_events(struct config_writer *writer, struct agent *agent)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (struct agent_event *agent_event :
	     lttng::urcu::lfht_iteration_adapter<struct agent_event,
						 decltype(agent_event::node),
						 &agent_event::node>(*agent->events->ht)) {
		ltt_ust_event fake_event;

		/*
		 * Initialize a fake ust event to reuse the same serialization
		 * function since UST and agent events contain the same info
		 * (and one could wonder why they don't reuse the same
		 * structures...).
		 */
		ret = init_ust_event_from_agent_event(&fake_event, agent_event);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_ust_event(writer, &fake_event);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /events */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_context(struct config_writer *writer, struct lttng_kernel_abi_context *ctx)
{
	int ret = LTTNG_OK;

	if (!ctx) {
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_context);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (ctx->ctx == LTTNG_KERNEL_ABI_CONTEXT_PERF_CPU_COUNTER) {
		ret = config_writer_open_element(writer, config_element_context_perf);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_unsigned_int(
			writer, config_element_type, ctx->u.perf_counter.type);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_unsigned_int(
			writer, config_element_config, ctx->u.perf_counter.config);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_string(
			writer, config_element_name, ctx->u.perf_counter.name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		/* /perf */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	} else {
		const char *context_type_string = get_kernel_context_type_string(ctx->ctx);

		if (!context_type_string) {
			ERR("Unsupported kernel context type.");
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		ret = config_writer_write_element_string(
			writer, config_element_type, context_type_string);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* /context */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_contexts(struct config_writer *writer, struct ltt_kernel_channel *kchan)
{
	int ret;

	if (cds_list_empty(&kchan->ctx_list)) {
		ret = LTTNG_OK;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_contexts);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *ctx :
	     lttng::urcu::list_iteration_adapter<ltt_kernel_context, &ltt_kernel_context::list>(
		     kchan->ctx_list)) {
		ret = save_kernel_context(writer, &ctx->ctx);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /contexts */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_context_perf_thread_counter(struct config_writer *writer,
						struct ltt_ust_context *ctx)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(ctx);

	/* Perf contexts are saved as event_perf_context_type */
	ret = config_writer_open_element(writer, config_element_context_perf);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_type, ctx->ctx.u.perf_counter.type);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_config, ctx->ctx.u.perf_counter.config);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_name, ctx->ctx.u.perf_counter.name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /perf */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_context_app_ctx(struct config_writer *writer, struct ltt_ust_context *ctx)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(ctx);

	/* Application contexts are saved as application_context_type */
	ret = config_writer_open_element(writer, config_element_context_app);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_context_app_provider_name, ctx->ctx.u.app_ctx.provider_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_context_app_ctx_name, ctx->ctx.u.app_ctx.ctx_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /app */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_context_generic(struct config_writer *writer, struct ltt_ust_context *ctx)
{
	int ret;
	const char *context_type_string;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(ctx);

	/* Save context as event_context_type_type */
	context_type_string = get_ust_context_type_string(ctx->ctx.ctx);
	if (!context_type_string) {
		ERR("Unsupported UST context type.");
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_type, context_type_string);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_context(struct config_writer *writer, struct cds_list_head *ctx_list)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(ctx_list);

	ret = config_writer_open_element(writer, config_element_contexts);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *ctx :
	     lttng::urcu::list_iteration_adapter<ltt_ust_context, &ltt_ust_context::list>(
		     *ctx_list)) {
		ret = config_writer_open_element(writer, config_element_context);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		switch (ctx->ctx.ctx) {
		case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
			ret = save_ust_context_perf_thread_counter(writer, ctx);
			break;
		case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
			ret = save_ust_context_app_ctx(writer, ctx);
			break;
		default:
			/* Save generic context. */
			ret = save_ust_context_generic(writer, ctx);
		}
		if (ret != LTTNG_OK) {
			goto end;
		}

		/* /context */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* /contexts */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_channel(struct config_writer *writer, struct ltt_kernel_channel *kchan)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(kchan);

	ret = config_writer_open_element(writer, config_element_channel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_name, kchan->channel->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(
		writer, config_element_enabled, kchan->channel->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_kernel_channel_attributes(writer, &kchan->channel->attr);
	if (ret != LTTNG_OK) {
		goto end;
	}

	ret = save_kernel_events(writer, kchan);
	if (ret != LTTNG_OK) {
		goto end;
	}

	ret = save_kernel_contexts(writer, kchan);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* /channel */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_channel(struct config_writer *writer,
			    struct ltt_ust_channel *ust_chan,
			    struct ltt_ust_session *session)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(ust_chan);
	LTTNG_ASSERT(session);

	ret = config_writer_open_element(writer, config_element_channel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_name, ust_chan->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled, ust_chan->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_ust_channel_attributes(writer, &ust_chan->attr);
	if (ret != LTTNG_OK) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_tracefile_size, ust_chan->tracefile_size);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_tracefile_count, ust_chan->tracefile_count);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(
		writer, config_element_live_timer_interval, session->live_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (ust_chan->domain == LTTNG_DOMAIN_UST) {
		ret = save_ust_events(writer, ust_chan->events);
		if (ret != LTTNG_OK) {
			goto end;
		}
	} else {
		struct agent *agent = nullptr;

		agent = trace_ust_find_agent(session, ust_chan->domain);
		if (!agent) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			ERR("Could not find agent associated to UST subdomain");
			goto end;
		}

		/*
		 * Channels associated with a UST sub-domain (such as JUL, Log4j
		 * or Python) don't have any non-internal events. We retrieve
		 * the "agent" events associated with this channel and serialize
		 * them.
		 */
		ret = save_agent_events(writer, agent);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	ret = save_ust_context(writer, &ust_chan->ctx_list);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* /channel */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_kernel_session(struct config_writer *writer, const ltt_session::locked_ref& session)
{
	int ret;

	LTTNG_ASSERT(writer);

	ret = config_writer_write_element_string(
		writer, config_element_type, config_domain_type_kernel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_buffer_type, config_buffer_type_global);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_channels);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *kchan :
	     lttng::urcu::list_iteration_adapter<ltt_kernel_channel, &ltt_kernel_channel::list>(
		     session->kernel_session->channel_list.head)) {
		ret = save_kernel_channel(writer, kchan);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /channels */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

static const char *get_config_domain_str(enum lttng_domain_type domain)
{
	const char *str_dom;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		str_dom = config_domain_type_kernel;
		break;
	case LTTNG_DOMAIN_UST:
		str_dom = config_domain_type_ust;
		break;
	case LTTNG_DOMAIN_JUL:
		str_dom = config_domain_type_jul;
		break;
	case LTTNG_DOMAIN_LOG4J:
		str_dom = config_domain_type_log4j;
		break;
	case LTTNG_DOMAIN_LOG4J2:
		str_dom = config_domain_type_log4j2;
		break;
	case LTTNG_DOMAIN_PYTHON:
		str_dom = config_domain_type_python;
		break;
	default:
		abort();
	}

	return str_dom;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_process_attr_tracker(struct config_writer *writer,
				     const ltt_session::locked_ref& session,
				     int domain,
				     enum lttng_process_attr process_attr)
{
	int ret = LTTNG_OK;
	const char *element_id_tracker, *element_target_id, *element_id;
	const struct process_attr_tracker *tracker;
	enum lttng_tracking_policy tracking_policy;
	struct lttng_process_attr_values *values = nullptr;

	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		element_id_tracker = config_element_process_attr_tracker_pid;
		element_target_id = config_element_process_attr_pid_value;
		element_id = config_element_process_attr_id;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		element_id_tracker = config_element_process_attr_tracker_vpid;
		element_target_id = config_element_process_attr_vpid_value;
		element_id = config_element_process_attr_id;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
		element_id_tracker = config_element_process_attr_tracker_uid;
		element_target_id = config_element_process_attr_uid_value;
		element_id = config_element_process_attr_id;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		element_id_tracker = config_element_process_attr_tracker_vuid;
		element_target_id = config_element_process_attr_vuid_value;
		element_id = config_element_process_attr_id;
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		element_id_tracker = config_element_process_attr_tracker_gid;
		element_target_id = config_element_process_attr_gid_value;
		element_id = config_element_process_attr_id;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		element_id_tracker = config_element_process_attr_tracker_vgid;
		element_target_id = config_element_process_attr_vgid_value;
		element_id = config_element_process_attr_id;
		break;
	default:
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		tracker = kernel_get_process_attr_tracker(session->kernel_session, process_attr);
		LTTNG_ASSERT(tracker);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		tracker = trace_ust_get_process_attr_tracker(session->ust_session, process_attr);
		LTTNG_ASSERT(tracker);
		break;
	}
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
	case LTTNG_DOMAIN_PYTHON:
	default:
		ret = LTTNG_ERR_UNSUPPORTED_DOMAIN;
		goto end;
	}

	tracking_policy = process_attr_tracker_get_tracking_policy(tracker);
	if (tracking_policy == LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
		/* Tracking all, nothing to output. */
		ret = LTTNG_OK;
		goto end;
	}

	ret = config_writer_open_element(writer, element_id_tracker);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_process_attr_values);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (tracking_policy == LTTNG_TRACKING_POLICY_INCLUDE_SET) {
		unsigned int i, count;
		const process_attr_tracker_status status =
			process_attr_tracker_get_inclusion_set(tracker, &values);

		if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}

		count = _lttng_process_attr_values_get_count(values);

		for (i = 0; i < count; i++) {
			unsigned int integral_value = UINT_MAX;
			const char *name = nullptr;
			const struct process_attr_value *value =
				lttng_process_attr_tracker_values_get_at_index(values, i);

			LTTNG_ASSERT(value);
			ret = config_writer_open_element(writer, element_target_id);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			switch (value->type) {
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
				integral_value = (unsigned int) value->value.pid;
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
				integral_value = (unsigned int) value->value.uid;
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
				integral_value = (unsigned int) value->value.gid;
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
				name = value->value.user_name;
				LTTNG_ASSERT(name);
				break;
			case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
				name = value->value.group_name;
				LTTNG_ASSERT(name);
				break;
			default:
				abort();
			}

			if (name) {
				ret = config_writer_write_element_string(
					writer, config_element_name, name);
			} else {
				ret = config_writer_write_element_unsigned_int(
					writer, element_id, integral_value);
			}

			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			/* /$element_target_id */
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
	}

	/* /values */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /$element_id_tracker */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	lttng_process_attr_values_destroy(values);
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_process_attr_trackers(struct config_writer *writer,
				      const ltt_session::locked_ref& session,
				      int domain)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_PROCESS_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_USER_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_GROUP_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		break;
	case LTTNG_DOMAIN_UST:
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		ret = save_process_attr_tracker(
			writer, session, domain, LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		if (ret != LTTNG_OK) {
			goto end;
		}
		break;
	default:
		ret = LTTNG_ERR_INVALID;
		goto end;
	}
	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_ust_domain(struct config_writer *writer,
			   const ltt_session::locked_ref& session,
			   enum lttng_domain_type domain)
{
	int ret;
	const char *buffer_type_string;
	const char *config_domain_name;

	LTTNG_ASSERT(writer);

	ret = config_writer_open_element(writer, config_element_domain);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	config_domain_name = get_config_domain_str(domain);
	if (!config_domain_name) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_type, config_domain_name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	buffer_type_string = get_buffer_type_string(session->ust_session->buffer_type);
	if (!buffer_type_string) {
		ERR("Unsupported buffer type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_buffer_type, buffer_type_string);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_channels);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *ust_chan : lttng::urcu::lfht_iteration_adapter<ltt_ust_channel,
								  decltype(ltt_ust_channel::node),
								  &ltt_ust_channel::node>(
		     *session->ust_session->domain_global.channels->ht)) {
		if (domain == ust_chan->domain) {
			ret = save_ust_channel(writer, ust_chan, session->ust_session);
			if (ret != LTTNG_OK) {
				goto end;
			}
		}
	}

	/* /channels */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (domain == LTTNG_DOMAIN_UST) {
		ret = config_writer_open_element(writer, config_element_process_attr_trackers);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = save_process_attr_trackers(writer, session, LTTNG_DOMAIN_UST);
		if (ret != LTTNG_OK) {
			goto end;
		}

		/* /trackers */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* /domain */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_domains(struct config_writer *writer, const ltt_session::locked_ref& session)
{
	int ret = LTTNG_OK;

	LTTNG_ASSERT(writer);

	if (!session->kernel_session && !session->ust_session) {
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_domains);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->kernel_session) {
		ret = config_writer_open_element(writer, config_element_domain);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = save_kernel_session(writer, session);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = config_writer_open_element(writer, config_element_process_attr_trackers);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = save_process_attr_trackers(writer, session, LTTNG_DOMAIN_KERNEL);
		if (ret != LTTNG_OK) {
			goto end;
		}

		/* /trackers */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		/* /domain */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	if (session->ust_session) {
		ret = save_ust_domain(writer, session, LTTNG_DOMAIN_UST);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_ust_domain(writer, session, LTTNG_DOMAIN_JUL);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_ust_domain(writer, session, LTTNG_DOMAIN_LOG4J);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_ust_domain(writer, session, LTTNG_DOMAIN_LOG4J2);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_ust_domain(writer, session, LTTNG_DOMAIN_PYTHON);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /domains */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_consumer_output(struct config_writer *writer, struct consumer_output *output)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(output);

	ret = config_writer_open_element(writer, config_element_consumer_output);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled, output->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_destination);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	switch (output->type) {
	case CONSUMER_DST_LOCAL:
		ret = config_writer_write_element_string(
			writer, config_element_path, output->dst.session_root_path);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	case CONSUMER_DST_NET:
	{
		char *uri;

		uri = calloc<char>(PATH_MAX);
		if (!uri) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = config_writer_open_element(writer, config_element_net_output);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_net_output;
		}

		if (output->dst.net.control_isset && output->dst.net.data_isset) {
			ret = uri_to_str_url(&output->dst.net.control, uri, PATH_MAX);
			if (ret < 0) {
				ret = LTTNG_ERR_INVALID;
				goto end_net_output;
			}

			ret = config_writer_write_element_string(
				writer, config_element_control_uri, uri);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end_net_output;
			}

			ret = uri_to_str_url(&output->dst.net.data, uri, PATH_MAX);
			if (ret < 0) {
				ret = LTTNG_ERR_INVALID;
				goto end_net_output;
			}

			ret = config_writer_write_element_string(
				writer, config_element_data_uri, uri);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end_net_output;
			}
			ret = LTTNG_OK;
		end_net_output:
			free(uri);
			if (ret != LTTNG_OK) {
				goto end;
			}
		} else {
			ret = !output->dst.net.control_isset ? LTTNG_ERR_URL_CTRL_MISS :
							       LTTNG_ERR_URL_DATA_MISS;
			free(uri);
			goto end;
		}

		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	}
	default:
		ERR("Unsupported consumer output type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* /destination */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /consumer_output */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_snapshot_outputs(struct config_writer *writer, struct snapshot *snapshot)
{
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(snapshot);

	int ret = config_writer_open_element(writer, config_element_snapshot_outputs);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *output : lttng::urcu::lfht_iteration_adapter<snapshot_output,
								decltype(snapshot_output::node),
								&snapshot_output::node>(
		     *snapshot->output_ht->ht)) {
		ret = config_writer_open_element(writer, config_element_output);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = config_writer_write_element_string(writer, config_element_name, output->name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = config_writer_write_element_unsigned_int(
			writer, config_element_max_size, output->max_size);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = save_consumer_output(writer, output->consumer);
		if (ret != LTTNG_OK) {
			goto end_unlock;
		}

		/* /output */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}
	}

	/* /snapshot_outputs */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
end_unlock:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_session_output(struct config_writer *writer, const ltt_session::locked_ref& session)
{
	int ret;

	LTTNG_ASSERT(writer);

	if ((session->snapshot_mode && session->snapshot.nb_output == 0) ||
	    (!session->snapshot_mode && !session->consumer)) {
		/* Session is in no output mode */
		ret = LTTNG_OK;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_output);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->snapshot_mode) {
		ret = save_snapshot_outputs(writer, &session->snapshot);
		if (ret != LTTNG_OK) {
			goto end;
		}
	} else {
		if (session->consumer) {
			ret = save_consumer_output(writer, session->consumer);
			if (ret != LTTNG_OK) {
				goto end;
			}
		}
	}

	/* /output */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
	ret = LTTNG_OK;
end:
	return ret;
}

static int save_session_rotation_schedule(struct config_writer *writer,
					  enum lttng_rotation_schedule_type type,
					  uint64_t value)
{
	int ret = 0;
	const char *element_name;
	const char *value_name;

	switch (type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		element_name = config_element_rotation_schedule_periodic;
		value_name = config_element_rotation_schedule_periodic_time_us;
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		element_name = config_element_rotation_schedule_size_threshold;
		value_name = config_element_rotation_schedule_size_threshold_bytes;
		break;
	default:
		ret = -1;
		goto end;
	}

	ret = config_writer_open_element(writer, element_name);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer, value_name, value);
	if (ret) {
		goto end;
	}

	/* Close schedule descriptor element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static int save_session_rotation_schedules(struct config_writer *writer,
					   const ltt_session::locked_ref& session)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_rotation_schedules);
	if (ret) {
		goto end;
	}
	if (session->rotate_timer_period) {
		ret = save_session_rotation_schedule(writer,
						     LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC,
						     session->rotate_timer_period);
		if (ret) {
			goto close_schedules;
		}
	}
	if (session->rotate_size) {
		ret = save_session_rotation_schedule(
			writer, LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD, session->rotate_size);
		if (ret) {
			goto close_schedules;
		}
	}

close_schedules:
	/* Close rotation schedules element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

/*
 * Save the given session.
 *
 * Return LTTNG_OK on success else a LTTNG_ERR* code.
 */
static int save_session(const ltt_session::locked_ref& session,
			struct lttng_save_session_attr *attr,
			lttng_sock_cred *creds)
{
	int ret, fd = -1;
	char config_file_path[LTTNG_PATH_MAX];
	size_t len;
	struct config_writer *writer = nullptr;
	size_t session_name_len;
	const char *provided_path;
	int file_open_flags = O_CREAT | O_WRONLY | O_TRUNC;

	LTTNG_ASSERT(attr);
	LTTNG_ASSERT(creds);

	session_name_len = strlen(session->name);
	memset(config_file_path, 0, sizeof(config_file_path));

	if (!session_access_ok(session, LTTNG_SOCK_GET_UID_CRED(creds)) || session->destroyed) {
		ret = LTTNG_ERR_EPERM;
		goto end;
	}

	provided_path = lttng_save_session_attr_get_output_url(attr);
	if (provided_path) {
		DBG3("Save session in provided path %s", provided_path);
		len = strlen(provided_path);
		if (len >= sizeof(config_file_path)) {
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}
		strncpy(config_file_path, provided_path, sizeof(config_file_path));
	} else {
		ssize_t ret_len;
		char *home_dir = utils_get_user_home_dir(LTTNG_SOCK_GET_UID_CRED(creds));
		if (!home_dir) {
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}

		ret_len = snprintf(config_file_path,
				   sizeof(config_file_path),
				   DEFAULT_SESSION_HOME_CONFIGPATH,
				   home_dir);
		free(home_dir);
		if (ret_len < 0) {
			PERROR("snprintf save session");
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}
		len = ret_len;
	}

	/*
	 * Check the path fits in the config file path dst including the '/'
	 * followed by trailing .lttng extension and the NULL terminated string.
	 */
	if ((len + session_name_len + 2 + sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION)) >
	    sizeof(config_file_path)) {
		ret = LTTNG_ERR_SET_URL;
		goto end;
	}

	ret = run_as_mkdir_recursive(config_file_path,
				     S_IRWXU | S_IRWXG,
				     LTTNG_SOCK_GET_UID_CRED(creds),
				     LTTNG_SOCK_GET_GID_CRED(creds));
	if (ret) {
		ret = LTTNG_ERR_SET_URL;
		goto end;
	}

	/*
	 * At this point, we know that everything fits in the buffer. Validation
	 * was done just above.
	 */
	config_file_path[len++] = '/';
	strncpy(config_file_path + len, session->name, sizeof(config_file_path) - len);
	len += session_name_len;
	strcpy(config_file_path + len, DEFAULT_SESSION_CONFIG_FILE_EXTENSION);
	len += sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION);
	config_file_path[len] = '\0';

	if (!attr->overwrite) {
		file_open_flags |= O_EXCL;
	}

	fd = run_as_open(config_file_path,
			 file_open_flags,
			 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
			 LTTNG_SOCK_GET_UID_CRED(creds),
			 LTTNG_SOCK_GET_GID_CRED(creds));
	if (fd < 0) {
		PERROR("Could not create configuration file");
		switch (errno) {
		case EEXIST:
			ret = LTTNG_ERR_SAVE_FILE_EXIST;
			break;
		case EACCES:
			ret = LTTNG_ERR_EPERM;
			break;
		default:
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			break;
		}
		goto end;
	}

	writer = config_writer_create(fd, 1);
	if (!writer) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_sessions);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_session);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_name, session->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->shm_path[0] != '\0') {
		ret = config_writer_write_element_string(
			writer, config_element_shared_memory_path, session->shm_path);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = save_domains(writer, session);
	if (ret != LTTNG_OK) {
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_started, session->active);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->snapshot_mode || session->live_timer || session->rotate_timer_period ||
	    session->rotate_size) {
		ret = config_writer_open_element(writer, config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		if (session->snapshot_mode) {
			ret = config_writer_write_element_bool(
				writer, config_element_snapshot_mode, 1);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		} else if (session->live_timer) {
			ret = config_writer_write_element_unsigned_int(
				writer, config_element_live_timer_interval, session->live_timer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
		if (session->rotate_timer_period || session->rotate_size) {
			ret = save_session_rotation_schedules(writer, session);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}

		/* /attributes */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = save_session_output(writer, session);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* /session */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /sessions */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	if (writer && config_writer_destroy(writer)) {
		/* Preserve the original error code */
		ret = ret != LTTNG_OK ? ret : LTTNG_ERR_SAVE_IO_FAIL;
	}
	if (ret != LTTNG_OK) {
		/* Delete file in case of error */
		if ((fd >= 0) && unlink(config_file_path)) {
			PERROR("Unlinking XML session configuration.");
		}
	}

	if (fd >= 0) {
		int closeret;

		closeret = close(fd);
		if (closeret) {
			PERROR("Closing XML session configuration");
		}
	}

	return ret;
}

int cmd_save_sessions(struct lttng_save_session_attr *attr, lttng_sock_cred *creds)
{
	const auto list_lock = lttng::sessiond::lock_session_list();
	const auto session_name = lttng_save_session_attr_get_session_name(attr);

	if (session_name) {
		/*
		 * Mind the order of the declaration of list_lock vs session:
		 * the session list lock must always be released _after_ the release of
		 * a session's reference (the destruction of a ref/locked_ref) to ensure
		 * since the reference's release may unpublish the session from the list of
		 * sessions.
		 */
		try {
			const auto session = ltt_session::find_locked_session(session_name);
			const auto save_ret = save_session(session, attr, creds);
			if (save_ret != LTTNG_OK) {
				return save_ret;
			}
		} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
			WARN_FMT("Failed to save session: {} {}", ex.what(), ex.source_location);
			return LTTNG_ERR_SESS_NOT_FOUND;
		}
	} else {
		struct ltt_session_list *list = session_get_list();

		for (auto raw_session_ptr :
		     lttng::urcu::list_iteration_adapter<ltt_session, &ltt_session::list>(
			     list->head)) {
			auto session = [raw_session_ptr]() {
				session_get(raw_session_ptr);
				raw_session_ptr->lock();
				return ltt_session::make_locked_ref(*raw_session_ptr);
			}();
			const auto save_ret = save_session(session, attr, creds);

			/* Don't abort if we don't have the required permissions. */
			if (save_ret != LTTNG_OK && save_ret != LTTNG_ERR_EPERM) {
				return save_ret;
			}
		}
	}

	return LTTNG_OK;
}
