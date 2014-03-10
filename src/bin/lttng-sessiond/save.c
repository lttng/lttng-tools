/*
 * Copyright (C) 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <urcu/uatomic.h>
#include <unistd.h>

#include <common/defaults.h>
#include <common/error.h>
#include <common/config/config.h>
#include <common/config/config-session-internal.h>
#include <common/utils.h>
#include <common/runas.h>
#include <lttng/save-internal.h>

#include "save.h"
#include "session.h"
#include "trace-ust.h"

static
int save_kernel_channel_attributes(struct config_writer *writer,
	struct lttng_channel_attr *attr)
{
	int ret;

	ret = config_writer_write_element_string(writer,
		config_element_overwrite_mode,
		attr->overwrite ? config_overwrite_mode_overwrite :
			config_overwrite_mode_discard);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_subbuf_size, attr->subbuf_size);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_num_subbuf,
		attr->num_subbuf);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_switch_timer_interval,
		attr->switch_timer_interval);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_read_timer_interval,
		attr->read_timer_interval);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_string(writer,
		config_element_output_type,
		attr->output == LTTNG_EVENT_SPLICE ?
		config_output_type_splice : config_output_type_mmap);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_tracefile_size, attr->tracefile_size);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_tracefile_count,
		attr->tracefile_count);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_live_timer_interval,
		attr->live_timer_interval);
	if (ret) {
		goto end;
	}
end:
	return ret ? LTTNG_ERR_SAVE_IO_FAIL : 0;
}

static
int save_ust_channel_attributes(struct config_writer *writer,
	struct lttng_ust_channel_attr *attr)
{
	int ret;

	ret = config_writer_write_element_string(writer,
		config_element_overwrite_mode,
		attr->overwrite ? config_overwrite_mode_overwrite :
			config_overwrite_mode_discard);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_subbuf_size, attr->subbuf_size);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_num_subbuf,
		attr->num_subbuf);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_switch_timer_interval,
		attr->switch_timer_interval);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_read_timer_interval,
		attr->read_timer_interval);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_string(writer,
		config_element_output_type,
		attr->output == LTTNG_UST_MMAP ?
		config_output_type_mmap : config_output_type_splice);
	if (ret) {
		goto end;
	}
end:
	return ret ? LTTNG_ERR_SAVE_IO_FAIL : 0;
}

static
const char *get_kernel_instrumentation_string(
	enum lttng_kernel_instrumentation instrumentation)
{
	const char *instrumentation_string;

	switch (instrumentation) {
	case LTTNG_KERNEL_ALL:
		instrumentation_string = config_event_type_all;
		break;
	case LTTNG_KERNEL_TRACEPOINT:
		instrumentation_string = config_event_type_tracepoint;
		break;
	case LTTNG_KERNEL_KPROBE:
		instrumentation_string = config_event_type_kprobe;
		break;
	case LTTNG_KERNEL_FUNCTION:
		instrumentation_string = config_event_type_function;
		break;
	case LTTNG_KERNEL_KRETPROBE:
		instrumentation_string = config_event_type_kretprobe;
		break;
	case LTTNG_KERNEL_NOOP:
		instrumentation_string = config_event_type_noop;
		break;
	case LTTNG_KERNEL_SYSCALL:
		instrumentation_string = config_event_type_syscall;
		break;
	default:
		instrumentation_string = NULL;
	}

	return instrumentation_string;
}

static
const char *get_kernel_context_type_string(
	enum lttng_kernel_context_type context_type)
{
	const char *context_type_string;

	switch (context_type) {
	case LTTNG_KERNEL_CONTEXT_PID:
		context_type_string = config_event_context_pid;
		break;
	case LTTNG_KERNEL_CONTEXT_PROCNAME:
		context_type_string = config_event_context_procname;
		break;
	case LTTNG_KERNEL_CONTEXT_PRIO:
		context_type_string = config_event_context_prio;
		break;
	case LTTNG_KERNEL_CONTEXT_NICE:
		context_type_string = config_event_context_nice;
		break;
	case LTTNG_KERNEL_CONTEXT_VPID:
		context_type_string = config_event_context_vpid;
		break;
	case LTTNG_KERNEL_CONTEXT_TID:
		context_type_string = config_event_context_tid;
		break;
	case LTTNG_KERNEL_CONTEXT_VTID:
		context_type_string = config_event_context_vtid;
		break;
	case LTTNG_KERNEL_CONTEXT_PPID:
		context_type_string = config_event_context_ppid;
		break;
	case LTTNG_KERNEL_CONTEXT_VPPID:
		context_type_string = config_event_context_vppid;
		break;
	case LTTNG_KERNEL_CONTEXT_HOSTNAME:
		context_type_string = config_event_context_hostname;
		break;
	default:
		context_type_string = NULL;
	}

	return context_type_string;
}

static
const char *get_ust_context_type_string(
	enum lttng_ust_context_type context_type)
{
	const char *context_type_string;

	switch (context_type) {
	case LTTNG_UST_CONTEXT_PROCNAME:
		context_type_string = config_event_context_procname;
		break;
	case LTTNG_UST_CONTEXT_VPID:
		context_type_string = config_event_context_vpid;
		break;
	case LTTNG_UST_CONTEXT_VTID:
		context_type_string = config_event_context_vtid;
		break;
	case LTTNG_UST_CONTEXT_IP:
		context_type_string = config_event_context_ip;
		break;
	case LTTNG_UST_CONTEXT_PTHREAD_ID:
		context_type_string = config_event_context_pthread_id;
		break;
	default:
		context_type_string = NULL;
	}

	return context_type_string;
}

static
const char *get_buffer_type_string(
	enum lttng_buffer_type buffer_type)
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
		buffer_type_string = NULL;
	}

	return buffer_type_string;
}

static
const char *get_loglevel_type_string(
	enum lttng_ust_loglevel_type loglevel_type)
{
	const char *loglevel_type_string;

	switch (loglevel_type) {
	case LTTNG_UST_LOGLEVEL_ALL:
		loglevel_type_string = config_loglevel_type_all;
		break;
	case LTTNG_UST_LOGLEVEL_RANGE:
		loglevel_type_string = config_loglevel_type_range;
		break;
	case LTTNG_UST_LOGLEVEL_SINGLE:
		loglevel_type_string = config_loglevel_type_single;
		break;
	default:
		loglevel_type_string = NULL;
	}

	return loglevel_type_string;
}

static
int save_kernel_event(struct config_writer *writer,
	struct ltt_kernel_event *event)
{
	int ret;
	const char *instrumentation_type;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->event->name[0]) {
		ret = config_writer_write_element_string(writer,
			config_element_name, event->event->name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled,
		event->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	instrumentation_type = get_kernel_instrumentation_string(
		event->event->instrumentation);
	if (!instrumentation_type) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_type,
		instrumentation_type);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->event->instrumentation == LTTNG_KERNEL_FUNCTION ||
		event->event->instrumentation == LTTNG_KERNEL_KPROBE ||
		event->event->instrumentation == LTTNG_KERNEL_KRETPROBE) {

		ret = config_writer_open_element(writer,
			config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		switch (event->event->instrumentation) {
		case LTTNG_KERNEL_FUNCTION:
			ret = config_writer_open_element(writer,
				config_element_function_attributes);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			ret = config_writer_write_element_string(writer,
				config_element_name,
				event->event->u.ftrace.symbol_name);
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
			break;
		case LTTNG_KERNEL_KPROBE:
		case LTTNG_KERNEL_KRETPROBE:
		{
			const char *symbol_name;
			uint64_t addr;
			uint64_t offset;

			if (event->event->instrumentation ==
				LTTNG_KERNEL_KPROBE) {
				/*
				 * Comments in lttng-kernel.h mention that
				 * either addr or symbol_name are set, not both.
				 */
				addr = event->event->u.kprobe.addr;
				offset = event->event->u.kprobe.offset;
				symbol_name = addr ? NULL :
					event->event->u.kprobe.symbol_name;
			} else {
				symbol_name =
					event->event->u.kretprobe.symbol_name;
				addr = event->event->u.kretprobe.addr;
				offset = event->event->u.kretprobe.offset;
			}

			ret = config_writer_open_element(writer,
				config_element_probe_attributes);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			if (symbol_name) {
				ret = config_writer_write_element_string(writer,
					config_element_symbol_name,
					symbol_name);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			if (addr) {
				ret = config_writer_write_element_unsigned_int(
					writer, config_element_address, addr);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			if (offset) {
				ret = config_writer_write_element_unsigned_int(
					writer, config_element_offset, offset);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
			break;
		}
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
end:
	return ret;
}

static
int save_kernel_events(struct config_writer *writer,
	struct ltt_kernel_event_list *event_list)
{
	int ret;
	struct ltt_kernel_event *event;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	cds_list_for_each_entry(event, &event_list->head, list) {
		ret = save_kernel_event(writer, event);
		if (ret) {
			goto end;
		}
	}

	/* /events */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_ust_event(struct config_writer *writer,
	struct ltt_ust_event *event)
{
	int ret;
	const char *loglevel_type_string;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->attr.name[0]) {
		ret = config_writer_write_element_string(writer,
			config_element_name, event->attr.name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled,
		event->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->attr.instrumentation != LTTNG_UST_TRACEPOINT) {
		ERR("Unsupported UST instrumentation type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}
	ret = config_writer_write_element_string(writer, config_element_type,
		config_event_type_tracepoint);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	loglevel_type_string = get_loglevel_type_string(
		event->attr.loglevel_type);
	if (!loglevel_type_string) {
		ERR("Unsupported UST loglevel type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer,
		config_element_loglevel_type, loglevel_type_string);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_signed_int(writer,
		config_element_loglevel, event->attr.loglevel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (event->filter_expression) {
		ret = config_writer_write_element_string(writer,
			config_element_filter, event->filter_expression);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	if (event->exclusion && event->exclusion->count) {
		uint32_t i;

		ret = config_writer_open_element(writer,
			config_element_exclusions);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		for (i = 0; i < event->exclusion->count; i++) {
			ret = config_writer_write_element_string(writer,
				config_element_exclusion,
				&event->exclusion->names[0][i]);
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
end:
	return ret;
}

static
int save_ust_events(struct config_writer *writer,
	struct lttng_ht *events)
{
	int ret;
	struct ltt_ust_event *event;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(events->ht, &iter.iter, node, node) {
		event = caa_container_of(node, struct ltt_ust_event, node);

		ret = save_ust_event(writer, event);
		if (ret) {
			rcu_read_unlock();
			goto end;
		}
	}
	rcu_read_unlock();

	/* /events */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_kernel_context(struct config_writer *writer,
	struct lttng_kernel_context *ctx)
{
	int ret = 0;

	if (!ctx) {
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_contexts);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_context);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (ctx->ctx == LTTNG_KERNEL_CONTEXT_PERF_COUNTER) {
		ret = config_writer_open_element(writer, config_element_perf);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_unsigned_int(writer,
			config_element_type, ctx->u.perf_counter.type);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_unsigned_int(writer,
			config_element_config, ctx->u.perf_counter.config);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_string(writer,
			config_element_name, ctx->u.perf_counter.name);
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
		const char *context_type_string =
			get_kernel_context_type_string(ctx->ctx);

		if (!context_type_string) {
			ERR("Unsupported kernel context type.");
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		ret = config_writer_write_element_string(writer,
			config_element_type, context_type_string);
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

	/* /contexts */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_ust_context(struct config_writer *writer,
	struct cds_list_head *ctx_list)
{
	int ret;
	struct ltt_ust_context *ctx;

	assert(writer);
	assert(ctx_list);

	ret = config_writer_open_element(writer, config_element_contexts);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	cds_list_for_each_entry(ctx, ctx_list, list) {
		const char *context_type_string;

		context_type_string = get_ust_context_type_string(ctx->ctx.ctx);
		if (!context_type_string) {
			ERR("Unsupported UST context type.")
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		ret = config_writer_open_element(writer,
			config_element_context);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_string(writer,
			config_element_type, context_type_string);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
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
end:
	return ret;
}

static
int save_kernel_channel(struct config_writer *writer,
	struct ltt_kernel_channel *kchan)
{
	int ret;

	assert(writer);
	assert(kchan);

	ret = config_writer_open_element(writer, config_element_channel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_name,
		kchan->channel->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled,
		kchan->channel->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_kernel_channel_attributes(writer, &kchan->channel->attr);
	if (ret) {
		goto end;
	}

	ret = save_kernel_events(writer, &kchan->events_list);
	if (ret) {
		goto end;
	}

	ret = save_kernel_context(writer, kchan->ctx);
	if (ret) {
		goto end;
	}

	/* /channel */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_ust_channel(struct config_writer *writer,
	struct ltt_ust_channel *ust_chan,
	struct ltt_ust_session *session)
{
	int ret;

	assert(writer);
	assert(ust_chan);
	assert(session);

	ret = config_writer_open_element(writer, config_element_channel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_name,
		ust_chan->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled,
		ust_chan->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_ust_channel_attributes(writer, &ust_chan->attr);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_tracefile_size, ust_chan->tracefile_size);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_tracefile_count, ust_chan->tracefile_count);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer,
		config_element_live_timer_interval,
		session->live_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_ust_events(writer, ust_chan->events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_ust_context(writer, &ust_chan->ctx_list);
	if (ret) {
		goto end;
	}

	/* /channel */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_kernel_session(struct config_writer *writer,
	struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	assert(writer);
	assert(session);

	ret = config_writer_write_element_string(writer, config_element_type,
		config_domain_type_kernel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer,
		config_element_buffer_type, config_buffer_type_global);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer,
		config_element_channels);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	cds_list_for_each_entry(kchan, &session->kernel_session->channel_list.head,
			list) {
		ret = save_kernel_channel(writer, kchan);
		if (ret) {
			goto end;
		}
	}

	/* /channels */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_ust_session(struct config_writer *writer,
	struct ltt_session *session, int save_jul)
{
	int ret;
	struct ltt_ust_channel *ust_chan;
	const char *buffer_type_string;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(writer);
	assert(session);

	ret = config_writer_write_element_string(writer, config_element_type,
			save_jul ? config_domain_type_jul : config_domain_type_ust);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	buffer_type_string = get_buffer_type_string(
			session->ust_session->buffer_type);
	if (!buffer_type_string) {
		ERR("Unsupported buffer type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer,
			config_element_buffer_type, buffer_type_string);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_channels);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(session->ust_session->domain_global.channels->ht,
			&iter.iter, node, node) {
		int jul_channel;

		ust_chan = caa_container_of(node, struct ltt_ust_channel, node);
		jul_channel = !strcmp(DEFAULT_JUL_CHANNEL_NAME, ust_chan->name);
		if (!(save_jul ^ jul_channel)) {
			ret = save_ust_channel(writer, ust_chan, session->ust_session);
			if (ret) {
				rcu_read_unlock();
				goto end;
			}
		}
	}
	rcu_read_unlock();

	/* /channels */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_domains(struct config_writer *writer, struct ltt_session *session)
{
	int ret = 0;

	assert(writer);
	assert(session);

	if (!session->kernel_session && !session->ust_session) {
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_domains);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}


	if (session->kernel_session) {
		ret = config_writer_open_element(writer,
			config_element_domain);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = save_kernel_session(writer, session);
		if (ret) {
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
		ret = config_writer_open_element(writer,
			config_element_domain);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = save_ust_session(writer, session, 0);
		if (ret) {
			goto end;
		}

		/* /domain */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	if (session->ust_session &&
		session->ust_session->domain_jul.being_used) {
		ret = config_writer_open_element(writer,
			config_element_domain);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = save_ust_session(writer, session, 1);
		if (ret) {
			goto end;
		}

		/* /domain */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* /domains */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
end:
	return ret;
}

static
int save_consumer_output(struct config_writer *writer,
	struct consumer_output *output)
{
	int ret;

	assert(writer);
	assert(output);

	ret = config_writer_open_element(writer, config_element_consumer_output);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled,
			output->enabled);
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
		ret = config_writer_write_element_string(writer,
			config_element_path, output->dst.trace_path);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	case CONSUMER_DST_NET:
	{
		char *uri;

		uri = zmalloc(PATH_MAX);
		if (!uri) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = config_writer_open_element(writer, config_element_net_output);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_net_output;
		}

		if (output->dst.net.control_isset &&
			output->dst.net.data_isset) {
			ret = uri_to_str_url(&output->dst.net.control, uri, PATH_MAX);
			if (ret < 0) {
				ret = LTTNG_ERR_INVALID;
				goto end_net_output;
			}

			ret = config_writer_write_element_string(writer,
					config_element_control_uri, uri);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end_net_output;
			}

			ret = uri_to_str_url(&output->dst.net.data, uri, PATH_MAX);
			if (ret < 0) {
				ret = LTTNG_ERR_INVALID;
				goto end_net_output;
			}

			ret = config_writer_write_element_string(writer,
					config_element_data_uri, uri);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end_net_output;
			}

end_net_output:
			free(uri);
			if (ret) {
				goto end;
			}
		} else {
			ret = !output->dst.net.control_isset ?
				LTTNG_ERR_URL_CTRL_MISS :
				LTTNG_ERR_URL_DATA_MISS;
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
end:
	return ret;
}

static
int save_snapshot_outputs(struct config_writer *writer,
	struct snapshot *snapshot)
{
	int ret;
	struct lttng_ht_iter iter;
	struct snapshot_output *output;

	assert(writer);
	assert(snapshot);

	ret = config_writer_open_element(writer, config_element_snapshot_outputs);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(snapshot->output_ht->ht, &iter.iter, output,
			node.node) {
		ret = config_writer_open_element(writer,
			config_element_output);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = config_writer_write_element_string(writer,
			config_element_name, output->name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = config_writer_write_element_unsigned_int(writer,
			config_element_max_size, output->max_size);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = save_consumer_output(writer, output->consumer);
		if (ret) {
			goto end_unlock;
		}

		/* /output */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}
	}
	rcu_read_unlock();

	/* /snapshot_outputs */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

end:
	return ret;
end_unlock:
	rcu_read_unlock();
	return ret;
}

static
int save_session_output(struct config_writer *writer,
	struct ltt_session *session)
{
	int ret;

	assert(writer);
	assert(session);

	if ((session->snapshot_mode && session->snapshot.nb_output == 0) ||
		(!session->snapshot_mode && !session->consumer)) {
		/* Session is in no output mode */
		ret = 0;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_output);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->snapshot_mode) {
		ret = save_snapshot_outputs(writer, &session->snapshot);
		if (ret) {
			goto end;
		}
	} else {
		if (session->consumer) {
			ret = save_consumer_output(writer, session->consumer);
			if (ret) {
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
end:
	return ret;
}

/*
 * Save the given session.
 *
 * Return 0 on success else a LTTNG_ERR* code.
 */
static
int save_session(struct ltt_session *session,
	struct lttng_save_session_attr *attr, lttng_sock_cred *creds)
{
	int ret, fd;
	char config_file_path[PATH_MAX];
	size_t len;
	struct config_writer *writer = NULL;
	size_t session_name_len;
	const char *provided_path;

	assert(session);
	assert(attr);
	assert(creds);

	session_name_len = strlen(session->name);

	if (!session_access_ok(session,
		LTTNG_SOCK_GET_UID_CRED(creds),
		LTTNG_SOCK_GET_GID_CRED(creds))) {
		ret = LTTNG_ERR_EPERM;
		goto end;
	}

	provided_path = lttng_save_session_attr_get_output_url(attr);
	if (provided_path) {
		len = strlen(provided_path);
		if (len > PATH_MAX) {
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}
		strncpy(config_file_path, provided_path, len);
	} else {
		ssize_t ret_len;
		char *home_dir = utils_get_user_home_dir(
			LTTNG_SOCK_GET_UID_CRED(creds));
		if (!home_dir) {
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}

		ret_len = snprintf(config_file_path, PATH_MAX,
				DEFAULT_SESSION_HOME_CONFIGPATH, home_dir);
		free(home_dir);
		if (ret_len < 0) {
			PERROR("snprintf save session");
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}
		len = ret_len;
	}

	/*
	 * Check the path fits in PATH_MAX, including the / followed by trailing
	 * .lttng extension and the NULL terminated string.
	 */
	if (len + session_name_len + 2 +
			sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION) > PATH_MAX) {
		ret = LTTNG_ERR_SET_URL;
		goto end;
	}

	ret = run_as_mkdir_recursive(config_file_path, S_IRWXU | S_IRWXG,
			LTTNG_SOCK_GET_UID_CRED(creds), LTTNG_SOCK_GET_GID_CRED(creds));
	if (ret) {
		ret = LTTNG_ERR_SET_URL;
		goto end;
	}

	config_file_path[len++] = '/';
	strncpy(config_file_path + len, session->name, session_name_len);
	len += session_name_len;
	strcpy(config_file_path + len, DEFAULT_SESSION_CONFIG_FILE_EXTENSION);

	if (!access(config_file_path, F_OK) && !attr->overwrite) {
		/* A file with the same name already exists, skip */
		goto end;
	}

	fd = run_as_open(config_file_path, O_CREAT | O_WRONLY | O_TRUNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
		LTTNG_SOCK_GET_UID_CRED(creds), LTTNG_SOCK_GET_GID_CRED(creds));
	if (fd < 0) {
		PERROR("Could not create configuration file");
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	writer = config_writer_create(fd);
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

	ret = config_writer_write_element_string(writer, config_element_name,
			session->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_domains(writer, session);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_started,
			session->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->snapshot_mode || session->live_timer) {
		ret = config_writer_open_element(writer, config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		if (session->snapshot_mode) {
			ret = config_writer_write_element_bool(writer,
					config_element_snapshot_mode, 1);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		} else {
			ret = config_writer_write_element_signed_int(writer,
					config_element_live_timer_interval, session->live_timer);
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
	if (ret) {
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
end:
	if (writer && config_writer_destroy(writer)) {
		/* Preserve the original error code */
		ret = ret ? ret : LTTNG_ERR_SAVE_IO_FAIL;
	}
	if (ret) {
		/* Delete file in case of error */
		if (unlink(config_file_path)) {
			PERROR("Unlinking XML session configuration.");
		}
	}

	return ret;
}

int cmd_save_sessions(struct lttng_save_session_attr *attr,
	lttng_sock_cred *creds)
{
	int ret;
	const char *session_name;
	struct ltt_session *session;

	session_lock_list();

	session_name = lttng_save_session_attr_get_session_name(attr);
	if (session_name) {
		session = session_find_by_name(session_name);
		if (!session) {
			ret = LTTNG_ERR_SESS_NOT_FOUND;
			goto end;
		}

		session_lock(session);
		ret = save_session(session, attr, creds);
		session_unlock(session);
		if (ret) {
			goto end;
		}
	} else {
		struct ltt_session_list *list = session_get_list();

		cds_list_for_each_entry(session, &list->head, list) {
			session_lock(session);
			ret = save_session(session, attr, creds);
			session_unlock(session);

			/* Don't abort if we don't have the required permissions. */
			if (ret && ret != LTTNG_ERR_EPERM) {
				goto end;
			}
		}
	}
	ret = LTTNG_OK;

end:
	session_unlock_list();
	return ret;
}
