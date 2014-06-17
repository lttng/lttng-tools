/*
 * Copyright (C) 2014 - Jonathan Rajotte <jonathan.r.julien@gmail.com>
 *                    - Olivier Cotte <olivier.cotte@polymtl.ca>
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


#include <include/config.h>
#include <common/config/config.h>
#include "mi-lttng.h"

#include <assert.h>

/* Strings related to command */
const char * const mi_lttng_element_command = "command";
const char * const mi_lttng_element_command_version = "version";
const char * const mi_lttng_element_command_list = "list";
const char * const mi_lttng_element_command_save = "save";
const char * const mi_lttng_element_command_load = "load";
const char * const mi_lttng_element_command_name = "name";
const char * const mi_lttng_element_command_output = "output";
const char * const mi_lttng_element_command_success = "success";

/* Strings related to version command */
const char * const mi_lttng_element_version = "version";
const char * const mi_lttng_element_version_str = "string";
const char * const mi_lttng_element_version_web = "url";
const char * const mi_lttng_element_version_major = "major";
const char * const mi_lttng_element_version_minor = "minor";
const char * const mi_lttng_element_version_commit = "commit";
const char * const mi_lttng_element_version_license = "license";
const char * const mi_lttng_element_version_patch_level = "patchLevel";
const char * const mi_lttng_element_version_description = "description";

/* Strings related to pid */
const char * const mi_lttng_element_pids = "pids";
const char * const mi_lttng_element_pid = "pid";
const char * const mi_lttng_element_pid_id = "id";

/* Strings related to save command */
const char * const mi_lttng_element_save = "save";

/* Strings related to load command */
const char * const mi_lttng_element_load = "load";

/* String related to a lttng_event_field */
const char * const mi_lttng_element_event_field = "event_field";
const char * const mi_lttng_element_event_fields = "event_fields";

/* General elements of mi_lttng */
const char * const mi_lttng_element_type_other = "OTHER";
const char * const mi_lttng_element_type_integer = "INTEGER";
const char * const mi_lttng_element_type_enum = "ENUM";
const char * const mi_lttng_element_type_float = "FLOAT";
const char * const mi_lttng_element_type_string = "STRING";
const char * const mi_lttng_element_nowrite = "nowrite";

/* String related to loglevel */
const char * const mi_lttng_loglevel_str_alert = "TRACE_ALERT";
const char * const mi_lttng_loglevel_str_crit = "TRACE_CRIT";
const char * const mi_lttng_loglevel_str_debug = "TRACE_DEBUG";
const char * const mi_lttng_loglevel_str_debug_function = "TRACE_DEBUG_FUNCTION";
const char * const mi_lttng_loglevel_str_debug_line = "TRACE_DEBUG_LINE";
const char * const mi_lttng_loglevel_str_debug_module = "TRACE_DEBUG_MODULE";
const char * const mi_lttng_loglevel_str_debug_process = "TRACE_DEBUG_PROCESS";
const char * const mi_lttng_loglevel_str_debug_program = "TRACE_DEBUG_PROGRAM";
const char * const mi_lttng_loglevel_str_debug_system = "TRACE_DEBUG_SYSTEM";
const char * const mi_lttng_loglevel_str_debug_unit = "TRACE_DEBUG_UNIT";
const char * const mi_lttng_loglevel_str_emerg = "TRACE_EMERG";
const char * const mi_lttng_loglevel_str_err = "TRACE_ERR";
const char * const mi_lttng_loglevel_str_info = "TRACE_INFO";
const char * const mi_lttng_loglevel_str_notice = "TRACE_NOTICE";
const char * const mi_lttng_loglevel_str_unknown = "UNKNOWN";
const char * const mi_lttng_loglevel_str_warning = "TRACE_WARNING";

/* String related to loglevel type */
const char * const mi_lttng_loglevel_type_all = "ALL";
const char * const mi_lttng_loglevel_type_range = "RANGE";
const char * const mi_lttng_loglevel_type_single = "SINGLE";
const char * const mi_lttng_loglevel_type_unknown = "UNKNOWN";

const char * const mi_lttng_element_empty = "";

const char *mi_lttng_loglevel_string(int value)
{
	switch (value) {
	case -1:
		return mi_lttng_element_empty;
	case LTTNG_LOGLEVEL_EMERG:
		return mi_lttng_loglevel_str_emerg;
	case LTTNG_LOGLEVEL_ALERT:
		return mi_lttng_loglevel_str_alert;
	case LTTNG_LOGLEVEL_CRIT:
		return mi_lttng_loglevel_str_crit;
	case LTTNG_LOGLEVEL_ERR:
		return mi_lttng_loglevel_str_err;
	case LTTNG_LOGLEVEL_WARNING:
		return mi_lttng_loglevel_str_warning;
	case LTTNG_LOGLEVEL_NOTICE:
		return mi_lttng_loglevel_str_notice;
	case LTTNG_LOGLEVEL_INFO:
		return mi_lttng_loglevel_str_info;
	case LTTNG_LOGLEVEL_DEBUG_SYSTEM:
		return mi_lttng_loglevel_str_debug_system;
	case LTTNG_LOGLEVEL_DEBUG_PROGRAM:
		return mi_lttng_loglevel_str_debug_program;
	case LTTNG_LOGLEVEL_DEBUG_PROCESS:
		return mi_lttng_loglevel_str_debug_process;
	case LTTNG_LOGLEVEL_DEBUG_MODULE:
		return mi_lttng_loglevel_str_debug_module;
	case LTTNG_LOGLEVEL_DEBUG_UNIT:
		return mi_lttng_loglevel_str_debug_unit;
	case LTTNG_LOGLEVEL_DEBUG_FUNCTION:
		return mi_lttng_loglevel_str_debug_function;
	case LTTNG_LOGLEVEL_DEBUG_LINE:
		return mi_lttng_loglevel_str_debug_line;
	case LTTNG_LOGLEVEL_DEBUG:
		return mi_lttng_loglevel_str_debug;
	default:
		return mi_lttng_loglevel_str_unknown;
	}
}

const char *mi_lttng_logleveltype_string(enum lttng_loglevel_type value)
{
	switch (value) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		return mi_lttng_loglevel_type_all;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		return mi_lttng_loglevel_type_range;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		return mi_lttng_loglevel_type_single;
	default:
		return mi_lttng_loglevel_type_unknown;
	}
}

const char *mi_lttng_eventtype_string(enum lttng_event_type value)
{
	switch (value) {
	case LTTNG_EVENT_ALL:
		return config_event_type_all;
	case LTTNG_EVENT_TRACEPOINT:
		return config_event_type_tracepoint;
	case LTTNG_EVENT_PROBE:
		return config_event_type_probe;
	case LTTNG_EVENT_FUNCTION:
		return config_event_type_function;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		return config_event_type_function_entry;
	case LTTNG_EVENT_SYSCALL:
		return config_event_type_syscall;
	case LTTNG_EVENT_NOOP:
		return config_event_type_noop;
	default:
		return mi_lttng_element_empty;
	}
}

const char *mi_lttng_eventfieldtype_string(enum lttng_event_field_type val)
{
	switch (val) {
	case(LTTNG_EVENT_FIELD_INTEGER):
		return mi_lttng_element_type_integer;
	case(LTTNG_EVENT_FIELD_ENUM):
		return mi_lttng_element_type_enum;
	case(LTTNG_EVENT_FIELD_FLOAT):
		return mi_lttng_element_type_float;
	case(LTTNG_EVENT_FIELD_STRING):
		return mi_lttng_element_type_string;
	default:
		return mi_lttng_element_type_other;
	}
}

const char *mi_lttng_domaintype_string(enum lttng_domain_type value)
{
	/* Note: This is a *duplicate* of get_domain_str from bin/lttng/utils.c */
	switch (value) {
	case LTTNG_DOMAIN_KERNEL:
		return config_domain_type_kernel;
	case LTTNG_DOMAIN_UST:
		return config_domain_type_ust;
	case LTTNG_DOMAIN_JUL:
		return config_domain_type_jul;
	default:
		/* Should not have an unknown domain */
		assert(0);
	}
}

const char *mi_lttng_buffertype_string(enum lttng_buffer_type value)
{
	switch (value) {
	case LTTNG_BUFFER_PER_PID:
		return config_buffer_type_per_pid;
	case LTTNG_BUFFER_PER_UID:
		return config_buffer_type_per_uid;
	case LTTNG_BUFFER_GLOBAL:
		return config_buffer_type_global;
	default:
		/* Should not have an unknow buffer type */
		assert(0);
	}
}

LTTNG_HIDDEN
struct mi_writer *mi_lttng_writer_create(int fd_output, int mi_output_type)
{
	struct mi_writer *mi_writer;

	mi_writer = zmalloc(sizeof(struct mi_writer));
	if (!mi_writer) {
		PERROR("zmalloc mi_writer_create");
		goto end;
	}
	if (mi_output_type == LTTNG_MI_XML) {
		mi_writer->writer = config_writer_create(fd_output);
		if (!mi_writer->writer) {
			goto err_destroy;
		}
		mi_writer->type = LTTNG_MI_XML;
	} else {
		goto err_destroy;
	}

end:
	return mi_writer;

err_destroy:
	free(mi_writer);
	return NULL;
}

LTTNG_HIDDEN
int mi_lttng_writer_destroy(struct mi_writer *writer)
{
	int ret;

	if (!writer) {
		ret = -EINVAL;
		goto end;
	}

	ret = config_writer_destroy(writer->writer);
	if (ret < 0) {
		goto end;
	}

	free(writer);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_writer_command_open(struct mi_writer *writer, const char *command)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command);
	if (ret) {
		goto end;
	}
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_command_name, command);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_writer_command_close(struct mi_writer *writer)
{
	return mi_lttng_writer_close_element(writer);
}

LTTNG_HIDDEN
int mi_lttng_writer_open_element(struct mi_writer *writer,
		const char *element_name)
{
	return config_writer_open_element(writer->writer, element_name);
}

LTTNG_HIDDEN
int mi_lttng_writer_close_element(struct mi_writer *writer)
{
	return config_writer_close_element(writer->writer);
}

LTTNG_HIDDEN
int mi_lttng_close_multi_element(struct mi_writer *writer,
		unsigned int nb_element)
{
	int ret, i;

	if (nb_element < 1) {
		ret = 0;
		goto end;
	}
	for (i = 0; i < nb_element; i++) {
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_unsigned_int(struct mi_writer *writer,
		const char *element_name, uint64_t value)
{
	return config_writer_write_element_unsigned_int(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_signed_int(struct mi_writer *writer,
		const char *element_name, int64_t value)
{
	return config_writer_write_element_signed_int(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_bool(struct mi_writer *writer,
		const char *element_name, int value)
{
	return config_writer_write_element_bool(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_string(struct mi_writer *writer,
		const char *element_name, const char *value)
{
	return config_writer_write_element_string(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_version(struct mi_writer *writer, struct mi_lttng_version *version,
	const char *lttng_description, const char *lttng_license)
{
	int ret;

	/* Open version */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_version);
	if (ret) {
		goto end;
	}

	/* Version string (contain info like rc etc.) */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_str, VERSION);
	if (ret) {
		goto end;
	}

	/* Major version number */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_version_major, version->version_major);
	if (ret) {
		goto end;
	}

	/* Minor version number */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_version_minor, version->version_minor);
	if (ret) {
		goto end;
	}

	/* Commit version number */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_commit, version->version_commit);
	if (ret) {
		goto end;
	}

	/* Patch number */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_version_patch_level, version->version_patchlevel);
	if (ret) {
		goto end;
	}

	/* Name of the version */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, version->version_name);
	if (ret) {
		goto end;
	}

	/* Description mostly related to beer... */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_description, lttng_description);
	if (ret) {
		goto end;
	}

	/* url */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_web, version->package_url);
	if (ret) {
		goto end;
	}

	/* License: free as in free beer...no...*speech* */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_license, lttng_license);
	if (ret) {
		goto end;
	}

	/* Close version element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_sessions_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_sessions);
}

LTTNG_HIDDEN
int mi_lttng_session(struct mi_writer *writer,
		struct lttng_session *session, int is_open)
{
	int ret;

	assert(session);

	/* Open sessions element */
	ret = mi_lttng_writer_open_element(writer,
			config_element_session);
	if (ret) {
		goto end;
	}

	/* Name of the session */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, session->name);
	if (ret) {
		goto end;
	}

	/* Path */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_path, session->path);
	if (ret) {
		goto end;
	}

	/* Enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_enabled, session->enabled);
	if (ret) {
		goto end;
	}

	/* Snapshot mode */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_snapshot_mode, session->snapshot_mode);
	if (ret) {
		goto end;
	}

	/* Live timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_live_timer_interval,
			session->live_timer_interval);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		/* Closing session element */
		ret = mi_lttng_writer_close_element(writer);
	}
end:
	return ret;

}

LTTNG_HIDDEN
int mi_lttng_domains_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_domains);
}

LTTNG_HIDDEN
int mi_lttng_domain(struct mi_writer *writer,
		struct lttng_domain *domain, int is_open)
{
	int ret = 0;
	const char *str_domain;
	const char *str_buffer;

	assert(domain);

	/* Open domain element */
	ret = mi_lttng_writer_open_element(writer, config_element_domain);
	if (ret) {
		goto end;
	}

	/* Domain Type */
	str_domain = mi_lttng_domaintype_string(domain->type);
	ret = mi_lttng_writer_write_element_string(writer, config_element_type,
			str_domain);
	if (ret) {
		goto end;
	}

	/* Buffer Type */
	str_buffer= mi_lttng_buffertype_string(domain->buf_type);
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_buffer_type, str_buffer);
	if (ret) {
		goto end;
	}

	/* TODO: attr... not sure how to use the union.... */

	if (!is_open) {
		/* Closing domain element */
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;

}

LTTNG_HIDDEN
int mi_lttng_channels_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_channels);
}

LTTNG_HIDDEN
int mi_lttng_channel(struct mi_writer *writer,
		struct lttng_channel *channel, int is_open)
{
	int ret = 0;

	assert(channel);

	/* Opening channel element */
	ret = mi_lttng_writer_open_element(writer, config_element_channel);
	if (ret) {
		goto end;
	}

	/* Name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			channel->name);
	if (ret) {
		goto end;
	}

	/* Enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_enabled, channel->enabled);
	if (ret) {
		goto end;
	}

	/* Attribute */
	ret = mi_lttng_channel_attr(writer, &channel->attr);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		/* Closing channel element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_channel_attr(struct mi_writer *writer,
		struct lttng_channel_attr *attr)
{
	int ret = 0;

	assert(attr);

	/* Opening Attributes */
	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	/* Overwrite */
	ret = mi_lttng_writer_write_element_string(writer,
		config_element_overwrite_mode,
		attr->overwrite ? config_overwrite_mode_overwrite :
			config_overwrite_mode_discard);
	if (ret) {
		goto end;
	}

	/* Sub buffer size in byte */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_subbuf_size, attr->subbuf_size);
	if (ret) {
		goto end;
	}

	/* Number of subbuffer (power of two) */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_num_subbuf,
		attr->num_subbuf);
	if (ret) {
		goto end;
	}

	/* Switch timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_switch_timer_interval,
		attr->switch_timer_interval);
	if (ret) {
		goto end;
	}

	/* Read timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_read_timer_interval,
		attr->read_timer_interval);
	if (ret) {
		goto end;
	}

	/* Event output */
	ret = mi_lttng_writer_write_element_string(writer,
		config_element_output_type,
		attr->output == LTTNG_EVENT_SPLICE ?
		config_output_type_splice : config_output_type_mmap);
	if (ret) {
		goto end;
	}

	/* Tracefile size in bytes */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_tracefile_size, attr->tracefile_size);
	if (ret) {
		goto end;
	}

	/* Count of tracefiles */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_tracefile_count,
		attr->tracefile_count);
	if (ret) {
		goto end;
	}

	/* Live timer interval in usec*/
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_live_timer_interval,
		attr->live_timer_interval);
	if (ret) {
		goto end;
	}

	/* Closing attributes */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;

}

LTTNG_HIDDEN
int mi_lttng_event_common_attributes(struct mi_writer *writer,
		struct lttng_event *event)
{
	int ret;

	/* Open event element */
	ret = mi_lttng_writer_open_element(writer, config_element_event);
	if (ret) {
		goto end;
	}

	/* event name */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, event->name);
	if (ret) {
		goto end;
	}

	/* event type */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_type, mi_lttng_eventtype_string(event->type));
	if (ret) {
		goto end;
	}

	/* is event enabled */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_enabled, event->enabled);
	if (ret) {
		goto end;
	}

	/* event filter enabled? */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_filter, event->filter);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_tracepoint_loglevel(struct mi_writer *writer,
		struct lttng_event *event)
{
	int ret;

	/* event loglevel */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_loglevel, mi_lttng_loglevel_string(event->loglevel));
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer,
			config_element_loglevel_type,
			mi_lttng_logleveltype_string(event->loglevel_type));
	if (ret) {
		goto end;
	}

	/* event exclusion filter */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_exclusion, event->exclusion);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_tracepoint_no_loglevel(struct mi_writer *writer,
		struct lttng_event *event)
{
	/* event exclusion filter */
	return mi_lttng_writer_write_element_bool(writer,
			config_element_exclusion, event->exclusion);
}

LTTNG_HIDDEN
int mi_lttng_event_function_probe(struct mi_writer *writer,
		struct lttng_event *event)
{
	int ret;

	if (event->attr.probe.addr != 0) {
		/* event probe address */
		ret = mi_lttng_writer_write_element_unsigned_int(writer,
				config_element_address, event->attr.probe.addr);
		if (ret) {
			goto end;
		}
	} else {
		/* event probe offset */
		ret = mi_lttng_writer_write_element_unsigned_int(writer,
				config_element_offset, event->attr.probe.offset);
		if (ret) {
			goto end;
		}

		/* event probe symbol_name */
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_symbol_name, event->attr.probe.symbol_name);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_function_entry(struct mi_writer *writer,
		struct lttng_event *event)
{
	/* event probe symbol_name */
	return mi_lttng_writer_write_element_string(writer,
			config_element_symbol_name, event->attr.ftrace.symbol_name);
}

LTTNG_HIDDEN
int mi_lttng_events_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_events);
}

LTTNG_HIDDEN
int mi_lttng_event(struct mi_writer *writer,
		struct lttng_event *event, int is_open)
{
	int ret;

	ret = mi_lttng_event_common_attributes(writer, event);
	if (ret) {
		goto end;
	}

	switch (event->type) {
	case LTTNG_EVENT_ALL:
		/* We should never have "all" events in list. */
		assert(0);
		break;
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (event->loglevel != -1) {
			ret = mi_lttng_event_tracepoint_loglevel(writer, event);
		} else {
			ret = mi_lttng_event_tracepoint_no_loglevel(writer, event);
		}
		break;
	}
	case LTTNG_EVENT_PROBE:
		ret = mi_lttng_event_function_probe(writer, event);
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		ret = mi_lttng_event_function_entry(writer, event);
		break;
	default:
		break;
	}

	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_pids_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, mi_lttng_element_pids);
}

LTTNG_HIDDEN
int mi_lttng_pid(struct mi_writer *writer, pid_t pid , const char *cmdline,
		int is_open)
{
	int ret;

	/* Open element pid */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_pid);
	if (ret) {
		goto end;
	}

	/* Writing pid number */
	ret = mi_lttng_writer_write_element_signed_int(writer,
			mi_lttng_element_pid_id, (int)pid);
	if (ret) {
		goto end;
	}

	/* Writing name of the process */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			cmdline);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		/* Closing Pid */
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_fields_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, mi_lttng_element_event_fields);
}

LTTNG_HIDDEN
int mi_lttng_event_field(struct mi_writer *writer,
		struct lttng_event_field *field)
{
	int ret;

	if (!field->field_name[0]) {
		/* To Review: not sure if legal david ?
		 * how should this be handle ?
		 */
		ret = 0;
		goto end;
	}

	/* Open field */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_event_field);
	if (ret) {
		goto end;
	}

	if (!field->field_name[0]) {
		goto close;
	}

	/* Name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			field->field_name);
	if (ret) {
		goto end;
	}

	/* Type */
	ret = mi_lttng_writer_write_element_string(writer, config_element_type,
			mi_lttng_eventfieldtype_string(field->type));
	if (ret) {
		goto end;
	}

	/* nowrite  */
	ret = mi_lttng_writer_write_element_signed_int(writer,
			mi_lttng_element_nowrite, field->nowrite);
	if (ret) {
		goto end;
	}

close:
	/* Close field element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}
