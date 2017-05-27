/*
 * Copyright (C) 2014 - Jonathan Rajotte <jonathan.r.julien@gmail.com>
 *                    - Olivier Cotte <olivier.cotte@polymtl.ca>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#define _LGPL_SOURCE
#include <common/config/session-config.h>
#include <common/defaults.h>
#include <lttng/snapshot-internal.h>
#include <lttng/channel.h>
#include "mi-lttng.h"

#include <assert.h>

#define MI_SCHEMA_MAJOR_VERSION 3
#define MI_SCHEMA_MINOR_VERSION 0

/* Machine interface namespace URI */
LTTNG_HIDDEN const char * const mi_lttng_xmlns = "xmlns";
LTTNG_HIDDEN const char * const mi_lttng_xmlns_xsi = "xmlns:xsi";
LTTNG_HIDDEN const char * const mi_lttng_w3_schema_uri = "http://www.w3.org/2001/XMLSchema-instance";
LTTNG_HIDDEN const char * const mi_lttng_schema_location = "xsi:schemaLocation";
LTTNG_HIDDEN const char * const mi_lttng_schema_location_uri =
	DEFAULT_LTTNG_MI_NAMESPACE " "
	"http://lttng.org/xml/schemas/lttng-mi/" XSTR(MI_SCHEMA_MAJOR_VERSION)
	"/lttng-mi-" XSTR(MI_SCHEMA_MAJOR_VERSION) "."
	XSTR(MI_SCHEMA_MINOR_VERSION) ".xsd";
LTTNG_HIDDEN const char * const mi_lttng_schema_version = "schemaVersion";
LTTNG_HIDDEN const char * const mi_lttng_schema_version_value = XSTR(MI_SCHEMA_MAJOR_VERSION)
	"." XSTR(MI_SCHEMA_MINOR_VERSION);

/* Strings related to command */
const char * const mi_lttng_element_command = "command";
const char * const mi_lttng_element_command_action = "snapshot_action";
const char * const mi_lttng_element_command_add_context = "add-context";
const char * const mi_lttng_element_command_create = "create";
const char * const mi_lttng_element_command_destroy = "destroy";
const char * const mi_lttng_element_command_disable_channel = "disable-channel";
const char * const mi_lttng_element_command_disable_event = "disable-event";
const char * const mi_lttng_element_command_enable_channels = "enable-channel";
const char * const mi_lttng_element_command_enable_event = "enable-event";
const char * const mi_lttng_element_command_list = "list";
const char * const mi_lttng_element_command_load = "load";
LTTNG_HIDDEN const char * const mi_lttng_element_command_metadata = "metadata";
LTTNG_HIDDEN const char * const mi_lttng_element_command_metadata_action = "metadata_action";
LTTNG_HIDDEN const char * const mi_lttng_element_command_regenerate = "regenerate";
LTTNG_HIDDEN const char * const mi_lttng_element_command_regenerate_action = "regenerate_action";
const char * const mi_lttng_element_command_name = "name";
const char * const mi_lttng_element_command_output = "output";
const char * const mi_lttng_element_command_save = "save";
const char * const mi_lttng_element_command_set_session = "set-session";
const char * const mi_lttng_element_command_snapshot = "snapshot";
const char * const mi_lttng_element_command_snapshot_add = "add_snapshot";
const char * const mi_lttng_element_command_snapshot_del = "del_snapshot";
const char * const mi_lttng_element_command_snapshot_list = "list_snapshot";
const char * const mi_lttng_element_command_snapshot_record = "record_snapshot";
const char * const mi_lttng_element_command_start = "start";
const char * const mi_lttng_element_command_stop = "stop";
const char * const mi_lttng_element_command_success = "success";
const char * const mi_lttng_element_command_track = "track";
const char * const mi_lttng_element_command_untrack = "untrack";
const char * const mi_lttng_element_command_version = "version";

/* Strings related to version command */
const char * const mi_lttng_element_version = "version";
const char * const mi_lttng_element_version_commit = "commit";
const char * const mi_lttng_element_version_description = "description";
const char * const mi_lttng_element_version_license = "license";
const char * const mi_lttng_element_version_major = "major";
const char * const mi_lttng_element_version_minor = "minor";
const char * const mi_lttng_element_version_patch_level = "patchLevel";
const char * const mi_lttng_element_version_str = "string";
const char * const mi_lttng_element_version_web = "url";

/* String related to a lttng_event_field */
const char * const mi_lttng_element_event_field = "event_field";
const char * const mi_lttng_element_event_fields = "event_fields";

/* String related to lttng_event_perf_counter_ctx */
const char * const mi_lttng_element_perf_counter_context = "perf";

/* Strings related to pid */
const char * const mi_lttng_element_pid_id = "id";

/* Strings related to save command */
const char * const mi_lttng_element_save = "save";

/* Strings related to load command */
const char * const mi_lttng_element_load = "load";
LTTNG_HIDDEN const char * const mi_lttng_element_load_overrides = "overrides";
LTTNG_HIDDEN const char * const mi_lttng_element_load_override_url = "url";

/* General elements of mi_lttng */
const char * const mi_lttng_element_empty = "";
const char * const mi_lttng_element_id = "id";
const char * const mi_lttng_element_nowrite = "nowrite";
const char * const mi_lttng_element_success = "success";
const char * const mi_lttng_element_type_enum = "ENUM";
const char * const mi_lttng_element_type_float = "FLOAT";
const char * const mi_lttng_element_type_integer = "INTEGER";
const char * const mi_lttng_element_type_other = "OTHER";
const char * const mi_lttng_element_type_string = "STRING";

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

/* String related to loglevel JUL */
const char * const mi_lttng_loglevel_str_jul_all = "JUL_ALL";
const char * const mi_lttng_loglevel_str_jul_config = "JUL_CONFIG";
const char * const mi_lttng_loglevel_str_jul_fine = "JUL_FINE";
const char * const mi_lttng_loglevel_str_jul_finer = "JUL_FINER";
const char * const mi_lttng_loglevel_str_jul_finest = "JUL_FINEST";
const char * const mi_lttng_loglevel_str_jul_info = "JUL_INFO";
const char * const mi_lttng_loglevel_str_jul_off = "JUL_OFF";
const char * const mi_lttng_loglevel_str_jul_severe = "JUL_SEVERE";
const char * const mi_lttng_loglevel_str_jul_warning = "JUL_WARNING";

/* String related to loglevel LOG4J */
const char * const mi_lttng_loglevel_str_log4j_off = "LOG4J_OFF";
const char * const mi_lttng_loglevel_str_log4j_fatal = "LOG4J_FATAL";
const char * const mi_lttng_loglevel_str_log4j_error = "LOG4J_ERROR";
const char * const mi_lttng_loglevel_str_log4j_warn = "LOG4J_WARN";
const char * const mi_lttng_loglevel_str_log4j_info = "LOG4J_INFO";
const char * const mi_lttng_loglevel_str_log4j_debug = "LOG4J_DEBUG";
const char * const mi_lttng_loglevel_str_log4j_trace = "LOG4J_TRACE";
const char * const mi_lttng_loglevel_str_log4j_all = "LOG4J_ALL";

/* String related to loglevel Python */
const char * const mi_lttng_loglevel_str_python_critical = "PYTHON_CRITICAL";
const char * const mi_lttng_loglevel_str_python_error = "PYTHON_ERROR";
const char * const mi_lttng_loglevel_str_python_warning = "PYTHON_WARNING";
const char * const mi_lttng_loglevel_str_python_info = "PYTHON_INFO";
const char * const mi_lttng_loglevel_str_python_debug = "PYTHON_DEBUG";
const char * const mi_lttng_loglevel_str_python_notset = "PYTHON_NOTSET";

/* String related to loglevel type */
const char * const mi_lttng_loglevel_type_all = "ALL";
const char * const mi_lttng_loglevel_type_range = "RANGE";
const char * const mi_lttng_loglevel_type_single = "SINGLE";
const char * const mi_lttng_loglevel_type_unknown = "UNKNOWN";

/* String related to a lttng_snapshot_output */
const char * const mi_lttng_element_snapshot_ctrl_url = "ctrl_url";
const char * const mi_lttng_element_snapshot_data_url = "data_url";
const char * const mi_lttng_element_snapshot_max_size = "max_size";
const char * const mi_lttng_element_snapshot_n_ptr = "n_ptr";
const char * const mi_lttng_element_snapshot_session_name = "session_name";
const char * const mi_lttng_element_snapshots = "snapshots";

/* String related to track/untrack command */
const char * const mi_lttng_element_track_untrack_all_wildcard = "*";

/* Deprecated symbols preserved for ABI compatibility. */
const char * const mi_lttng_context_type_perf_counter;
const char * const mi_lttng_context_type_perf_cpu_counter;
const char * const mi_lttng_context_type_perf_thread_counter;
const char * const mi_lttng_element_track_untrack_pid_target;
const char * const mi_lttng_element_track_untrack_targets;
const char * const mi_lttng_element_calibrate;
const char * const mi_lttng_element_calibrate_function;
const char * const mi_lttng_element_command_calibrate;

/* This is a merge of jul loglevel and regular loglevel
 * Those should never overlap by definition
 * (see struct lttng_event loglevel)
 */
LTTNG_HIDDEN
const char *mi_lttng_loglevel_string(int value, enum lttng_domain_type domain)
{
	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	case LTTNG_DOMAIN_UST:
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
		break;
	case LTTNG_DOMAIN_LOG4J:
		switch (value) {
		case -1:
			return mi_lttng_element_empty;
		case LTTNG_LOGLEVEL_LOG4J_OFF:
			return mi_lttng_loglevel_str_log4j_off;
		case LTTNG_LOGLEVEL_LOG4J_FATAL:
			return mi_lttng_loglevel_str_log4j_fatal;
		case LTTNG_LOGLEVEL_LOG4J_ERROR:
			return mi_lttng_loglevel_str_log4j_error;
		case LTTNG_LOGLEVEL_LOG4J_WARN:
			return mi_lttng_loglevel_str_log4j_warn;
		case LTTNG_LOGLEVEL_LOG4J_INFO:
			return mi_lttng_loglevel_str_log4j_info;
		case LTTNG_LOGLEVEL_LOG4J_DEBUG:
			return mi_lttng_loglevel_str_log4j_debug;
		case LTTNG_LOGLEVEL_LOG4J_TRACE:
			return mi_lttng_loglevel_str_log4j_trace;
		case LTTNG_LOGLEVEL_LOG4J_ALL:
			return mi_lttng_loglevel_str_log4j_all;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	case LTTNG_DOMAIN_JUL:
		switch (value) {
		case -1:
			return mi_lttng_element_empty;
		case LTTNG_LOGLEVEL_JUL_OFF:
			return mi_lttng_loglevel_str_jul_off;
		case LTTNG_LOGLEVEL_JUL_SEVERE:
			return mi_lttng_loglevel_str_jul_severe;
		case LTTNG_LOGLEVEL_JUL_WARNING:
			return mi_lttng_loglevel_str_jul_warning;
		case LTTNG_LOGLEVEL_JUL_INFO:
			return mi_lttng_loglevel_str_jul_info;
		case LTTNG_LOGLEVEL_JUL_CONFIG:
			return mi_lttng_loglevel_str_jul_config;
		case LTTNG_LOGLEVEL_JUL_FINE:
			return mi_lttng_loglevel_str_jul_fine;
		case LTTNG_LOGLEVEL_JUL_FINER:
			return mi_lttng_loglevel_str_jul_finer;
		case LTTNG_LOGLEVEL_JUL_FINEST:
			return mi_lttng_loglevel_str_jul_finest;
		case LTTNG_LOGLEVEL_JUL_ALL:
			return mi_lttng_loglevel_str_jul_all;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	case LTTNG_DOMAIN_PYTHON:
		switch (value) {
		case LTTNG_LOGLEVEL_PYTHON_CRITICAL:
			return mi_lttng_loglevel_str_python_critical;
		case LTTNG_LOGLEVEL_PYTHON_ERROR:
			return mi_lttng_loglevel_str_python_error;
		case LTTNG_LOGLEVEL_PYTHON_WARNING:
			return mi_lttng_loglevel_str_python_warning;
		case LTTNG_LOGLEVEL_PYTHON_INFO:
			return mi_lttng_loglevel_str_python_info;
		case LTTNG_LOGLEVEL_PYTHON_DEBUG:
			return mi_lttng_loglevel_str_python_debug;
		case LTTNG_LOGLEVEL_PYTHON_NOTSET:
			return mi_lttng_loglevel_str_python_notset;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	default:
		return mi_lttng_loglevel_str_unknown;
	}
}

LTTNG_HIDDEN
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

LTTNG_HIDDEN
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

static
const char *mi_lttng_event_contexttype_string(enum lttng_event_context_type val)
{
	switch (val) {
	case LTTNG_EVENT_CONTEXT_PID:
		return config_event_context_pid;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		return config_event_context_procname;
	case LTTNG_EVENT_CONTEXT_PRIO:
		return config_event_context_prio;
	case LTTNG_EVENT_CONTEXT_NICE:
		return config_event_context_nice;
	case LTTNG_EVENT_CONTEXT_VPID:
		return config_event_context_vpid;
	case LTTNG_EVENT_CONTEXT_TID:
		return config_event_context_tid;
	case LTTNG_EVENT_CONTEXT_VTID:
		return config_event_context_vtid;
	case LTTNG_EVENT_CONTEXT_PPID:
		return config_event_context_ppid;
	case LTTNG_EVENT_CONTEXT_VPPID:
		return config_event_context_vppid;
	case LTTNG_EVENT_CONTEXT_PTHREAD_ID:
		return config_event_context_pthread_id;
	case LTTNG_EVENT_CONTEXT_HOSTNAME:
		return config_event_context_hostname;
	case LTTNG_EVENT_CONTEXT_IP:
		return config_event_context_ip;
	default:
		return NULL;
	}
}

LTTNG_HIDDEN
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

LTTNG_HIDDEN
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
	case LTTNG_DOMAIN_LOG4J:
		return config_domain_type_log4j;
	case LTTNG_DOMAIN_PYTHON:
		return config_domain_type_python;
	default:
		/* Should not have an unknown domain */
		assert(0);
		return NULL;
	}
}

LTTNG_HIDDEN
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
		return NULL;
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
		mi_writer->writer = config_writer_create(fd_output, 0);
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

	/*
	 * A command is always the MI's root node, it must declare the current
	 * namespace and schema URIs and the schema's version.
	 */
	ret = config_writer_open_element(writer->writer,
			mi_lttng_element_command);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(writer->writer,
			mi_lttng_xmlns, DEFAULT_LTTNG_MI_NAMESPACE);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(writer->writer,
			mi_lttng_xmlns_xsi, mi_lttng_w3_schema_uri);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(writer->writer,
			mi_lttng_schema_location,
			mi_lttng_schema_location_uri);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(writer->writer,
			mi_lttng_schema_version,
			mi_lttng_schema_version_value);
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
			mi_lttng_element_version_str, version->version);
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

	/* TODO: union  attr
	 * This union is not currently used and was added for
	 * future ust domain support.
	 * Date: 25-06-2014
	 * */

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
	struct lttng_channel *chan = caa_container_of(attr,
			struct lttng_channel, attr);
	uint64_t discarded_events, lost_packets, monitor_timer_interval;
	int64_t blocking_timeout;

	assert(attr);

	ret = lttng_channel_get_discarded_event_count(chan, &discarded_events);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_lost_packet_count(chan, &lost_packets);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_monitor_timer_interval(chan,
			&monitor_timer_interval);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_blocking_timeout(chan,
			&blocking_timeout);
	if (ret) {
		goto end;
	}

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

	/* Monitor timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_monitor_timer_interval,
		monitor_timer_interval);
	if (ret) {
		goto end;
	}

	/* Retry timeout in usec */
	ret = mi_lttng_writer_write_element_signed_int(writer,
		config_element_blocking_timeout,
		blocking_timeout);
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

	/* Discarded events */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_discarded_events,
		discarded_events);
	if (ret) {
		goto end;
	}

	/* Lost packets */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
		config_element_lost_packets,
		lost_packets);
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
	const char *filter_expression;

	/* Open event element */
	ret = mi_lttng_writer_open_element(writer, config_element_event);
	if (ret) {
		goto end;
	}

	/* Event name */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, event->name);
	if (ret) {
		goto end;
	}

	/* Event type */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_type, mi_lttng_eventtype_string(event->type));
	if (ret) {
		goto end;
	}

	/* Is event enabled */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_enabled, event->enabled);
	if (ret) {
		goto end;
	}

	/* Event filter expression */
	ret = lttng_event_get_filter_expression(event, &filter_expression);
	if (ret) {
		goto end;
	}

	if (filter_expression) {
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_filter_expression,
				filter_expression);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static int write_event_exclusions(struct mi_writer *writer,
		struct lttng_event *event)
{
	int i;
	int ret;
	int exclusion_count;

	/* Open event exclusions */
	ret = mi_lttng_writer_open_element(writer, config_element_exclusions);
	if (ret) {
		goto end;
	}

	exclusion_count = lttng_event_get_exclusion_name_count(event);
	if (exclusion_count < 0) {
		ret = exclusion_count;
		goto end;
	}

	for (i = 0; i < exclusion_count; i++) {
		const char *name;

		ret = lttng_event_get_exclusion_name(event, i, &name);
		if (ret) {
			/* Close exclusions */
			mi_lttng_writer_close_element(writer);
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(writer,
				config_element_exclusion, name);
		if (ret) {
			/* Close exclusions */
			mi_lttng_writer_close_element(writer);
			goto end;
		}
	}

	/* Close exclusions */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_tracepoint_loglevel(struct mi_writer *writer,
		struct lttng_event *event, enum lttng_domain_type domain)
{
	int ret;

	/* Event loglevel */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_loglevel,
			mi_lttng_loglevel_string(event->loglevel, domain));
	if (ret) {
		goto end;
	}

	/* Log level type */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_loglevel_type,
			mi_lttng_logleveltype_string(event->loglevel_type));
	if (ret) {
		goto end;
	}

	/* Event exclusions */
	ret = write_event_exclusions(writer, event);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_tracepoint_no_loglevel(struct mi_writer *writer,
		struct lttng_event *event)
{
	/* event exclusion filter */
	return write_event_exclusions(writer, event);
}

LTTNG_HIDDEN
int mi_lttng_event_function_probe(struct mi_writer *writer,
		struct lttng_event *event)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_probe_attributes);
	if (ret) {
		goto end;
	}

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

	/* Close probe_attributes and attributes */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_event_function_entry(struct mi_writer *writer,
		struct lttng_event *event)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_probe_attributes);
	if (ret) {
		goto end;
	}

	/* event probe symbol_name */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_symbol_name, event->attr.ftrace.symbol_name);
	if (ret) {
		goto end;
	}

	/* Close function_attributes and attributes */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_events_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_events);
}

LTTNG_HIDDEN
int mi_lttng_event(struct mi_writer *writer,
		struct lttng_event *event, int is_open, enum lttng_domain_type domain)
{
	int ret;

	ret = mi_lttng_event_common_attributes(writer, event);
	if (ret) {
		goto end;
	}

	switch (event->type) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (event->loglevel != -1) {
			ret = mi_lttng_event_tracepoint_loglevel(writer, event, domain);
		} else {
			ret = mi_lttng_event_tracepoint_no_loglevel(writer, event);
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
		/* Fallthrough */
	case LTTNG_EVENT_PROBE:
		ret = mi_lttng_event_function_probe(writer, event);
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		ret = mi_lttng_event_function_entry(writer, event);
		break;
	case LTTNG_EVENT_ALL:
		/* Fallthrough */
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
int mi_lttng_trackers_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_trackers);
}

LTTNG_HIDDEN
int mi_lttng_pid_tracker_open(struct mi_writer *writer)
{
	int ret;

	/* Open element pid_tracker */
	ret = mi_lttng_writer_open_element(writer, config_element_pid_tracker);
	if (ret) {
		goto end;
	}

	/* Open targets element */
	ret = mi_lttng_targets_open(writer);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_pids_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_pids);
}

/*
 * TODO: move the listing of pid for user agent to process semantic on
 * mi api bump. The use of process element break the mi api.
 */
LTTNG_HIDDEN
int mi_lttng_pid(struct mi_writer *writer, pid_t pid , const char *name,
		int is_open)
{
	int ret;

	/* Open pid process */
	ret = mi_lttng_writer_open_element(writer, config_element_pid);
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
	if (name) {
		ret = mi_lttng_writer_write_element_string(writer, config_element_name,
				name);
		if (ret) {
			goto end;
		}
	}

	if (!is_open) {
		/* Closing Pid */
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_targets_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer,
			config_element_targets);
}

LTTNG_HIDDEN
int mi_lttng_pid_target(struct mi_writer *writer, pid_t pid, int is_open)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer,
			config_element_target_pid);
	if (ret) {
		goto end;
	}

	/* Writing pid number
	 * Special case for element all on track untrack command
	 * All pid is represented as wildcard *
	 */
	if ((int) pid == -1) {
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_pid,
				mi_lttng_element_track_untrack_all_wildcard);
	} else {
		ret = mi_lttng_writer_write_element_signed_int(writer,
				config_element_pid, (int) pid);
	}
	if (ret) {
		goto end;
	}

	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
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

LTTNG_HIDDEN
int mi_lttng_perf_counter_context(struct mi_writer *writer,
		struct lttng_event_perf_counter_ctx  *perf_context)
{
	int ret;

	/* Open perf_counter_context */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_perf_counter_context);
	if (ret) {
		goto end;
	}

	/* Type */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_type, perf_context->type);
	if (ret) {
		goto end;
	}

	/* Config */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_config, perf_context->config);
	if (ret) {
		goto end;
	}

	/* Name of the perf counter */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, perf_context->name);
	if (ret) {
		goto end;
	}

	/* Close perf_counter_context */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

static
int mi_lttng_app_context(struct mi_writer *writer,
		const char *provider_name, const char *ctx_name)
{
	int ret;

	/* Open app */
	ret = mi_lttng_writer_open_element(writer,
			config_element_context_app);
	if (ret) {
		goto end;
	}

	/* provider_name */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_context_app_provider_name,
			provider_name);
	if (ret) {
		goto end;
	}

	/* ctx_name */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_context_app_ctx_name, ctx_name);
	if (ret) {
		goto end;
	}

	/* Close app */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_context(struct mi_writer *writer,
		struct lttng_event_context *context, int is_open)
{
	int ret;

	/* Open context */
	ret = mi_lttng_writer_open_element(writer , config_element_context);
	if (ret) {
		goto end;
	}

	/* Special case for PERF_*_COUNTER
	 * print the lttng_event_perf_counter_ctx*/
	switch (context->ctx) {
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
	{
		struct lttng_event_perf_counter_ctx *perf_context =
				&context->u.perf_counter;
		ret =  mi_lttng_perf_counter_context(writer, perf_context);
		if (ret) {
			goto end;
		}
		break;
	}
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
	{
		ret = mi_lttng_app_context(writer,
				context->u.app_ctx.provider_name,
				context->u.app_ctx.ctx_name);
		if (ret) {
			goto end;
		}
		break;
	}
	default:
	{
		const char *type_string = mi_lttng_event_contexttype_string(
				context->ctx);
		if (!type_string) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		/* Print context type */
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_type, type_string);
		break;
	}
	}

	/* Close context */
	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_snapshot_output_session_name(struct mi_writer *writer,
		const char *session_name)
{
	int ret;

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Snapshot output list for current session name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			session_name);
	if (ret) {
		goto end;
	}

	/* Open element snapshots (sequence one snapshot) */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_snapshots);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_snapshot_list_output(struct mi_writer *writer,
		struct lttng_snapshot_output *output)
{
	int ret;

	/* Open element snapshot output */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	/* ID of the snapshot output */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_id, output->id);
	if (ret) {
		goto end;
	}

	/* Name of the output */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			output->name);
	if (ret) {
		goto end;
	}

	/* Destination of the output (ctrl_url)*/
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_snapshot_ctrl_url, output->ctrl_url);
	if (ret) {
		goto end;
	}

	/* Destination of the output (data_url) */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_snapshot_data_url, output->data_url);
	if (ret) {
		goto end;
	}

	/* total size of all stream combined */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_snapshot_max_size, output->max_size);
	if (ret) {
		goto end;
	}

	/* Close snapshot output element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_snapshot_del_output(struct mi_writer *writer, int id,
		const char *name, const char *current_session_name)
{
	int ret;

	/* Open element del_snapshot */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}


	if (id != UINT32_MAX) {
		/* "Snapshot output "id" successfully deleted
		 * for "current_session_name"
		 * ID of the snapshot output
		 */
		ret = mi_lttng_writer_write_element_unsigned_int(writer,
				mi_lttng_element_id, id);
		if (ret) {
			goto end;
		}
	} else {
		/* "Snapshot output "name" successfully deleted
		 * for session "current_session_name"
		 * Name of the output
		 */
		ret = mi_lttng_writer_write_element_string(writer, config_element_name,
				name);
		if (ret) {
			goto end;
		}
	}

	/* Snapshot was deleted for session "current_session_name"*/
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_snapshot_session_name,
			current_session_name);
	if (ret) {
		goto end;
	}

	/* Close snapshot element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_snapshot_add_output(struct mi_writer *writer,
		const char *current_session_name, const char *n_ptr,
		struct lttng_snapshot_output *output)
{
	int ret;

	/* Open element snapshot */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	/* Snapshot output id */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_id, output->id);
	if (ret) {
		goto end;
	}

	/* Snapshot output names */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, n_ptr);
	if (ret) {
		goto end;
	}

	/* Destination of the output (ctrl_url)*/
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_snapshot_ctrl_url, output->ctrl_url);
	if (ret) {
		goto end;
	}

	/* Snapshot added for session "current_session_name"*/
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_snapshot_session_name, current_session_name);
	if (ret) {
		goto end;
	}

	/* total size of all stream combined */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_snapshot_max_size, output->max_size);
	if (ret) {
		goto end;
	}

	/* Close snapshot element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_snapshot_record(struct mi_writer *writer,
		const char *current_session_name, const char *url,
		const char *cmdline_ctrl_url, const char *cmdline_data_url)
{
	int ret;

	/* Open element snapshot */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	/*
	 * If a valid an URL was given, serialize it,
	 * else take the command line data and ctrl urls*/
	if (url) {
		/* Destination of the output (ctrl_url)*/
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_snapshot_ctrl_url, url);
		if (ret) {
			goto end;
		}
	} else if (cmdline_ctrl_url) {
		/* Destination of the output (ctrl_url)*/
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_snapshot_ctrl_url, cmdline_ctrl_url);
		if (ret) {
			goto end;
		}

		/* Destination of the output (data_url) */
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_snapshot_data_url, cmdline_data_url);
		if (ret) {
			goto end;
		}
	}

	/* Close record_snapshot element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}
