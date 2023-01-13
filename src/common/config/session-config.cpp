/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "lttng/tracker.h"
#define _LGPL_SOURCE
#include "config-internal.hpp"
#include "session-config.hpp"

#include <common/compat/getenv.hpp>
#include <common/defaults.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/utils.hpp>

#include <lttng/lttng-error.h>
#include <lttng/lttng.h>
#include <lttng/rotation.h>
#include <lttng/snapshot.h>
#include <lttng/userspace-probe.h>

#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xmlschemas.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CONFIG_USERSPACE_PROBE_LOOKUP_METHOD_NAME_MAX_LEN 7

namespace {
struct session_config_validation_ctx {
	xmlSchemaParserCtxtPtr parser_ctx;
	xmlSchemaPtr schema;
	xmlSchemaValidCtxtPtr schema_validation_ctx;
};
} /* namespace */

const char *const config_element_all = "all";
LTTNG_EXPORT const char *config_xml_encoding = "UTF-8";
LTTNG_EXPORT size_t config_xml_encoding_bytes_per_char = 2; /* Size of the encoding's largest
							       character */
LTTNG_EXPORT const char *config_xml_indent_string = "\t";
LTTNG_EXPORT const char *config_xml_true = "true";
LTTNG_EXPORT const char *config_xml_false = "false";

const char *const config_element_channel = "channel";
const char *const config_element_channels = "channels";
const char *const config_element_domain = "domain";
const char *const config_element_domains = "domains";
const char *const config_element_event = "event";
const char *const config_element_events = "events";
const char *const config_element_context = "context";
const char *const config_element_contexts = "contexts";
const char *const config_element_attributes = "attributes";
const char *const config_element_exclusion = "exclusion";
const char *const config_element_exclusions = "exclusions";
const char *const config_element_function_attributes = "function_attributes";
const char *const config_element_probe_attributes = "probe_attributes";
const char *const config_element_symbol_name = "symbol_name";
const char *const config_element_address = "address";
const char *const config_element_offset = "offset";

const char *const config_element_userspace_probe_lookup = "lookup_method";
const char *const config_element_userspace_probe_lookup_function_default = "DEFAULT";
const char *const config_element_userspace_probe_lookup_function_elf = "ELF";
const char *const config_element_userspace_probe_lookup_tracepoint_sdt = "SDT";
const char *const config_element_userspace_probe_location_binary_path = "binary_path";
const char *const config_element_userspace_probe_function_attributes =
	"userspace_probe_function_attributes";
const char *const config_element_userspace_probe_function_location_function_name = "function_name";
const char *const config_element_userspace_probe_tracepoint_attributes =
	"userspace_probe_tracepoint_attributes";
const char *const config_element_userspace_probe_tracepoint_location_provider_name =
	"provider_name";
const char *const config_element_userspace_probe_tracepoint_location_probe_name = "probe_name";

const char *const config_element_name = "name";
const char *const config_element_enabled = "enabled";
const char *const config_element_overwrite_mode = "overwrite_mode";
const char *const config_element_subbuf_size = "subbuffer_size";
const char *const config_element_num_subbuf = "subbuffer_count";
const char *const config_element_switch_timer_interval = "switch_timer_interval";
const char *const config_element_read_timer_interval = "read_timer_interval";
const char *const config_element_monitor_timer_interval = "monitor_timer_interval";
const char *const config_element_blocking_timeout = "blocking_timeout";
const char *const config_element_output = "output";
const char *const config_element_output_type = "output_type";
const char *const config_element_tracefile_size = "tracefile_size";
const char *const config_element_tracefile_count = "tracefile_count";
const char *const config_element_live_timer_interval = "live_timer_interval";
const char *const config_element_discarded_events = "discarded_events";
const char *const config_element_lost_packets = "lost_packets";
const char *const config_element_type = "type";
const char *const config_element_buffer_type = "buffer_type";
const char *const config_element_session = "session";
const char *const config_element_sessions = "sessions";
const char *const config_element_context_perf = "perf";
const char *const config_element_context_app = "app";
const char *const config_element_context_app_provider_name = "provider_name";
const char *const config_element_context_app_ctx_name = "ctx_name";
const char *const config_element_config = "config";
const char *const config_element_started = "started";
const char *const config_element_snapshot_mode = "snapshot_mode";
const char *const config_element_loglevel = "loglevel";
const char *const config_element_loglevel_type = "loglevel_type";
const char *const config_element_filter = "filter";
const char *const config_element_filter_expression = "filter_expression";
const char *const config_element_snapshot_outputs = "snapshot_outputs";
const char *const config_element_consumer_output = "consumer_output";
const char *const config_element_destination = "destination";
const char *const config_element_path = "path";
const char *const config_element_net_output = "net_output";
const char *const config_element_control_uri = "control_uri";
const char *const config_element_data_uri = "data_uri";
const char *const config_element_max_size = "max_size";
const char *const config_element_pid = "pid";
const char *const config_element_pids = "pids";
const char *const config_element_shared_memory_path = "shared_memory_path";

const char *const config_element_process_attr_id = "id";
const char *const config_element_process_attr_tracker_pid = "pid_process_attr_tracker";
const char *const config_element_process_attr_tracker_vpid = "vpid_process_attr_tracker";
const char *const config_element_process_attr_tracker_uid = "uid_process_attr_tracker";
const char *const config_element_process_attr_tracker_vuid = "vuid_process_attr_tracker";
const char *const config_element_process_attr_tracker_gid = "gid_process_attr_tracker";
const char *const config_element_process_attr_tracker_vgid = "vgid_process_attr_tracker";
const char *const config_element_process_attr_trackers = "process_attr_trackers";
const char *const config_element_process_attr_values = "process_attr_values";
const char *const config_element_process_attr_value_type = "process_attr_value_type";
const char *const config_element_process_attr_pid_value = "pid";
const char *const config_element_process_attr_vpid_value = "vpid";
const char *const config_element_process_attr_uid_value = "uid";
const char *const config_element_process_attr_vuid_value = "vuid";
const char *const config_element_process_attr_gid_value = "gid";
const char *const config_element_process_attr_vgid_value = "vgid";
const char *const config_element_process_attr_tracker_type = "process_attr_tracker_type";

/* Used for support of legacy tracker serialization (< 2.12). */
const char *const config_element_trackers_legacy = "trackers";
const char *const config_element_pid_tracker_legacy = "pid_tracker";
const char *const config_element_tracker_targets_legacy = "targets";
const char *const config_element_tracker_pid_legacy = "pid";

const char *const config_element_rotation_schedules = "rotation_schedules";
const char *const config_element_rotation_schedule_periodic = "periodic";
const char *const config_element_rotation_schedule_periodic_time_us = "time_us";
const char *const config_element_rotation_schedule_size_threshold = "size_threshold";
const char *const config_element_rotation_schedule_size_threshold_bytes = "bytes";

const char *const config_domain_type_kernel = "KERNEL";
const char *const config_domain_type_ust = "UST";
const char *const config_domain_type_jul = "JUL";
const char *const config_domain_type_log4j = "LOG4J";
const char *const config_domain_type_python = "PYTHON";

const char *const config_buffer_type_per_pid = "PER_PID";
const char *const config_buffer_type_per_uid = "PER_UID";
const char *const config_buffer_type_global = "GLOBAL";

const char *const config_overwrite_mode_discard = "DISCARD";
const char *const config_overwrite_mode_overwrite = "OVERWRITE";

const char *const config_output_type_splice = "SPLICE";
const char *const config_output_type_mmap = "MMAP";

const char *const config_loglevel_type_all = "ALL";
const char *const config_loglevel_type_range = "RANGE";
const char *const config_loglevel_type_single = "SINGLE";

const char *const config_event_type_all = "ALL";
const char *const config_event_type_tracepoint = "TRACEPOINT";
const char *const config_event_type_probe = "PROBE";
const char *const config_event_type_userspace_probe = "USERSPACE_PROBE";
const char *const config_event_type_function = "FUNCTION";
const char *const config_event_type_function_entry = "FUNCTION_ENTRY";
const char *const config_event_type_noop = "NOOP";
const char *const config_event_type_syscall = "SYSCALL";
const char *const config_event_type_kprobe = "KPROBE";
const char *const config_event_type_kretprobe = "KRETPROBE";

const char *const config_event_context_pid = "PID";
const char *const config_event_context_procname = "PROCNAME";
const char *const config_event_context_prio = "PRIO";
const char *const config_event_context_nice = "NICE";
const char *const config_event_context_vpid = "VPID";
const char *const config_event_context_tid = "TID";
const char *const config_event_context_vtid = "VTID";
const char *const config_event_context_ppid = "PPID";
const char *const config_event_context_vppid = "VPPID";
const char *const config_event_context_pthread_id = "PTHREAD_ID";
const char *const config_event_context_hostname = "HOSTNAME";
const char *const config_event_context_ip = "IP";
const char *const config_event_context_perf_thread_counter = "PERF_THREAD_COUNTER";
const char *const config_event_context_app = "APP";
const char *const config_event_context_interruptible = "INTERRUPTIBLE";
const char *const config_event_context_preemptible = "PREEMPTIBLE";
const char *const config_event_context_need_reschedule = "NEED_RESCHEDULE";
const char *const config_event_context_migratable = "MIGRATABLE";
const char *const config_event_context_callstack_user = "CALLSTACK_USER";
const char *const config_event_context_callstack_kernel = "CALLSTACK_KERNEL";
const char *const config_event_context_cgroup_ns = "CGROUP_NS";
const char *const config_event_context_ipc_ns = "IPC_NS";
const char *const config_event_context_mnt_ns = "MNT_NS";
const char *const config_event_context_net_ns = "NET_NS";
const char *const config_event_context_pid_ns = "PID_NS";
const char *const config_event_context_time_ns = "TIME_NS";
const char *const config_event_context_user_ns = "USER_NS";
const char *const config_event_context_uts_ns = "UTS_NS";
const char *const config_event_context_uid = "UID";
const char *const config_event_context_euid = "EUID";
const char *const config_event_context_suid = "SUID";
const char *const config_event_context_gid = "GID";
const char *const config_event_context_egid = "EGID";
const char *const config_event_context_sgid = "SGID";
const char *const config_event_context_vuid = "VUID";
const char *const config_event_context_veuid = "VEUID";
const char *const config_event_context_vsuid = "VSUID";
const char *const config_event_context_vgid = "VGID";
const char *const config_event_context_vegid = "VEGID";
const char *const config_event_context_vsgid = "VSGID";

/* Deprecated symbols */
LTTNG_EXPORT const char *config_element_perf;

enum process_event_node_phase {
	CREATION = 0,
	ENABLE = 1,
};

namespace {
struct consumer_output {
	int enabled;
	char *path;
	char *control_uri;
	char *data_uri;
};
} /* namespace */

/*
 * Returns a xmlChar string which must be released using xmlFree().
 */
static xmlChar *encode_string(const char *in_str)
{
	xmlChar *out_str = nullptr;
	xmlCharEncodingHandlerPtr handler;
	int out_len, ret, in_len;

	LTTNG_ASSERT(in_str);

	handler = xmlFindCharEncodingHandler(config_xml_encoding);
	if (!handler) {
		ERR("xmlFindCharEncodingHandler return NULL!. Configure issue!");
		goto end;
	}

	in_len = strlen(in_str);
	/*
	 * Add 1 byte for the NULL terminted character. The factor 4 here is
	 * used because UTF-8 characters can take up to 4 bytes.
	 */
	out_len = (in_len * 4) + 1;
	out_str = (xmlChar *) xmlMalloc(out_len);
	if (!out_str) {
		goto end;
	}

	ret = handler->input(out_str, &out_len, (const xmlChar *) in_str, &in_len);
	if (ret < 0) {
		xmlFree(out_str);
		out_str = nullptr;
		goto end;
	}

	/* out_len is now the size of out_str */
	out_str[out_len] = '\0';
end:
	return out_str;
}

struct config_writer *config_writer_create(int fd_output, int indent)
{
	int ret;
	struct config_writer *writer;
	xmlOutputBufferPtr buffer;

	writer = zmalloc<config_writer>();
	if (!writer) {
		PERROR("zmalloc config_writer_create");
		goto end;
	}

	buffer = xmlOutputBufferCreateFd(fd_output, nullptr);
	if (!buffer) {
		goto error_destroy;
	}

	writer->writer = xmlNewTextWriter(buffer);
	ret = xmlTextWriterStartDocument(writer->writer, nullptr, config_xml_encoding, nullptr);
	if (ret < 0) {
		goto error_destroy;
	}

	ret = xmlTextWriterSetIndentString(writer->writer, BAD_CAST config_xml_indent_string);
	if (ret) {
		goto error_destroy;
	}

	ret = xmlTextWriterSetIndent(writer->writer, indent);
	if (ret) {
		goto error_destroy;
	}

end:
	return writer;
error_destroy:
	config_writer_destroy(writer);
	return nullptr;
}

int config_writer_destroy(struct config_writer *writer)
{
	int ret = 0;

	if (!writer) {
		ret = -EINVAL;
		goto end;
	}

	if (xmlTextWriterEndDocument(writer->writer) < 0) {
		WARN("Could not close XML document");
		ret = -EIO;
	}

	if (writer->writer) {
		xmlFreeTextWriter(writer->writer);
	}

	free(writer);
end:
	return ret;
}

int config_writer_open_element(struct config_writer *writer, const char *element_name)
{
	int ret;
	xmlChar *encoded_element_name;

	if (!writer || !writer->writer || !element_name || !element_name[0]) {
		ret = -1;
		goto end;
	}

	encoded_element_name = encode_string(element_name);
	if (!encoded_element_name) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterStartElement(writer->writer, encoded_element_name);
	xmlFree(encoded_element_name);
end:
	return ret >= 0 ? 0 : ret;
}

int config_writer_write_attribute(struct config_writer *writer, const char *name, const char *value)
{
	int ret;
	xmlChar *encoded_name = nullptr;
	xmlChar *encoded_value = nullptr;

	if (!writer || !writer->writer || !name || !name[0]) {
		ret = -1;
		goto end;
	}

	encoded_name = encode_string(name);
	if (!encoded_name) {
		ret = -1;
		goto end;
	}

	encoded_value = encode_string(value);
	if (!encoded_value) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterWriteAttribute(writer->writer, encoded_name, encoded_value);
end:
	xmlFree(encoded_name);
	xmlFree(encoded_value);
	return ret >= 0 ? 0 : ret;
}

int config_writer_close_element(struct config_writer *writer)
{
	int ret;

	if (!writer || !writer->writer) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterEndElement(writer->writer);
end:
	return ret >= 0 ? 0 : ret;
}

int config_writer_write_element_unsigned_int(struct config_writer *writer,
					     const char *element_name,
					     uint64_t value)
{
	int ret;
	xmlChar *encoded_element_name;

	if (!writer || !writer->writer || !element_name || !element_name[0]) {
		ret = -1;
		goto end;
	}

	encoded_element_name = encode_string(element_name);
	if (!encoded_element_name) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterWriteFormatElement(
		writer->writer, encoded_element_name, "%" PRIu64, value);
	xmlFree(encoded_element_name);
end:
	return ret >= 0 ? 0 : ret;
}

int config_writer_write_element_signed_int(struct config_writer *writer,
					   const char *element_name,
					   int64_t value)
{
	int ret;
	xmlChar *encoded_element_name;

	if (!writer || !writer->writer || !element_name || !element_name[0]) {
		ret = -1;
		goto end;
	}

	encoded_element_name = encode_string(element_name);
	if (!encoded_element_name) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterWriteFormatElement(
		writer->writer, encoded_element_name, "%" PRIi64, value);
	xmlFree(encoded_element_name);
end:
	return ret >= 0 ? 0 : ret;
}

int config_writer_write_element_bool(struct config_writer *writer,
				     const char *element_name,
				     int value)
{
	return config_writer_write_element_string(
		writer, element_name, value ? config_xml_true : config_xml_false);
}

int config_writer_write_element_double(struct config_writer *writer,
				       const char *element_name,
				       double value)
{
	int ret;
	xmlChar *encoded_element_name;

	if (!writer || !writer->writer || !element_name || !element_name[0]) {
		ret = -1;
		goto end;
	}

	encoded_element_name = encode_string(element_name);
	if (!encoded_element_name) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterWriteFormatElement(writer->writer, encoded_element_name, "%f", value);
	xmlFree(encoded_element_name);
end:
	return ret >= 0 ? 0 : ret;
}

int config_writer_write_element_string(struct config_writer *writer,
				       const char *element_name,
				       const char *value)
{
	int ret;
	xmlChar *encoded_element_name = nullptr;
	xmlChar *encoded_value = nullptr;

	if (!writer || !writer->writer || !element_name || !element_name[0] || !value) {
		ret = -1;
		goto end;
	}

	encoded_element_name = encode_string(element_name);
	if (!encoded_element_name) {
		ret = -1;
		goto end;
	}

	encoded_value = encode_string(value);
	if (!encoded_value) {
		ret = -1;
		goto end;
	}

	ret = xmlTextWriterWriteElement(writer->writer, encoded_element_name, encoded_value);
end:
	xmlFree(encoded_element_name);
	xmlFree(encoded_value);
	return ret >= 0 ? 0 : ret;
}

static ATTR_FORMAT_PRINTF(2, 3) void xml_error_handler(void *ctx __attribute__((unused)),
						       const char *format,
						       ...)
{
	char *errMsg;
	va_list args;
	int ret;

	va_start(args, format);
	ret = vasprintf(&errMsg, format, args);
	va_end(args);
	if (ret == -1) {
		ERR("String allocation failed in xml error handler");
		return;
	}

	fprintf(stderr, "XML Error: %s", errMsg);
	free(errMsg);
}

static void fini_session_config_validation_ctx(struct session_config_validation_ctx *ctx)
{
	if (ctx->parser_ctx) {
		xmlSchemaFreeParserCtxt(ctx->parser_ctx);
	}

	if (ctx->schema) {
		xmlSchemaFree(ctx->schema);
	}

	if (ctx->schema_validation_ctx) {
		xmlSchemaFreeValidCtxt(ctx->schema_validation_ctx);
	}

	memset(ctx, 0, sizeof(struct session_config_validation_ctx));
}

static char *get_session_config_xsd_path()
{
	char *xsd_path;
	const char *base_path = lttng_secure_getenv(DEFAULT_SESSION_CONFIG_XSD_PATH_ENV);
	size_t base_path_len;
	size_t max_path_len;

	if (!base_path) {
		base_path = DEFAULT_SESSION_CONFIG_XSD_PATH;
	}

	base_path_len = strlen(base_path);
	max_path_len = base_path_len + sizeof(DEFAULT_SESSION_CONFIG_XSD_FILENAME) + 1;
	xsd_path = zmalloc<char>(max_path_len);
	if (!xsd_path) {
		goto end;
	}

	strcpy(xsd_path, base_path);
	if (xsd_path[base_path_len - 1] != '/') {
		xsd_path[base_path_len++] = '/';
	}

	strcpy(xsd_path + base_path_len, DEFAULT_SESSION_CONFIG_XSD_FILENAME);
end:
	return xsd_path;
}

static int init_session_config_validation_ctx(struct session_config_validation_ctx *ctx)
{
	int ret;
	char *xsd_path = get_session_config_xsd_path();

	if (!xsd_path) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ctx->parser_ctx = xmlSchemaNewParserCtxt(xsd_path);
	if (!ctx->parser_ctx) {
		ERR("XSD parser context creation failed");
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}
	xmlSchemaSetParserErrors(ctx->parser_ctx, xml_error_handler, xml_error_handler, nullptr);

	ctx->schema = xmlSchemaParse(ctx->parser_ctx);
	if (!ctx->schema) {
		ERR("XSD parsing failed");
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	ctx->schema_validation_ctx = xmlSchemaNewValidCtxt(ctx->schema);
	if (!ctx->schema_validation_ctx) {
		ERR("XSD validation context creation failed");
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	xmlSchemaSetValidErrors(
		ctx->schema_validation_ctx, xml_error_handler, xml_error_handler, nullptr);
	ret = 0;

end:
	if (ret) {
		fini_session_config_validation_ctx(ctx);
	}

	free(xsd_path);
	return ret;
}

static int parse_uint(xmlChar *str, uint64_t *val)
{
	int ret;
	char *endptr;

	if (!str || !val) {
		ret = -1;
		goto end;
	}

	*val = strtoull((const char *) str, &endptr, 10);
	if (!endptr || *endptr) {
		ret = -1;
	} else {
		ret = 0;
	}

end:
	return ret;
}

static int parse_int(xmlChar *str, int64_t *val)
{
	int ret;
	char *endptr;

	if (!str || !val) {
		ret = -1;
		goto end;
	}

	*val = strtoll((const char *) str, &endptr, 10);
	if (!endptr || *endptr) {
		ret = -1;
	} else {
		ret = 0;
	}

end:
	return ret;
}

static int parse_bool(xmlChar *str, int *val)
{
	int ret = 0;

	if (!str || !val) {
		ret = -1;
		goto end;
	}

	if (!strcmp((const char *) str, config_xml_true) || !strcmp((const char *) str, "1")) {
		*val = 1;
	} else if (!strcmp((const char *) str, config_xml_false) ||
		   !strcmp((const char *) str, "0")) {
		*val = 0;
	} else {
		WARN("Invalid boolean value encountered (%s).", (const char *) str);
		ret = -1;
	}
end:
	return ret;
}

static int get_domain_type(xmlChar *domain)
{
	int ret;

	if (!domain) {
		goto error;
	}

	if (!strcmp((char *) domain, config_domain_type_kernel)) {
		ret = LTTNG_DOMAIN_KERNEL;
	} else if (!strcmp((char *) domain, config_domain_type_ust)) {
		ret = LTTNG_DOMAIN_UST;
	} else if (!strcmp((char *) domain, config_domain_type_jul)) {
		ret = LTTNG_DOMAIN_JUL;
	} else if (!strcmp((char *) domain, config_domain_type_log4j)) {
		ret = LTTNG_DOMAIN_LOG4J;
	} else if (!strcmp((char *) domain, config_domain_type_python)) {
		ret = LTTNG_DOMAIN_PYTHON;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static int get_buffer_type(xmlChar *buffer_type)
{
	int ret;

	if (!buffer_type) {
		goto error;
	}

	if (!strcmp((char *) buffer_type, config_buffer_type_global)) {
		ret = LTTNG_BUFFER_GLOBAL;
	} else if (!strcmp((char *) buffer_type, config_buffer_type_per_uid)) {
		ret = LTTNG_BUFFER_PER_UID;
	} else if (!strcmp((char *) buffer_type, config_buffer_type_per_pid)) {
		ret = LTTNG_BUFFER_PER_PID;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static int get_overwrite_mode(xmlChar *overwrite_mode)
{
	int ret;

	if (!overwrite_mode) {
		goto error;
	}

	if (!strcmp((char *) overwrite_mode, config_overwrite_mode_overwrite)) {
		ret = 1;
	} else if (!strcmp((char *) overwrite_mode, config_overwrite_mode_discard)) {
		ret = 0;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static int get_output_type(xmlChar *output_type)
{
	int ret;

	if (!output_type) {
		goto error;
	}

	if (!strcmp((char *) output_type, config_output_type_mmap)) {
		ret = LTTNG_EVENT_MMAP;
	} else if (!strcmp((char *) output_type, config_output_type_splice)) {
		ret = LTTNG_EVENT_SPLICE;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static int get_event_type(xmlChar *event_type)
{
	int ret;

	if (!event_type) {
		goto error;
	}

	if (!strcmp((char *) event_type, config_event_type_all)) {
		ret = LTTNG_EVENT_ALL;
	} else if (!strcmp((char *) event_type, config_event_type_tracepoint)) {
		ret = LTTNG_EVENT_TRACEPOINT;
	} else if (!strcmp((char *) event_type, config_event_type_probe)) {
		ret = LTTNG_EVENT_PROBE;
	} else if (!strcmp((char *) event_type, config_event_type_userspace_probe)) {
		ret = LTTNG_EVENT_USERSPACE_PROBE;
	} else if (!strcmp((char *) event_type, config_event_type_function)) {
		ret = LTTNG_EVENT_FUNCTION;
	} else if (!strcmp((char *) event_type, config_event_type_function_entry)) {
		ret = LTTNG_EVENT_FUNCTION_ENTRY;
	} else if (!strcmp((char *) event_type, config_event_type_noop)) {
		ret = LTTNG_EVENT_NOOP;
	} else if (!strcmp((char *) event_type, config_event_type_syscall)) {
		ret = LTTNG_EVENT_SYSCALL;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static int get_loglevel_type(xmlChar *loglevel_type)
{
	int ret;

	if (!loglevel_type) {
		goto error;
	}

	if (!strcmp((char *) loglevel_type, config_loglevel_type_all)) {
		ret = LTTNG_EVENT_LOGLEVEL_ALL;
	} else if (!strcmp((char *) loglevel_type, config_loglevel_type_range)) {
		ret = LTTNG_EVENT_LOGLEVEL_RANGE;
	} else if (!strcmp((char *) loglevel_type, config_loglevel_type_single)) {
		ret = LTTNG_EVENT_LOGLEVEL_SINGLE;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

/*
 * Return the context type or -1 on error.
 */
static int get_context_type(xmlChar *context_type)
{
	int ret;

	if (!context_type) {
		goto error;
	}

	if (!strcmp((char *) context_type, config_event_context_pid)) {
		ret = LTTNG_EVENT_CONTEXT_PID;
	} else if (!strcmp((char *) context_type, config_event_context_procname)) {
		ret = LTTNG_EVENT_CONTEXT_PROCNAME;
	} else if (!strcmp((char *) context_type, config_event_context_prio)) {
		ret = LTTNG_EVENT_CONTEXT_PRIO;
	} else if (!strcmp((char *) context_type, config_event_context_nice)) {
		ret = LTTNG_EVENT_CONTEXT_NICE;
	} else if (!strcmp((char *) context_type, config_event_context_vpid)) {
		ret = LTTNG_EVENT_CONTEXT_VPID;
	} else if (!strcmp((char *) context_type, config_event_context_tid)) {
		ret = LTTNG_EVENT_CONTEXT_TID;
	} else if (!strcmp((char *) context_type, config_event_context_vtid)) {
		ret = LTTNG_EVENT_CONTEXT_VTID;
	} else if (!strcmp((char *) context_type, config_event_context_ppid)) {
		ret = LTTNG_EVENT_CONTEXT_PPID;
	} else if (!strcmp((char *) context_type, config_event_context_vppid)) {
		ret = LTTNG_EVENT_CONTEXT_VPPID;
	} else if (!strcmp((char *) context_type, config_event_context_pthread_id)) {
		ret = LTTNG_EVENT_CONTEXT_PTHREAD_ID;
	} else if (!strcmp((char *) context_type, config_event_context_hostname)) {
		ret = LTTNG_EVENT_CONTEXT_HOSTNAME;
	} else if (!strcmp((char *) context_type, config_event_context_ip)) {
		ret = LTTNG_EVENT_CONTEXT_IP;
	} else if (!strcmp((char *) context_type, config_event_context_interruptible)) {
		ret = LTTNG_EVENT_CONTEXT_INTERRUPTIBLE;
	} else if (!strcmp((char *) context_type, config_event_context_preemptible)) {
		ret = LTTNG_EVENT_CONTEXT_PREEMPTIBLE;
	} else if (!strcmp((char *) context_type, config_event_context_need_reschedule)) {
		ret = LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE;
	} else if (!strcmp((char *) context_type, config_event_context_migratable)) {
		ret = LTTNG_EVENT_CONTEXT_MIGRATABLE;
	} else if (!strcmp((char *) context_type, config_event_context_callstack_user)) {
		ret = LTTNG_EVENT_CONTEXT_CALLSTACK_USER;
	} else if (!strcmp((char *) context_type, config_event_context_callstack_kernel)) {
		ret = LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL;
	} else if (!strcmp((char *) context_type, config_event_context_cgroup_ns)) {
		ret = LTTNG_EVENT_CONTEXT_CGROUP_NS;
	} else if (!strcmp((char *) context_type, config_event_context_ipc_ns)) {
		ret = LTTNG_EVENT_CONTEXT_IPC_NS;
	} else if (!strcmp((char *) context_type, config_event_context_mnt_ns)) {
		ret = LTTNG_EVENT_CONTEXT_MNT_NS;
	} else if (!strcmp((char *) context_type, config_event_context_net_ns)) {
		ret = LTTNG_EVENT_CONTEXT_NET_NS;
	} else if (!strcmp((char *) context_type, config_event_context_pid_ns)) {
		ret = LTTNG_EVENT_CONTEXT_PID_NS;
	} else if (!strcmp((char *) context_type, config_event_context_time_ns)) {
		ret = LTTNG_EVENT_CONTEXT_TIME_NS;
	} else if (!strcmp((char *) context_type, config_event_context_user_ns)) {
		ret = LTTNG_EVENT_CONTEXT_USER_NS;
	} else if (!strcmp((char *) context_type, config_event_context_uts_ns)) {
		ret = LTTNG_EVENT_CONTEXT_UTS_NS;
	} else if (!strcmp((char *) context_type, config_event_context_uid)) {
		ret = LTTNG_EVENT_CONTEXT_UID;
	} else if (!strcmp((char *) context_type, config_event_context_euid)) {
		ret = LTTNG_EVENT_CONTEXT_EUID;
	} else if (!strcmp((char *) context_type, config_event_context_suid)) {
		ret = LTTNG_EVENT_CONTEXT_SUID;
	} else if (!strcmp((char *) context_type, config_event_context_gid)) {
		ret = LTTNG_EVENT_CONTEXT_GID;
	} else if (!strcmp((char *) context_type, config_event_context_egid)) {
		ret = LTTNG_EVENT_CONTEXT_EGID;
	} else if (!strcmp((char *) context_type, config_event_context_sgid)) {
		ret = LTTNG_EVENT_CONTEXT_SGID;
	} else if (!strcmp((char *) context_type, config_event_context_vuid)) {
		ret = LTTNG_EVENT_CONTEXT_VUID;
	} else if (!strcmp((char *) context_type, config_event_context_veuid)) {
		ret = LTTNG_EVENT_CONTEXT_VEUID;
	} else if (!strcmp((char *) context_type, config_event_context_vsuid)) {
		ret = LTTNG_EVENT_CONTEXT_VSUID;
	} else if (!strcmp((char *) context_type, config_event_context_vgid)) {
		ret = LTTNG_EVENT_CONTEXT_VGID;
	} else if (!strcmp((char *) context_type, config_event_context_vegid)) {
		ret = LTTNG_EVENT_CONTEXT_VEGID;
	} else if (!strcmp((char *) context_type, config_event_context_vsgid)) {
		ret = LTTNG_EVENT_CONTEXT_VSGID;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static int init_domain(xmlNodePtr domain_node, struct lttng_domain *domain)
{
	int ret;
	xmlNodePtr node;

	for (node = xmlFirstElementChild(domain_node); node; node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_type)) {
			/* domain type */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = get_domain_type(node_content);
			free(node_content);
			if (ret < 0) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			domain->type = (lttng_domain_type) ret;
		} else if (!strcmp((const char *) node->name, config_element_buffer_type)) {
			/* buffer type */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = get_buffer_type(node_content);
			free(node_content);
			if (ret < 0) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			domain->buf_type = (lttng_buffer_type) ret;
		}
	}
	ret = 0;
end:
	return ret;
}

static int get_net_output_uris(xmlNodePtr net_output_node, char **control_uri, char **data_uri)
{
	xmlNodePtr node;

	for (node = xmlFirstElementChild(net_output_node); node;
	     node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_control_uri)) {
			/* control_uri */
			*control_uri = (char *) xmlNodeGetContent(node);
			if (!*control_uri) {
				break;
			}
		} else {
			/* data_uri */
			*data_uri = (char *) xmlNodeGetContent(node);
			if (!*data_uri) {
				break;
			}
		}
	}

	return *control_uri || *data_uri ? 0 : -LTTNG_ERR_LOAD_INVALID_CONFIG;
}

static int process_consumer_output(xmlNodePtr consumer_output_node, struct consumer_output *output)
{
	int ret;
	xmlNodePtr node;

	LTTNG_ASSERT(output);

	for (node = xmlFirstElementChild(consumer_output_node); node;
	     node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_enabled)) {
			xmlChar *enabled_str = xmlNodeGetContent(node);

			/* enabled */
			if (!enabled_str) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = parse_bool(enabled_str, &output->enabled);
			free(enabled_str);
			if (ret) {
				goto end;
			}
		} else {
			xmlNodePtr output_type_node;

			/* destination */
			output_type_node = xmlFirstElementChild(node);
			if (!output_type_node) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			if (!strcmp((const char *) output_type_node->name, config_element_path)) {
				/* path */
				output->path = (char *) xmlNodeGetContent(output_type_node);
				if (!output->path) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}
			} else {
				/* net_output */
				ret = get_net_output_uris(
					output_type_node, &output->control_uri, &output->data_uri);
				if (ret) {
					goto end;
				}
			}
		}
	}
	ret = 0;

end:
	if (ret) {
		free(output->path);
		free(output->control_uri);
		free(output->data_uri);
		memset(output, 0, sizeof(struct consumer_output));
	}
	return ret;
}

static int create_snapshot_session(const char *session_name,
				   xmlNodePtr output_node,
				   const struct config_load_session_override_attr *overrides)
{
	int ret;
	enum lttng_error_code ret_code;
	xmlNodePtr node = nullptr;
	xmlNodePtr snapshot_output_list_node;
	xmlNodePtr snapshot_output_node;
	struct lttng_session_descriptor *session_descriptor = nullptr;

	LTTNG_ASSERT(session_name);
	LTTNG_ASSERT(output_node);

	/*
	 * Use a descriptor without output since consumer output size is not
	 * exposed by the session descriptor api.
	 */
	session_descriptor = lttng_session_descriptor_snapshot_create(session_name);
	if (session_descriptor == nullptr) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ret_code = lttng_create_session_ext(session_descriptor);
	if (ret_code != LTTNG_OK) {
		ret = -ret_code;
		goto end;
	}

	snapshot_output_list_node = xmlFirstElementChild(output_node);

	/* Parse and create snapshot outputs */
	for (snapshot_output_node = xmlFirstElementChild(snapshot_output_list_node);
	     snapshot_output_node;
	     snapshot_output_node = xmlNextElementSibling(snapshot_output_node)) {
		char *name = nullptr;
		uint64_t max_size = UINT64_MAX;
		struct consumer_output output = {};
		struct lttng_snapshot_output *snapshot_output = nullptr;
		const char *control_uri = nullptr;
		const char *data_uri = nullptr;
		const char *path = nullptr;

		for (node = xmlFirstElementChild(snapshot_output_node); node;
		     node = xmlNextElementSibling(node)) {
			if (!strcmp((const char *) node->name, config_element_name)) {
				/* name */
				name = (char *) xmlNodeGetContent(node);
				if (!name) {
					ret = -LTTNG_ERR_NOMEM;
					goto error_snapshot_output;
				}
			} else if (!strcmp((const char *) node->name, config_element_max_size)) {
				xmlChar *content = xmlNodeGetContent(node);

				/* max_size */
				if (!content) {
					ret = -LTTNG_ERR_NOMEM;
					goto error_snapshot_output;
				}
				ret = parse_uint(content, &max_size);
				free(content);
				if (ret) {
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto error_snapshot_output;
				}
			} else {
				/* consumer_output */
				ret = process_consumer_output(node, &output);
				if (ret) {
					goto error_snapshot_output;
				}
			}
		}

		control_uri = output.control_uri;
		data_uri = output.data_uri;
		path = output.path;

		if (overrides) {
			if (overrides->path_url) {
				path = overrides->path_url;
				/* Control/data_uri are null */
				control_uri = nullptr;
				data_uri = nullptr;
			} else {
				if (overrides->ctrl_url) {
					control_uri = overrides->ctrl_url;
					/* path is null */
					path = nullptr;
				}
				if (overrides->data_url) {
					data_uri = overrides->data_url;
					/* path is null */
					path = nullptr;
				}
			}
		}

		snapshot_output = lttng_snapshot_output_create();
		if (!snapshot_output) {
			ret = -LTTNG_ERR_NOMEM;
			goto error_snapshot_output;
		}

		ret = lttng_snapshot_output_set_name(name, snapshot_output);
		if (ret) {
			goto error_snapshot_output;
		}

		ret = lttng_snapshot_output_set_size(max_size, snapshot_output);
		if (ret) {
			goto error_snapshot_output;
		}

		if (path) {
			ret = lttng_snapshot_output_set_ctrl_url(path, snapshot_output);
			if (ret) {
				goto error_snapshot_output;
			}
		} else {
			if (control_uri) {
				ret = lttng_snapshot_output_set_ctrl_url(control_uri,
									 snapshot_output);
				if (ret) {
					goto error_snapshot_output;
				}
			}

			if (data_uri) {
				ret = lttng_snapshot_output_set_data_url(data_uri, snapshot_output);
				if (ret) {
					goto error_snapshot_output;
				}
			}
		}

		ret = lttng_snapshot_add_output(session_name, snapshot_output);
	error_snapshot_output:
		free(name);
		free(output.path);
		free(output.control_uri);
		free(output.data_uri);
		lttng_snapshot_output_destroy(snapshot_output);
		if (ret) {
			goto end;
		}
	}
end:
	lttng_session_descriptor_destroy(session_descriptor);
	return ret;
}

static int create_session(const char *name,
			  xmlNodePtr output_node,
			  uint64_t live_timer_interval,
			  const struct config_load_session_override_attr *overrides)
{
	int ret = 0;
	enum lttng_error_code ret_code;
	struct consumer_output output = {};
	xmlNodePtr consumer_output_node;
	const char *control_uri = nullptr;
	const char *data_uri = nullptr;
	const char *path = nullptr;
	struct lttng_session_descriptor *session_descriptor = nullptr;

	LTTNG_ASSERT(name);

	if (output_node) {
		consumer_output_node = xmlFirstElementChild(output_node);
		if (!consumer_output_node) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		if (strcmp((const char *) consumer_output_node->name,
			   config_element_consumer_output)) {
			WARN("Invalid output type, expected %s node",
			     config_element_consumer_output);
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		ret = process_consumer_output(consumer_output_node, &output);
		if (ret) {
			goto end;
		}
	}

	control_uri = output.control_uri;
	data_uri = output.data_uri;
	path = output.path;

	/* Check for override and apply them */
	if (overrides) {
		if (overrides->path_url) {
			path = overrides->path_url;
			/* control/data_uri are null */;
			control_uri = nullptr;
			data_uri = nullptr;
		} else {
			if (overrides->ctrl_url) {
				control_uri = overrides->ctrl_url;
				/* path is null */
				path = nullptr;
			}
			if (overrides->data_url) {
				data_uri = overrides->data_url;
				/* path is null */
				path = nullptr;
			}
		}
	}

	if (live_timer_interval != UINT64_MAX && !control_uri && !data_uri) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	if (control_uri || data_uri) {
		/* network destination */
		if (live_timer_interval && live_timer_interval != UINT64_MAX) {
			/*
			 * URLs are provided for sure since the test above make sure that
			 * with a live timer the data and control URIs are provided. So,
			 * NULL is passed here and will be set right after.
			 */
			session_descriptor = lttng_session_descriptor_live_network_create(
				name, control_uri, data_uri, live_timer_interval);
		} else {
			session_descriptor = lttng_session_descriptor_network_create(
				name, control_uri, data_uri);
		}

	} else if (path != nullptr) {
		session_descriptor = lttng_session_descriptor_local_create(name, path);
	} else {
		/* No output */
		session_descriptor = lttng_session_descriptor_create(name);
	}

	if (session_descriptor == nullptr) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	ret_code = lttng_create_session_ext(session_descriptor);
	if (ret_code != LTTNG_OK) {
		ret = -ret_code;
		goto end;
	}

end:
	free(output.path);
	free(output.control_uri);
	free(output.data_uri);
	lttng_session_descriptor_destroy(session_descriptor);
	return ret;
}

static struct lttng_userspace_probe_location *
process_userspace_probe_function_attribute_node(xmlNodePtr attribute_node)
{
	xmlNodePtr function_attribute_node;
	char *function_name = nullptr, *binary_path = nullptr;
	struct lttng_userspace_probe_location *location = nullptr;
	struct lttng_userspace_probe_location_lookup_method *lookup_method = nullptr;

	/*
	 * Process userspace probe location function attributes. The order of
	 * the fields are not guaranteed so we need to iterate over all fields
	 * and check at the end if everything we need for this location type is
	 * there.
	 */
	for (function_attribute_node = xmlFirstElementChild(attribute_node);
	     function_attribute_node;
	     function_attribute_node = xmlNextElementSibling(function_attribute_node)) {
		/* Handle function name, binary path and lookup method. */
		if (!strcmp((const char *) function_attribute_node->name,
			    config_element_userspace_probe_function_location_function_name)) {
			function_name = (char *) xmlNodeGetContent(function_attribute_node);
			if (!function_name) {
				goto error;
			}
		} else if (!strcmp((const char *) function_attribute_node->name,
				   config_element_userspace_probe_location_binary_path)) {
			binary_path = (char *) xmlNodeGetContent(function_attribute_node);
			if (!binary_path) {
				goto error;
			}
		} else if (!strcmp((const char *) function_attribute_node->name,
				   config_element_userspace_probe_lookup)) {
			char *lookup_method_name;

			lookup_method_name = (char *) xmlNodeGetContent(function_attribute_node);
			if (!lookup_method_name) {
				goto error;
			}

			/*
			 * function_default lookup method defaults to
			 * function_elf lookup method at the moment.
			 */
			if (!strcmp(lookup_method_name,
				    config_element_userspace_probe_lookup_function_elf) ||
			    !strcmp(lookup_method_name,
				    config_element_userspace_probe_lookup_function_default)) {
				lookup_method =
					lttng_userspace_probe_location_lookup_method_function_elf_create();
				if (!lookup_method) {
					PERROR("Error creating function default/ELF lookup method");
				}
			} else {
				WARN("Unknown function lookup method");
			}

			free(lookup_method_name);
			if (!lookup_method) {
				goto error;
			}
		} else {
			goto error;
		}

		/* Check if all the necessary fields were found. */
		if (binary_path && function_name && lookup_method) {
			/* Ownership of lookup_method is transferred. */
			location = lttng_userspace_probe_location_function_create(
				binary_path, function_name, lookup_method);
			lookup_method = nullptr;
			goto error;
		}
	}
error:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
	free(binary_path);
	free(function_name);
	return location;
}

static struct lttng_userspace_probe_location *
process_userspace_probe_tracepoint_attribute_node(xmlNodePtr attribute_node)
{
	xmlNodePtr tracepoint_attribute_node;
	char *probe_name = nullptr, *provider_name = nullptr, *binary_path = nullptr;
	struct lttng_userspace_probe_location *location = nullptr;
	struct lttng_userspace_probe_location_lookup_method *lookup_method = nullptr;

	/*
	 * Process userspace probe location tracepoint attributes. The order of
	 * the fields are not guaranteed so we need to iterate over all fields
	 * and check at the end if everything we need for this location type is
	 * there.
	 */
	for (tracepoint_attribute_node = xmlFirstElementChild(attribute_node);
	     tracepoint_attribute_node;
	     tracepoint_attribute_node = xmlNextElementSibling(tracepoint_attribute_node)) {
		if (!strcmp((const char *) tracepoint_attribute_node->name,
			    config_element_userspace_probe_tracepoint_location_probe_name)) {
			probe_name = (char *) xmlNodeGetContent(tracepoint_attribute_node);
			if (!probe_name) {
				goto error;
			}
		} else if (!strcmp((const char *) tracepoint_attribute_node->name,
				   config_element_userspace_probe_tracepoint_location_provider_name)) {
			provider_name = (char *) xmlNodeGetContent(tracepoint_attribute_node);
			if (!provider_name) {
				goto error;
			}
		} else if (!strcmp((const char *) tracepoint_attribute_node->name,
				   config_element_userspace_probe_location_binary_path)) {
			binary_path = (char *) xmlNodeGetContent(tracepoint_attribute_node);
			if (!binary_path) {
				goto error;
			}
		} else if (!strcmp((const char *) tracepoint_attribute_node->name,
				   config_element_userspace_probe_lookup)) {
			char *lookup_method_name;

			lookup_method_name = (char *) xmlNodeGetContent(tracepoint_attribute_node);
			if (!lookup_method_name) {
				goto error;
			}

			if (!strcmp(lookup_method_name,
				    config_element_userspace_probe_lookup_tracepoint_sdt)) {
				lookup_method =
					lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create();
				if (!lookup_method) {
					PERROR("Error creating tracepoint SDT lookup method");
				}
			} else {
				WARN("Unknown tracepoint lookup method");
			}

			free(lookup_method_name);
			if (!lookup_method) {
				goto error;
			}
		} else {
			WARN("Unknown tracepoint attribute");
			goto error;
		}

		/* Check if all the necessary fields were found. */
		if (binary_path && provider_name && probe_name && lookup_method) {
			/* Ownership of lookup_method is transferred. */
			location = lttng_userspace_probe_location_tracepoint_create(
				binary_path, provider_name, probe_name, lookup_method);
			lookup_method = nullptr;
			goto error;
		}
	}
error:
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
	free(binary_path);
	free(provider_name);
	free(probe_name);
	return location;
}

static int process_probe_attribute_node(xmlNodePtr probe_attribute_node,
					struct lttng_event_probe_attr *attr)
{
	int ret;

	LTTNG_ASSERT(probe_attribute_node);
	LTTNG_ASSERT(attr);

	if (!strcmp((const char *) probe_attribute_node->name, config_element_address)) {
		xmlChar *content;
		uint64_t addr = 0;

		/* addr */
		content = xmlNodeGetContent(probe_attribute_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &addr);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		attr->addr = addr;
	} else if (!strcmp((const char *) probe_attribute_node->name, config_element_offset)) {
		xmlChar *content;
		uint64_t offset = 0;

		/* offset */
		content = xmlNodeGetContent(probe_attribute_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &offset);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		attr->offset = offset;
	} else if (!strcmp((const char *) probe_attribute_node->name, config_element_symbol_name)) {
		xmlChar *content;

		/* symbol_name */
		content = xmlNodeGetContent(probe_attribute_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = lttng_strncpy(
			attr->symbol_name, (const char *) content, LTTNG_SYMBOL_NAME_LEN);
		if (ret == -1) {
			ERR("symbol name \"%s\"'s length (%zu) exceeds the maximal permitted length (%d) in session configuration",
			    (const char *) content,
			    strlen((const char *) content),
			    LTTNG_SYMBOL_NAME_LEN);
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			free(content);
			goto end;
		}
		free(content);
	}
	ret = 0;
end:
	return ret;
}

static int process_event_node(xmlNodePtr event_node,
			      struct lttng_handle *handle,
			      const char *channel_name,
			      const enum process_event_node_phase phase)
{
	int ret = 0, i;
	xmlNodePtr node;
	struct lttng_event *event;
	char **exclusions = nullptr;
	unsigned long exclusion_count = 0;
	char *filter_expression = nullptr;

	LTTNG_ASSERT(event_node);
	LTTNG_ASSERT(handle);
	LTTNG_ASSERT(channel_name);

	event = lttng_event_create();
	if (!event) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Initialize default log level which varies by domain */
	switch (handle->domain.type) {
	case LTTNG_DOMAIN_JUL:
		event->loglevel = LTTNG_LOGLEVEL_JUL_ALL;
		break;
	case LTTNG_DOMAIN_LOG4J:
		event->loglevel = LTTNG_LOGLEVEL_LOG4J_ALL;
		break;
	case LTTNG_DOMAIN_PYTHON:
		event->loglevel = LTTNG_LOGLEVEL_PYTHON_DEBUG;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_KERNEL:
		event->loglevel = LTTNG_LOGLEVEL_DEBUG;
		break;
	default:
		abort();
	}

	for (node = xmlFirstElementChild(event_node); node; node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_name)) {
			xmlChar *content;

			/* name */
			content = xmlNodeGetContent(node);
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = lttng_strncpy(
				event->name, (const char *) content, LTTNG_SYMBOL_NAME_LEN);
			if (ret == -1) {
				WARN("Event \"%s\"'s name length (%zu) exceeds the maximal permitted length (%d) in session configuration",
				     (const char *) content,
				     strlen((const char *) content),
				     LTTNG_SYMBOL_NAME_LEN);
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				free(content);
				goto end;
			}
			free(content);
		} else if (!strcmp((const char *) node->name, config_element_enabled)) {
			xmlChar *content = xmlNodeGetContent(node);

			/* enabled */
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = parse_bool(content, &event->enabled);
			free(content);
			if (ret) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}
		} else if (!strcmp((const char *) node->name, config_element_type)) {
			xmlChar *content = xmlNodeGetContent(node);

			/* type */
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = get_event_type(content);
			free(content);
			if (ret < 0) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			event->type = (lttng_event_type) ret;
		} else if (!strcmp((const char *) node->name, config_element_loglevel_type)) {
			xmlChar *content = xmlNodeGetContent(node);

			/* loglevel_type */
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = get_loglevel_type(content);
			free(content);
			if (ret < 0) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			event->loglevel_type = (lttng_loglevel_type) ret;
		} else if (!strcmp((const char *) node->name, config_element_loglevel)) {
			xmlChar *content;
			int64_t loglevel = 0;

			/* loglevel */
			content = xmlNodeGetContent(node);
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = parse_int(content, &loglevel);
			free(content);
			if (ret) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			if (loglevel > INT_MAX || loglevel < INT_MIN) {
				WARN("loglevel out of range.");
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			event->loglevel = loglevel;
		} else if (!strcmp((const char *) node->name, config_element_filter)) {
			xmlChar *content = xmlNodeGetContent(node);

			/* filter */
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			free(filter_expression);
			filter_expression = strdup((char *) content);
			free(content);
			if (!filter_expression) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}
		} else if (!strcmp((const char *) node->name, config_element_exclusions)) {
			xmlNodePtr exclusion_node;
			int exclusion_index = 0;

			/* exclusions */
			if (exclusions) {
				/*
				 * Exclusions has already been initialized,
				 * invalid file.
				 */
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			exclusion_count = xmlChildElementCount(node);
			if (!exclusion_count) {
				continue;
			}

			exclusions = calloc<char *>(exclusion_count);
			if (!exclusions) {
				exclusion_count = 0;
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			for (exclusion_node = xmlFirstElementChild(node); exclusion_node;
			     exclusion_node = xmlNextElementSibling(exclusion_node)) {
				xmlChar *content = xmlNodeGetContent(exclusion_node);

				if (!content) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}

				exclusions[exclusion_index] = strdup((const char *) content);
				free(content);
				if (!exclusions[exclusion_index]) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}
				exclusion_index++;
			}

			event->exclusion = 1;
		} else if (!strcmp((const char *) node->name, config_element_attributes)) {
			xmlNodePtr attribute_node = xmlFirstElementChild(node);

			/* attributes */
			if (!attribute_node) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			if (!strcmp((const char *) attribute_node->name,
				    config_element_probe_attributes)) {
				xmlNodePtr probe_attribute_node;

				/* probe_attributes */
				for (probe_attribute_node = xmlFirstElementChild(attribute_node);
				     probe_attribute_node;
				     probe_attribute_node =
					     xmlNextElementSibling(probe_attribute_node)) {
					ret = process_probe_attribute_node(probe_attribute_node,
									   &event->attr.probe);
					if (ret) {
						goto end;
					}
				}
			} else if (!strcmp((const char *) attribute_node->name,
					   config_element_function_attributes)) {
				size_t sym_len;
				xmlChar *content;
				xmlNodePtr symbol_node = xmlFirstElementChild(attribute_node);

				/* function_attributes */
				content = xmlNodeGetContent(symbol_node);
				if (!content) {
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				sym_len = strlen((char *) content);
				if (sym_len >= LTTNG_SYMBOL_NAME_LEN) {
					WARN("Function name too long.");
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					free(content);
					goto end;
				}

				ret = lttng_strncpy(
					event->attr.ftrace.symbol_name, (char *) content, sym_len);
				if (ret == -1) {
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					free(content);
					goto end;
				}
				free(content);
			} else if (!strcmp((const char *) attribute_node->name,
					   config_element_userspace_probe_tracepoint_attributes)) {
				struct lttng_userspace_probe_location *location;

				location = process_userspace_probe_tracepoint_attribute_node(
					attribute_node);
				if (!location) {
					WARN("Error processing userspace probe tracepoint attribute");
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}
				ret = lttng_event_set_userspace_probe_location(event, location);
				if (ret) {
					WARN("Error setting userspace probe location field");
					lttng_userspace_probe_location_destroy(location);
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}
			} else if (!strcmp((const char *) attribute_node->name,
					   config_element_userspace_probe_function_attributes)) {
				struct lttng_userspace_probe_location *location;

				location = process_userspace_probe_function_attribute_node(
					attribute_node);
				if (!location) {
					WARN("Error processing userspace probe function attribute");
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				ret = lttng_event_set_userspace_probe_location(event, location);
				if (ret) {
					WARN("Error setting userspace probe location field");
					lttng_userspace_probe_location_destroy(location);
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}
			} else {
				/* Unknown event attribute. */
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}
		}
	}

	if ((event->enabled && phase == ENABLE) || phase == CREATION) {
		ret = lttng_enable_event_with_exclusions(
			handle, event, channel_name, filter_expression, exclusion_count, exclusions);
		if (ret < 0) {
			WARN("Enabling event (name:%s) on load failed.", event->name);
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	}
	ret = 0;
end:
	for (i = 0; i < exclusion_count; i++) {
		free(exclusions[i]);
	}

	lttng_event_destroy(event);
	free(exclusions);
	free(filter_expression);
	return ret;
}

static int
process_events_node(xmlNodePtr events_node, struct lttng_handle *handle, const char *channel_name)
{
	int ret = 0;
	struct lttng_event event;
	xmlNodePtr node;

	LTTNG_ASSERT(events_node);
	LTTNG_ASSERT(handle);
	LTTNG_ASSERT(channel_name);

	for (node = xmlFirstElementChild(events_node); node; node = xmlNextElementSibling(node)) {
		ret = process_event_node(node, handle, channel_name, CREATION);
		if (ret) {
			goto end;
		}
	}

	/*
	 * Disable all events to enable only the necessary events.
	 * Limitations regarding lttng_disable_events and tuple descriptor
	 * force this approach.
	 */
	memset(&event, 0, sizeof(event));
	event.loglevel = -1;
	event.type = LTTNG_EVENT_ALL;
	ret = lttng_disable_event_ext(handle, &event, channel_name, nullptr);
	if (ret) {
		goto end;
	}

	for (node = xmlFirstElementChild(events_node); node; node = xmlNextElementSibling(node)) {
		ret = process_event_node(node, handle, channel_name, ENABLE);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static int process_channel_attr_node(xmlNodePtr attr_node,
				     struct lttng_channel *channel,
				     xmlNodePtr *contexts_node,
				     xmlNodePtr *events_node)
{
	int ret;

	LTTNG_ASSERT(attr_node);
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(contexts_node);
	LTTNG_ASSERT(events_node);

	if (!strcmp((const char *) attr_node->name, config_element_name)) {
		xmlChar *content;

		/* name */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = lttng_strncpy(channel->name, (const char *) content, LTTNG_SYMBOL_NAME_LEN);
		if (ret == -1) {
			WARN("Channel \"%s\"'s name length (%zu) exceeds the maximal permitted length (%d) in session configuration",
			     (const char *) content,
			     strlen((const char *) content),
			     LTTNG_SYMBOL_NAME_LEN);
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			free(content);
			goto end;
		}
		free(content);
	} else if (!strcmp((const char *) attr_node->name, config_element_enabled)) {
		xmlChar *content;
		int enabled;

		/* enabled */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_bool(content, &enabled);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		channel->enabled = enabled;
	} else if (!strcmp((const char *) attr_node->name, config_element_overwrite_mode)) {
		xmlChar *content;

		/* overwrite_mode */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = get_overwrite_mode(content);
		free(content);
		if (ret < 0) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		channel->attr.overwrite = ret;
	} else if (!strcmp((const char *) attr_node->name, config_element_subbuf_size)) {
		xmlChar *content;

		/* subbuffer_size */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &channel->attr.subbuf_size);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name, config_element_num_subbuf)) {
		xmlChar *content;

		/* subbuffer_count */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &channel->attr.num_subbuf);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name, config_element_switch_timer_interval)) {
		xmlChar *content;
		uint64_t switch_timer_interval = 0;

		/* switch_timer_interval */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &switch_timer_interval);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		if (switch_timer_interval > UINT_MAX) {
			WARN("switch_timer_interval out of range.");
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		channel->attr.switch_timer_interval = switch_timer_interval;
	} else if (!strcmp((const char *) attr_node->name, config_element_read_timer_interval)) {
		xmlChar *content;
		uint64_t read_timer_interval = 0;

		/* read_timer_interval */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &read_timer_interval);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		if (read_timer_interval > UINT_MAX) {
			WARN("read_timer_interval out of range.");
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		channel->attr.read_timer_interval = read_timer_interval;
	} else if (!strcmp((const char *) attr_node->name, config_element_output_type)) {
		xmlChar *content;

		/* output_type */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = get_output_type(content);
		free(content);
		if (ret < 0) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		channel->attr.output = (lttng_event_output) ret;
	} else if (!strcmp((const char *) attr_node->name, config_element_tracefile_size)) {
		xmlChar *content;

		/* tracefile_size */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &channel->attr.tracefile_size);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name, config_element_tracefile_count)) {
		xmlChar *content;

		/* tracefile_count */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &channel->attr.tracefile_count);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name, config_element_live_timer_interval)) {
		xmlChar *content;
		uint64_t live_timer_interval = 0;

		/* live_timer_interval */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &live_timer_interval);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		if (live_timer_interval > UINT_MAX) {
			WARN("live_timer_interval out of range.");
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		channel->attr.live_timer_interval = live_timer_interval;
	} else if (!strcmp((const char *) attr_node->name, config_element_monitor_timer_interval)) {
		xmlChar *content;
		uint64_t monitor_timer_interval = 0;

		/* monitor_timer_interval */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_uint(content, &monitor_timer_interval);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		ret = lttng_channel_set_monitor_timer_interval(channel, monitor_timer_interval);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name, config_element_blocking_timeout)) {
		xmlChar *content;
		int64_t blocking_timeout = 0;

		/* blocking_timeout */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = parse_int(content, &blocking_timeout);
		free(content);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		ret = lttng_channel_set_blocking_timeout(channel, blocking_timeout);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name, config_element_events)) {
		/* events */
		*events_node = attr_node;
	} else {
		/* contexts */
		*contexts_node = attr_node;
	}
	ret = 0;
end:
	return ret;
}

static int
process_context_node(xmlNodePtr context_node, struct lttng_handle *handle, const char *channel_name)
{
	int ret;
	struct lttng_event_context context;
	xmlNodePtr context_child_node = xmlFirstElementChild(context_node);

	LTTNG_ASSERT(handle);
	LTTNG_ASSERT(channel_name);

	if (!context_child_node) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	memset(&context, 0, sizeof(context));

	if (!strcmp((const char *) context_child_node->name, config_element_type)) {
		/* type */
		xmlChar *content = xmlNodeGetContent(context_child_node);

		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = get_context_type(content);
		free(content);
		if (ret < 0) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}

		context.ctx = (lttng_event_context_type) ret;
	} else if (!strcmp((const char *) context_child_node->name, config_element_context_perf)) {
		/* perf */
		xmlNodePtr perf_attr_node;

		context.ctx = handle->domain.type == LTTNG_DOMAIN_KERNEL ?
			LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER :
			LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER;
		for (perf_attr_node = xmlFirstElementChild(context_child_node); perf_attr_node;
		     perf_attr_node = xmlNextElementSibling(perf_attr_node)) {
			if (!strcmp((const char *) perf_attr_node->name, config_element_type)) {
				xmlChar *content;
				uint64_t type = 0;

				/* type */
				content = xmlNodeGetContent(perf_attr_node);
				if (!content) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}

				ret = parse_uint(content, &type);
				free(content);
				if (ret) {
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				if (type > UINT32_MAX) {
					WARN("perf context type out of range.");
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				context.u.perf_counter.type = type;
			} else if (!strcmp((const char *) perf_attr_node->name,
					   config_element_config)) {
				xmlChar *content;
				uint64_t config = 0;

				/* config */
				content = xmlNodeGetContent(perf_attr_node);
				if (!content) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}

				ret = parse_uint(content, &config);
				free(content);
				if (ret) {
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				context.u.perf_counter.config = config;
			} else if (!strcmp((const char *) perf_attr_node->name,
					   config_element_name)) {
				xmlChar *content;

				/* name */
				content = xmlNodeGetContent(perf_attr_node);
				if (!content) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}

				ret = lttng_strncpy(context.u.perf_counter.name,
						    (const char *) content,
						    LTTNG_SYMBOL_NAME_LEN);
				if (ret == -1) {
					WARN("Perf counter \"%s\"'s name length (%zu) exceeds the maximal permitted length (%d) in session configuration",
					     (const char *) content,
					     strlen((const char *) content),
					     LTTNG_SYMBOL_NAME_LEN);
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					free(content);
					goto end;
				}
				free(content);
			}
		}
	} else if (!strcmp((const char *) context_child_node->name, config_element_context_app)) {
		/* application context */
		xmlNodePtr app_ctx_node;

		context.ctx = LTTNG_EVENT_CONTEXT_APP_CONTEXT;
		for (app_ctx_node = xmlFirstElementChild(context_child_node); app_ctx_node;
		     app_ctx_node = xmlNextElementSibling(app_ctx_node)) {
			xmlChar *content;
			char **target = strcmp((const char *) app_ctx_node->name,
					       config_element_context_app_provider_name) == 0 ?
				&context.u.app_ctx.provider_name :
				&context.u.app_ctx.ctx_name;

			content = xmlNodeGetContent(app_ctx_node);
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			*target = (char *) content;
		}
	} else {
		/* Unrecognized context type */
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	ret = lttng_add_context(handle, &context, nullptr, channel_name);
	if (context.ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		free(context.u.app_ctx.provider_name);
		free(context.u.app_ctx.ctx_name);
	}
end:
	return ret;
}

static int process_contexts_node(xmlNodePtr contexts_node,
				 struct lttng_handle *handle,
				 const char *channel_name)
{
	int ret = 0;
	xmlNodePtr context_node;

	for (context_node = xmlFirstElementChild(contexts_node); context_node;
	     context_node = xmlNextElementSibling(context_node)) {
		ret = process_context_node(context_node, handle, channel_name);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

static int get_tracker_elements(enum lttng_process_attr process_attr,
				const char **element_id_tracker,
				const char **element_value_type,
				const char **element_value,
				const char **element_value_alias,
				const char **element_name)
{
	int ret = 0;

	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		*element_id_tracker = config_element_process_attr_tracker_pid;
		*element_value_type = config_element_process_attr_pid_value;
		*element_value = config_element_process_attr_id;
		*element_value_alias = config_element_process_attr_id;
		*element_name = nullptr;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		*element_id_tracker = config_element_process_attr_tracker_vpid;
		*element_value_type = config_element_process_attr_vpid_value;
		*element_value = config_element_process_attr_id;
		*element_value_alias = nullptr;
		*element_name = nullptr;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
		*element_id_tracker = config_element_process_attr_tracker_uid;
		*element_value_type = config_element_process_attr_uid_value;
		*element_value = config_element_process_attr_id;
		*element_value_alias = nullptr;
		*element_name = config_element_name;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		*element_id_tracker = config_element_process_attr_tracker_vuid;
		*element_value_type = config_element_process_attr_vuid_value;
		*element_value = config_element_process_attr_id;
		*element_value_alias = nullptr;
		*element_name = config_element_name;
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		*element_id_tracker = config_element_process_attr_tracker_gid;
		*element_value_type = config_element_process_attr_gid_value;
		*element_value = config_element_process_attr_id;
		*element_value_alias = nullptr;
		*element_name = config_element_name;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		*element_id_tracker = config_element_process_attr_tracker_vgid;
		*element_value_type = config_element_process_attr_vgid_value;
		*element_value = config_element_process_attr_id;
		*element_value_alias = nullptr;
		*element_name = config_element_name;
		break;
	default:
		ret = LTTNG_ERR_INVALID;
	}
	return ret;
}

static int process_legacy_pid_tracker_node(xmlNodePtr trackers_node, struct lttng_handle *handle)
{
	int ret = 0, child_count;
	xmlNodePtr targets_node = nullptr;
	xmlNodePtr node;
	const char *element_id_tracker;
	const char *element_target_id;
	const char *element_id;
	const char *element_id_alias;
	const char *element_name;
	enum lttng_error_code tracker_handle_ret_code;
	struct lttng_process_attr_tracker_handle *tracker_handle = nullptr;
	enum lttng_process_attr_tracker_handle_status status;
	const enum lttng_process_attr process_attr = handle->domain.type == LTTNG_DOMAIN_UST ?
		LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID :
		LTTNG_PROCESS_ATTR_PROCESS_ID;

	LTTNG_ASSERT(handle);

	tracker_handle_ret_code = lttng_session_get_tracker_handle(
		handle->session_name, handle->domain.type, process_attr, &tracker_handle);
	if (tracker_handle_ret_code != LTTNG_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = get_tracker_elements(process_attr,
				   &element_id_tracker,
				   &element_target_id,
				   &element_id,
				   &element_id_alias,
				   &element_name);
	if (ret) {
		goto end;
	}

	/* Get the targets node */
	for (node = xmlFirstElementChild(trackers_node); node; node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_tracker_targets_legacy)) {
			targets_node = node;
			break;
		}
	}

	if (!targets_node) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* Go through all id target node */
	child_count = xmlChildElementCount(targets_node);
	status = lttng_process_attr_tracker_handle_set_tracking_policy(
		tracker_handle,
		child_count == 0 ? LTTNG_TRACKING_POLICY_EXCLUDE_ALL :
				   LTTNG_TRACKING_POLICY_INCLUDE_SET);
	if (status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
		ret = LTTNG_ERR_UNK;
		goto end;
	}

	/* Add all tracked values. */
	for (node = xmlFirstElementChild(targets_node); node; node = xmlNextElementSibling(node)) {
		xmlNodePtr pid_target_node = node;

		/* get pid_target node and track it */
		for (node = xmlFirstElementChild(pid_target_node); node;
		     node = xmlNextElementSibling(node)) {
			if (!strcmp((const char *) node->name, config_element_tracker_pid_legacy)) {
				int64_t id;
				xmlChar *content = xmlNodeGetContent(node);

				if (!content) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				ret = parse_int(content, &id);
				free(content);
				if (ret) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				switch (process_attr) {
				case LTTNG_PROCESS_ATTR_PROCESS_ID:
					status =
						lttng_process_attr_process_id_tracker_handle_add_pid(
							tracker_handle, (pid_t) id);
					break;
				case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
					status =
						lttng_process_attr_virtual_process_id_tracker_handle_add_pid(
							tracker_handle, (pid_t) id);
					break;
				default:
					ret = LTTNG_ERR_INVALID;
					goto end;
				}
			}
			switch (status) {
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
				continue;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID:
				ret = LTTNG_ERR_INVALID;
				break;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS:
				ret = LTTNG_ERR_PROCESS_ATTR_EXISTS;
				break;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING:
				ret = LTTNG_ERR_PROCESS_ATTR_MISSING;
				break;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR:
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR:
			default:
				ret = LTTNG_ERR_UNK;
				goto end;
			}
		}
		node = pid_target_node;
	}

end:
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return ret;
}

static int process_id_tracker_node(xmlNodePtr id_tracker_node,
				   struct lttng_handle *handle,
				   enum lttng_process_attr process_attr)
{
	int ret = 0, child_count;
	xmlNodePtr values_node = nullptr;
	xmlNodePtr node;
	const char *element_id_tracker;
	const char *element_target_id;
	const char *element_id;
	const char *element_id_alias;
	const char *element_name;
	enum lttng_error_code tracker_handle_ret_code;
	struct lttng_process_attr_tracker_handle *tracker_handle = nullptr;
	enum lttng_process_attr_tracker_handle_status status;

	LTTNG_ASSERT(handle);
	LTTNG_ASSERT(id_tracker_node);

	tracker_handle_ret_code = lttng_session_get_tracker_handle(
		handle->session_name, handle->domain.type, process_attr, &tracker_handle);
	if (tracker_handle_ret_code != LTTNG_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = get_tracker_elements(process_attr,
				   &element_id_tracker,
				   &element_target_id,
				   &element_id,
				   &element_id_alias,
				   &element_name);
	if (ret) {
		goto end;
	}

	/* get the values node */
	for (node = xmlFirstElementChild(id_tracker_node); node;
	     node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_process_attr_values)) {
			values_node = node;
			break;
		}
	}

	if (!values_node) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* Go through all id target node */
	child_count = xmlChildElementCount(values_node);
	status = lttng_process_attr_tracker_handle_set_tracking_policy(
		tracker_handle,
		child_count == 0 ? LTTNG_TRACKING_POLICY_EXCLUDE_ALL :
				   LTTNG_TRACKING_POLICY_INCLUDE_SET);
	if (status != LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
		ret = LTTNG_ERR_UNK;
		goto end;
	}

	/* Add all tracked values. */
	for (node = xmlFirstElementChild(values_node); node; node = xmlNextElementSibling(node)) {
		xmlNodePtr id_target_node = node;

		/* get id node and track it */
		for (node = xmlFirstElementChild(id_target_node); node;
		     node = xmlNextElementSibling(node)) {
			if (!strcmp((const char *) node->name, element_id) ||
			    (element_id_alias &&
			     !strcmp((const char *) node->name, element_id_alias))) {
				int64_t id;
				xmlChar *content = xmlNodeGetContent(node);

				if (!content) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				ret = parse_int(content, &id);
				free(content);
				if (ret) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				switch (process_attr) {
				case LTTNG_PROCESS_ATTR_PROCESS_ID:
					status =
						lttng_process_attr_process_id_tracker_handle_add_pid(
							tracker_handle, (pid_t) id);
					break;
				case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
					status =
						lttng_process_attr_virtual_process_id_tracker_handle_add_pid(
							tracker_handle, (pid_t) id);
					break;
				case LTTNG_PROCESS_ATTR_USER_ID:
					status = lttng_process_attr_user_id_tracker_handle_add_uid(
						tracker_handle, (uid_t) id);
					break;
				case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
					status =
						lttng_process_attr_virtual_user_id_tracker_handle_add_uid(
							tracker_handle, (uid_t) id);
					break;
				case LTTNG_PROCESS_ATTR_GROUP_ID:
					status = lttng_process_attr_group_id_tracker_handle_add_gid(
						tracker_handle, (gid_t) id);
					break;
				case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
					status =
						lttng_process_attr_virtual_group_id_tracker_handle_add_gid(
							tracker_handle, (gid_t) id);
					break;
				default:
					ret = LTTNG_ERR_INVALID;
					goto end;
				}
			} else if (element_name &&
				   !strcmp((const char *) node->name, element_name)) {
				xmlChar *content = xmlNodeGetContent(node);

				if (!content) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				switch (process_attr) {
				case LTTNG_PROCESS_ATTR_USER_ID:
					status =
						lttng_process_attr_user_id_tracker_handle_add_user_name(
							tracker_handle, (const char *) content);
					break;
				case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
					status =
						lttng_process_attr_virtual_user_id_tracker_handle_add_user_name(
							tracker_handle, (const char *) content);
					break;
				case LTTNG_PROCESS_ATTR_GROUP_ID:
					status =
						lttng_process_attr_group_id_tracker_handle_add_group_name(
							tracker_handle, (const char *) content);
					break;
				case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
					status =
						lttng_process_attr_virtual_group_id_tracker_handle_add_group_name(
							tracker_handle, (const char *) content);
					break;
				default:
					free(content);
					ret = LTTNG_ERR_INVALID;
					goto end;
				}
				free(content);
			}
			switch (status) {
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
				continue;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID:
				ret = LTTNG_ERR_INVALID;
				break;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_EXISTS:
				ret = LTTNG_ERR_PROCESS_ATTR_EXISTS;
				break;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_MISSING:
				ret = LTTNG_ERR_PROCESS_ATTR_MISSING;
				break;
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_ERROR:
			case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR:
			default:
				ret = LTTNG_ERR_UNK;
				goto end;
			}
		}
		node = id_target_node;
	}

end:
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return ret;
}

static int process_domain_node(xmlNodePtr domain_node, const char *session_name)
{
	int ret;
	struct lttng_domain domain {};
	struct lttng_handle *handle = nullptr;
	struct lttng_channel *channel = nullptr;
	xmlNodePtr channels_node = nullptr;
	xmlNodePtr trackers_node = nullptr;
	xmlNodePtr pid_tracker_node = nullptr;
	xmlNodePtr vpid_tracker_node = nullptr;
	xmlNodePtr uid_tracker_node = nullptr;
	xmlNodePtr vuid_tracker_node = nullptr;
	xmlNodePtr gid_tracker_node = nullptr;
	xmlNodePtr vgid_tracker_node = nullptr;
	xmlNodePtr node;

	LTTNG_ASSERT(session_name);

	ret = init_domain(domain_node, &domain);
	if (ret) {
		goto end;
	}

	handle = lttng_create_handle(session_name, &domain);
	if (!handle) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* get the channels node */
	for (node = xmlFirstElementChild(domain_node); node; node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_channels)) {
			channels_node = node;
			break;
		}
	}

	if (!channels_node) {
		goto end;
	}

	/* create all channels */
	for (node = xmlFirstElementChild(channels_node); node; node = xmlNextElementSibling(node)) {
		const enum lttng_domain_type original_domain = domain.type;
		xmlNodePtr contexts_node = nullptr;
		xmlNodePtr events_node = nullptr;
		xmlNodePtr channel_attr_node;

		/*
		 * Channels of the "agent" types cannot be created directly.
		 * They are meant to be created implicitly through the
		 * activation of events in their domain. However, a user
		 * can override the default channel configuration attributes
		 * by creating the underlying UST channel _before_ enabling
		 * an agent domain event.
		 *
		 * Hence, the channel's type is substituted before the creation
		 * and restored by the time the events are created.
		 */
		switch (domain.type) {
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
			domain.type = LTTNG_DOMAIN_UST;
		default:
			break;
		}

		channel = lttng_channel_create(&domain);
		if (!channel) {
			ret = -1;
			goto end;
		}

		for (channel_attr_node = xmlFirstElementChild(node); channel_attr_node;
		     channel_attr_node = xmlNextElementSibling(channel_attr_node)) {
			ret = process_channel_attr_node(
				channel_attr_node, channel, &contexts_node, &events_node);
			if (ret) {
				goto end;
			}
		}

		ret = lttng_enable_channel(handle, channel);
		if (ret < 0) {
			goto end;
		}

		/* Restore the original channel domain. */
		domain.type = original_domain;

		ret = process_events_node(events_node, handle, channel->name);
		if (ret) {
			goto end;
		}

		ret = process_contexts_node(contexts_node, handle, channel->name);
		if (ret) {
			goto end;
		}

		lttng_channel_destroy(channel);
	}
	channel = nullptr;

	/* get the trackers node */
	for (node = xmlFirstElementChild(domain_node); node; node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_process_attr_trackers) ||
		    !strcmp((const char *) node->name, config_element_trackers_legacy)) {
			if (trackers_node) {
				ERR("Only one instance of `%s` or `%s` is allowed in a session configuration",
				    config_element_process_attr_trackers,
				    config_element_trackers_legacy);
				ret = -1;
				goto end;
			}
			trackers_node = node;
			break;
		}
	}

	if (!trackers_node) {
		goto end;
	}

	for (node = xmlFirstElementChild(trackers_node); node; node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_process_attr_tracker_pid)) {
			pid_tracker_node = node;
			ret = process_id_tracker_node(
				pid_tracker_node, handle, LTTNG_PROCESS_ATTR_PROCESS_ID);
			if (ret) {
				goto end;
			}
		}
		if (!strcmp((const char *) node->name, config_element_process_attr_tracker_vpid)) {
			vpid_tracker_node = node;
			ret = process_id_tracker_node(
				vpid_tracker_node, handle, LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
			if (ret) {
				goto end;
			}
		}
		if (!strcmp((const char *) node->name, config_element_process_attr_tracker_uid)) {
			uid_tracker_node = node;
			ret = process_id_tracker_node(
				uid_tracker_node, handle, LTTNG_PROCESS_ATTR_USER_ID);
			if (ret) {
				goto end;
			}
		}
		if (!strcmp((const char *) node->name, config_element_process_attr_tracker_vuid)) {
			vuid_tracker_node = node;
			ret = process_id_tracker_node(
				vuid_tracker_node, handle, LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
			if (ret) {
				goto end;
			}
		}
		if (!strcmp((const char *) node->name, config_element_process_attr_tracker_gid)) {
			gid_tracker_node = node;
			ret = process_id_tracker_node(
				gid_tracker_node, handle, LTTNG_PROCESS_ATTR_GROUP_ID);
			if (ret) {
				goto end;
			}
		}
		if (!strcmp((const char *) node->name, config_element_process_attr_tracker_vgid)) {
			vgid_tracker_node = node;
			ret = process_id_tracker_node(
				vgid_tracker_node, handle, LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
			if (ret) {
				goto end;
			}
		}
		if (!strcmp((const char *) node->name, config_element_pid_tracker_legacy)) {
			ret = process_legacy_pid_tracker_node(node, handle);
			if (ret) {
				goto end;
			}
		}
	}

end:
	lttng_channel_destroy(channel);
	lttng_destroy_handle(handle);
	return ret;
}

static int add_periodic_rotation(const char *name, uint64_t time_us)
{
	int ret;
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *periodic = lttng_rotation_schedule_periodic_create();

	if (!periodic) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	status = lttng_rotation_schedule_periodic_set_period(periodic, time_us);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	status = lttng_session_add_rotation_schedule(name, periodic);
	switch (status) {
	case LTTNG_ROTATION_STATUS_OK:
		ret = 0;
		break;
	case LTTNG_ROTATION_STATUS_SCHEDULE_ALREADY_SET:
	case LTTNG_ROTATION_STATUS_INVALID:
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		break;
	default:
		ret = -LTTNG_ERR_UNK;
		break;
	}
error:
	lttng_rotation_schedule_destroy(periodic);
	return ret;
}

static int add_size_rotation(const char *name, uint64_t size_bytes)
{
	int ret;
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *size = lttng_rotation_schedule_size_threshold_create();

	if (!size) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	status = lttng_rotation_schedule_size_threshold_set_threshold(size, size_bytes);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	status = lttng_session_add_rotation_schedule(name, size);
	switch (status) {
	case LTTNG_ROTATION_STATUS_OK:
		ret = 0;
		break;
	case LTTNG_ROTATION_STATUS_SCHEDULE_ALREADY_SET:
	case LTTNG_ROTATION_STATUS_INVALID:
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		break;
	default:
		ret = -LTTNG_ERR_UNK;
		break;
	}
error:
	lttng_rotation_schedule_destroy(size);
	return ret;
}

static int process_session_rotation_schedules_node(xmlNodePtr schedules_node,
						   uint64_t *rotation_timer_interval,
						   uint64_t *rotation_size)
{
	int ret = 0;
	xmlNodePtr child;

	for (child = xmlFirstElementChild(schedules_node); child;
	     child = xmlNextElementSibling(child)) {
		if (!strcmp((const char *) child->name,
			    config_element_rotation_schedule_periodic)) {
			xmlChar *content;
			xmlNodePtr time_us_node;

			/* periodic rotation schedule */
			time_us_node = xmlFirstElementChild(child);
			if (!time_us_node ||
			    strcmp((const char *) time_us_node->name,
				   config_element_rotation_schedule_periodic_time_us)) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			/* time_us child */
			content = xmlNodeGetContent(time_us_node);
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}
			ret = parse_uint(content, rotation_timer_interval);
			free(content);
			if (ret) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}
		} else if (!strcmp((const char *) child->name,
				   config_element_rotation_schedule_size_threshold)) {
			xmlChar *content;
			xmlNodePtr bytes_node;

			/* size_threshold rotation schedule */
			bytes_node = xmlFirstElementChild(child);
			if (!bytes_node ||
			    strcmp((const char *) bytes_node->name,
				   config_element_rotation_schedule_size_threshold_bytes)) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			/* bytes child */
			content = xmlNodeGetContent(bytes_node);
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}
			ret = parse_uint(content, rotation_size);
			free(content);
			if (ret) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}
		}
	}

end:
	return ret;
}

static int process_session_node(xmlNodePtr session_node,
				const char *session_name,
				int overwrite,
				const struct config_load_session_override_attr *overrides)
{
	int ret, started = -1, snapshot_mode = -1;
	uint64_t live_timer_interval = UINT64_MAX, rotation_timer_interval = 0, rotation_size = 0;
	xmlChar *name = nullptr;
	xmlChar *shm_path = nullptr;
	xmlNodePtr domains_node = nullptr;
	xmlNodePtr output_node = nullptr;
	xmlNodePtr node;
	xmlNodePtr attributes_child;
	struct lttng_domain *kernel_domain = nullptr;
	struct lttng_domain *ust_domain = nullptr;
	struct lttng_domain *jul_domain = nullptr;
	struct lttng_domain *log4j_domain = nullptr;
	struct lttng_domain *python_domain = nullptr;

	for (node = xmlFirstElementChild(session_node); node; node = xmlNextElementSibling(node)) {
		if (!name && !strcmp((const char *) node->name, config_element_name)) {
			/* name */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			name = node_content;
		} else if (!domains_node &&
			   !strcmp((const char *) node->name, config_element_domains)) {
			/* domains */
			domains_node = node;
		} else if (started == -1 &&
			   !strcmp((const char *) node->name, config_element_started)) {
			/* started */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			ret = parse_bool(node_content, &started);
			free(node_content);
			if (ret) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto error;
			}
		} else if (!output_node &&
			   !strcmp((const char *) node->name, config_element_output)) {
			/* output */
			output_node = node;
		} else if (!shm_path &&
			   !strcmp((const char *) node->name, config_element_shared_memory_path)) {
			/* shared memory path */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			shm_path = node_content;
		} else {
			/*
			 * attributes, snapshot_mode, live_timer_interval, rotation_size,
			 * rotation_timer_interval.
			 */
			for (attributes_child = xmlFirstElementChild(node); attributes_child;
			     attributes_child = xmlNextElementSibling(attributes_child)) {
				if (!strcmp((const char *) attributes_child->name,
					    config_element_snapshot_mode)) {
					/* snapshot_mode */
					xmlChar *snapshot_mode_content =
						xmlNodeGetContent(attributes_child);
					if (!snapshot_mode_content) {
						ret = -LTTNG_ERR_NOMEM;
						goto error;
					}

					ret = parse_bool(snapshot_mode_content, &snapshot_mode);
					free(snapshot_mode_content);
					if (ret) {
						ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
						goto error;
					}
				} else if (!strcmp((const char *) attributes_child->name,
						   config_element_live_timer_interval)) {
					/* live_timer_interval */
					xmlChar *timer_interval_content =
						xmlNodeGetContent(attributes_child);
					if (!timer_interval_content) {
						ret = -LTTNG_ERR_NOMEM;
						goto error;
					}

					ret = parse_uint(timer_interval_content,
							 &live_timer_interval);
					free(timer_interval_content);
					if (ret) {
						ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
						goto error;
					}
				} else if (!strcmp((const char *) attributes_child->name,
						   config_element_rotation_schedules)) {
					ret = process_session_rotation_schedules_node(
						attributes_child,
						&rotation_timer_interval,
						&rotation_size);
					if (ret) {
						ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
						goto error;
					}
				}
			}
		}
	}

	if (!name) {
		/* Mandatory attribute, as defined in the session XSD */
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto error;
	}

	if (session_name && strcmp((char *) name, session_name)) {
		/* This is not the session we are looking for */
		ret = -LTTNG_ERR_NO_SESSION;
		goto error;
	}

	/* Init domains to create the session handles */
	for (node = xmlFirstElementChild(domains_node); node; node = xmlNextElementSibling(node)) {
		lttng_domain *domain = zmalloc<lttng_domain>();

		if (!domain) {
			ret = -LTTNG_ERR_NOMEM;
			goto error;
		}

		ret = init_domain(node, domain);
		if (ret) {
			goto domain_init_error;
		}

		switch (domain->type) {
		case LTTNG_DOMAIN_KERNEL:
			if (kernel_domain) {
				/* Same domain seen twice, invalid! */
				goto domain_init_error;
			}
			kernel_domain = domain;
			break;
		case LTTNG_DOMAIN_UST:
			if (ust_domain) {
				/* Same domain seen twice, invalid! */
				goto domain_init_error;
			}
			ust_domain = domain;
			break;
		case LTTNG_DOMAIN_JUL:
			if (jul_domain) {
				/* Same domain seen twice, invalid! */
				goto domain_init_error;
			}
			jul_domain = domain;
			break;
		case LTTNG_DOMAIN_LOG4J:
			if (log4j_domain) {
				/* Same domain seen twice, invalid! */
				goto domain_init_error;
			}
			log4j_domain = domain;
			break;
		case LTTNG_DOMAIN_PYTHON:
			if (python_domain) {
				/* Same domain seen twice, invalid! */
				goto domain_init_error;
			}
			python_domain = domain;
			break;
		default:
			WARN("Invalid domain type");
			goto domain_init_error;
		}
		continue;
	domain_init_error:
		free(domain);
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto error;
	}

	/* Apply overrides */
	if (overrides) {
		if (overrides->session_name) {
			xmlChar *name_override = xmlStrdup(BAD_CAST(overrides->session_name));
			if (!name_override) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			/* Overrides the session name to the provided name */
			xmlFree(name);
			name = name_override;
		}
	}

	if (overwrite) {
		/* Destroy session if it exists */
		ret = lttng_destroy_session((const char *) name);
		if (ret && ret != -LTTNG_ERR_SESS_NOT_FOUND) {
			ERR("Failed to destroy existing session.");
			goto error;
		}
	}

	/* Create session type depending on output type */
	if (snapshot_mode && snapshot_mode != -1) {
		ret = create_snapshot_session((const char *) name, output_node, overrides);
	} else if (live_timer_interval && live_timer_interval != UINT64_MAX) {
		ret = create_session(
			(const char *) name, output_node, live_timer_interval, overrides);
	} else {
		/* regular session */
		ret = create_session((const char *) name, output_node, UINT64_MAX, overrides);
	}
	if (ret) {
		goto error;
	}

	if (shm_path) {
		ret = lttng_set_session_shm_path((const char *) name, (const char *) shm_path);
		if (ret) {
			goto error;
		}
	}

	for (node = xmlFirstElementChild(domains_node); node; node = xmlNextElementSibling(node)) {
		ret = process_domain_node(node, (const char *) name);
		if (ret) {
			goto end;
		}
	}

	if (rotation_timer_interval) {
		ret = add_periodic_rotation((const char *) name, rotation_timer_interval);
		if (ret < 0) {
			goto error;
		}
	}
	if (rotation_size) {
		ret = add_size_rotation((const char *) name, rotation_size);
		if (ret < 0) {
			goto error;
		}
	}

	if (started) {
		ret = lttng_start_tracing((const char *) name);
		if (ret) {
			goto end;
		}
	}

end:
	if (ret < 0) {
		ERR("Failed to load session %s: %s", (const char *) name, lttng_strerror(ret));
		lttng_destroy_session((const char *) name);
	}

error:
	free(kernel_domain);
	free(ust_domain);
	free(jul_domain);
	free(log4j_domain);
	free(python_domain);
	xmlFree(name);
	xmlFree(shm_path);
	return ret;
}

/*
 * Return 1 if the given path is readable by the current UID or 0 if not.
 * Return -1 if the path is EPERM.
 */
static int validate_file_read_creds(const char *path)
{
	int ret;

	LTTNG_ASSERT(path);

	/* Can we read the file. */
	ret = access(path, R_OK);
	if (!ret) {
		goto valid;
	}
	if (errno == EACCES) {
		return -1;
	} else {
		/* Invalid. */
		return 0;
	}
valid:
	return 1;
}

static int load_session_from_file(const char *path,
				  const char *session_name,
				  struct session_config_validation_ctx *validation_ctx,
				  int overwrite,
				  const struct config_load_session_override_attr *overrides)
{
	int ret, session_found = !session_name;
	xmlDocPtr doc = nullptr;
	xmlNodePtr sessions_node;
	xmlNodePtr session_node;

	LTTNG_ASSERT(path);
	LTTNG_ASSERT(validation_ctx);

	ret = validate_file_read_creds(path);
	if (ret != 1) {
		if (ret == -1) {
			ret = -LTTNG_ERR_EPERM;
		} else {
			ret = -LTTNG_ERR_LOAD_SESSION_NOENT;
		}
		goto end;
	}

	doc = xmlParseFile(path);
	if (!doc) {
		ret = -LTTNG_ERR_LOAD_IO_FAIL;
		goto end;
	}

	ret = xmlSchemaValidateDoc(validation_ctx->schema_validation_ctx, doc);
	if (ret) {
		ERR("Session configuration file validation failed");
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	sessions_node = xmlDocGetRootElement(doc);
	if (!sessions_node) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	for (session_node = xmlFirstElementChild(sessions_node); session_node;
	     session_node = xmlNextElementSibling(session_node)) {
		ret = process_session_node(session_node, session_name, overwrite, overrides);
		if (!session_name && ret) {
			/* Loading error occurred. */
			goto end;
		} else if (session_name) {
			if (ret == 0) {
				/* Target session found and loaded */
				session_found = 1;
				break;
			} else if (ret == -LTTNG_ERR_NO_SESSION) {
				/*
				 * Ignore this error, we are looking for a
				 * specific session.
				 */
				ret = 0;
			} else {
				/* Loading error occurred. */
				goto end;
			}
		}
	}
end:
	xmlFreeDoc(doc);
	if (!ret) {
		ret = session_found ? 0 : -LTTNG_ERR_LOAD_SESSION_NOENT;
	}
	return ret;
}

static int load_session_from_path(const char *path,
				  const char *session_name,
				  struct session_config_validation_ctx *validation_ctx,
				  int overwrite,
				  const struct config_load_session_override_attr *overrides)
{
	int ret, session_found = !session_name;
	DIR *directory = nullptr;
	struct lttng_dynamic_buffer file_path;
	size_t path_len;

	LTTNG_ASSERT(path);
	LTTNG_ASSERT(validation_ctx);
	path_len = strlen(path);
	lttng_dynamic_buffer_init(&file_path);
	if (path_len >= LTTNG_PATH_MAX) {
		ERR("Session configuration load path \"%s\" length (%zu) exceeds the maximal length allowed (%d)",
		    path,
		    path_len,
		    LTTNG_PATH_MAX);
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	directory = opendir(path);
	if (!directory) {
		switch (errno) {
		case ENOTDIR:
			/* Try the file loading. */
			break;
		case ENOENT:
			ret = -LTTNG_ERR_LOAD_SESSION_NOENT;
			goto end;
		default:
			ret = -LTTNG_ERR_LOAD_IO_FAIL;
			goto end;
		}
	}
	if (directory) {
		size_t file_path_root_len;

		ret = lttng_dynamic_buffer_set_capacity(&file_path, LTTNG_PATH_MAX);
		if (ret) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = lttng_dynamic_buffer_append(&file_path, path, path_len);
		if (ret) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		if (file_path.data[file_path.size - 1] != '/') {
			ret = lttng_dynamic_buffer_append(&file_path, "/", 1);
			if (ret) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}
		}
		file_path_root_len = file_path.size;

		/* Search for *.lttng files */
		for (;;) {
			size_t file_name_len;
			struct dirent *result;

			/*
			 * When the end of the directory stream is reached, NULL
			 * is returned and errno is kept unchanged. When an
			 * error occurs, NULL is returned and errno is set
			 * accordingly. To distinguish between the two, set
			 * errno to zero before calling readdir().
			 *
			 * On success, readdir() returns a pointer to a dirent
			 * structure. This structure may be statically
			 * allocated, do not attempt to free(3) it.
			 */
			errno = 0;
			result = readdir(directory);

			/* Reached end of dir stream or error out. */
			if (!result) {
				if (errno) {
					PERROR("Failed to enumerate the contents of path \"%s\" while loading session, readdir returned",
					       path);
					ret = -LTTNG_ERR_LOAD_IO_FAIL;
					goto end;
				}
				break;
			}

			file_name_len = strlen(result->d_name);

			if (file_name_len <= sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION)) {
				continue;
			}

			if (file_path.size + file_name_len >= LTTNG_PATH_MAX) {
				WARN("Ignoring file \"%s\" since the path's length (%zu) would exceed the maximal permitted size (%d)",
				     result->d_name,
				     /* +1 to account for NULL terminator. */
				     file_path.size + file_name_len + 1,
				     LTTNG_PATH_MAX);
				continue;
			}

			/* Does the file end with .lttng? */
			if (strcmp(DEFAULT_SESSION_CONFIG_FILE_EXTENSION,
				   result->d_name + file_name_len -
					   sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION) + 1)) {
				continue;
			}

			ret = lttng_dynamic_buffer_append(
				&file_path, result->d_name, file_name_len + 1);
			if (ret) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = load_session_from_file(
				file_path.data, session_name, validation_ctx, overwrite, overrides);
			if (session_name && (!ret || ret != -LTTNG_ERR_LOAD_SESSION_NOENT)) {
				session_found = 1;
				break;
			}
			if (ret && ret != -LTTNG_ERR_LOAD_SESSION_NOENT) {
				goto end;
			}
			/*
			 * Reset the buffer's size to the location of the
			 * path's trailing '/'.
			 */
			ret = lttng_dynamic_buffer_set_size(&file_path, file_path_root_len);
			if (ret) {
				ret = -LTTNG_ERR_UNK;
				goto end;
			}
		}
	} else {
		ret = load_session_from_file(
			path, session_name, validation_ctx, overwrite, overrides);
		if (ret) {
			goto end;
		}
		session_found = 1;
	}

	ret = 0;
end:
	if (directory) {
		if (closedir(directory)) {
			PERROR("closedir");
		}
	}
	if (!ret && !session_found) {
		ret = -LTTNG_ERR_LOAD_SESSION_NOENT;
	}
	lttng_dynamic_buffer_reset(&file_path);
	return ret;
}

/*
 * Validate that the given path's credentials and the current process have the
 * same UID. If so, return 1 else return 0 if it does NOT match.
 */
static int validate_path_creds(const char *path)
{
	int ret, uid = getuid();
	struct stat buf;

	LTTNG_ASSERT(path);

	if (uid == 0) {
		goto valid;
	}

	ret = stat(path, &buf);
	if (ret < 0) {
		if (errno != ENOENT) {
			PERROR("stat");
		}
		goto valid;
	}

	if (buf.st_uid != uid) {
		goto invalid;
	}

valid:
	return 1;
invalid:
	return 0;
}

int config_load_session(const char *path,
			const char *session_name,
			int overwrite,
			unsigned int autoload,
			const struct config_load_session_override_attr *overrides)
{
	int ret;
	bool session_loaded = false;
	const char *path_ptr = nullptr;
	struct session_config_validation_ctx validation_ctx = {};

	ret = init_session_config_validation_ctx(&validation_ctx);
	if (ret) {
		goto end;
	}

	if (!path) {
		const char *home_path;
		const char *sys_path;

		/* Try home path */
		home_path = utils_get_home_dir();
		if (home_path) {
			char path_buf[PATH_MAX];

			/*
			 * Try user session configuration path. Ignore error here so we can
			 * continue loading the system wide sessions.
			 */
			if (autoload) {
				ret = snprintf(path_buf,
					       sizeof(path_buf),
					       DEFAULT_SESSION_HOME_CONFIGPATH
					       "/" DEFAULT_SESSION_CONFIG_AUTOLOAD,
					       home_path);
				if (ret < 0) {
					PERROR("snprintf session autoload home config path");
					ret = -LTTNG_ERR_INVALID;
					goto end;
				}

				/*
				 * Credentials are only validated for the autoload in order to
				 * avoid any user session daemon to try to load kernel sessions
				 * automatically and failing all the times.
				 */
				ret = validate_path_creds(path_buf);
				if (ret) {
					path_ptr = path_buf;
				}
			} else {
				ret = snprintf(path_buf,
					       sizeof(path_buf),
					       DEFAULT_SESSION_HOME_CONFIGPATH,
					       home_path);
				if (ret < 0) {
					PERROR("snprintf session home config path");
					ret = -LTTNG_ERR_INVALID;
					goto end;
				}
				path_ptr = path_buf;
			}
			if (path_ptr) {
				ret = load_session_from_path(path_ptr,
							     session_name,
							     &validation_ctx,
							     overwrite,
							     overrides);
				if (ret && ret != -LTTNG_ERR_LOAD_SESSION_NOENT) {
					goto end;
				}
				/*
				 * Continue even if the session was found since we have to try
				 * the system wide sessions.
				 */
				session_loaded = true;
			}
		}

		/* Reset path pointer for the system wide dir. */
		path_ptr = nullptr;

		/* Try system wide configuration directory. */
		if (autoload) {
			sys_path = DEFAULT_SESSION_SYSTEM_CONFIGPATH
				"/" DEFAULT_SESSION_CONFIG_AUTOLOAD;
			ret = validate_path_creds(sys_path);
			if (ret) {
				path_ptr = sys_path;
			}
		} else {
			sys_path = DEFAULT_SESSION_SYSTEM_CONFIGPATH;
			path_ptr = sys_path;
		}

		if (path_ptr) {
			ret = load_session_from_path(
				path_ptr, session_name, &validation_ctx, overwrite, overrides);
			if (!ret) {
				session_loaded = true;
			}
		} else {
			ret = 0;
		}
	} else {
		ret = access(path, F_OK);
		if (ret < 0) {
			PERROR("access");
			switch (errno) {
			case ENOENT:
				ret = -LTTNG_ERR_INVALID;
				WARN("Session configuration path does not exist.");
				break;
			case EACCES:
				ret = -LTTNG_ERR_EPERM;
				break;
			default:
				ret = -LTTNG_ERR_UNK;
				break;
			}
			goto end;
		}

		ret = load_session_from_path(
			path, session_name, &validation_ctx, overwrite, overrides);
	}
end:
	fini_session_config_validation_ctx(&validation_ctx);
	if (ret == -LTTNG_ERR_LOAD_SESSION_NOENT && !session_name && !path) {
		/*
		 * Don't report an error if no sessions are found when called
		 * without a session_name or a search path.
		 */
		ret = 0;
	}

	if (session_loaded && ret == -LTTNG_ERR_LOAD_SESSION_NOENT) {
		/* A matching session was found in one of the search paths. */
		ret = 0;
	}
	return ret;
}

static void __attribute__((destructor)) session_config_exit()
{
	xmlCleanupParser();
}
