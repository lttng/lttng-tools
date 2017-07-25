/*
 * Copyright (C) 2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#include <common/defaults.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/utils.h>
#include <common/compat/getenv.h>
#include <lttng/lttng-error.h>
#include <libxml/parser.h>
#include <libxml/valid.h>
#include <libxml/xmlschemas.h>
#include <libxml/tree.h>
#include <lttng/lttng.h>
#include <lttng/snapshot.h>

#include "session-config.h"
#include "config-internal.h"

struct handler_filter_args {
	const char* section;
	config_entry_handler_cb handler;
	void *user_data;
};

struct session_config_validation_ctx {
	xmlSchemaParserCtxtPtr parser_ctx;
	xmlSchemaPtr schema;
	xmlSchemaValidCtxtPtr schema_validation_ctx;
};

const char * const config_str_yes = "yes";
const char * const config_str_true = "true";
const char * const config_str_on = "on";
const char * const config_str_no = "no";
const char * const config_str_false = "false";
const char * const config_str_off = "off";
const char * const config_xml_encoding = "UTF-8";
const size_t config_xml_encoding_bytes_per_char = 2;	/* Size of the encoding's largest character */
const char * const config_xml_indent_string = "\t";
const char * const config_xml_true = "true";
const char * const config_xml_false = "false";

const char * const config_element_channel = "channel";
const char * const config_element_channels = "channels";
const char * const config_element_domain = "domain";
const char * const config_element_domains = "domains";
const char * const config_element_event = "event";
const char * const config_element_events = "events";
const char * const config_element_context = "context";
const char * const config_element_contexts = "contexts";
const char * const config_element_attributes = "attributes";
const char * const config_element_exclusion = "exclusion";
const char * const config_element_exclusions = "exclusions";
const char * const config_element_function_attributes = "function_attributes";
const char * const config_element_probe_attributes = "probe_attributes";
const char * const config_element_symbol_name = "symbol_name";
const char * const config_element_address = "address";
const char * const config_element_offset = "offset";
const char * const config_element_name = "name";
const char * const config_element_enabled = "enabled";
const char * const config_element_overwrite_mode = "overwrite_mode";
const char * const config_element_subbuf_size = "subbuffer_size";
const char * const config_element_num_subbuf = "subbuffer_count";
const char * const config_element_switch_timer_interval = "switch_timer_interval";
const char * const config_element_read_timer_interval = "read_timer_interval";
LTTNG_HIDDEN const char * const config_element_monitor_timer_interval = "monitor_timer_interval";
LTTNG_HIDDEN const char * const config_element_blocking_timeout = "blocking_timeout";
const char * const config_element_output = "output";
const char * const config_element_output_type = "output_type";
const char * const config_element_tracefile_size = "tracefile_size";
const char * const config_element_tracefile_count = "tracefile_count";
const char * const config_element_live_timer_interval = "live_timer_interval";
LTTNG_HIDDEN const char * const config_element_discarded_events = "discarded_events";
LTTNG_HIDDEN const char * const config_element_lost_packets = "lost_packets";
const char * const config_element_type = "type";
const char * const config_element_buffer_type = "buffer_type";
const char * const config_element_session = "session";
const char * const config_element_sessions = "sessions";
LTTNG_HIDDEN const char * const config_element_context_perf = "perf";
LTTNG_HIDDEN const char * const config_element_context_app = "app";
LTTNG_HIDDEN const char * const config_element_context_app_provider_name = "provider_name";
LTTNG_HIDDEN const char * const config_element_context_app_ctx_name = "ctx_name";
const char * const config_element_config = "config";
const char * const config_element_started = "started";
const char * const config_element_snapshot_mode = "snapshot_mode";
const char * const config_element_loglevel = "loglevel";
const char * const config_element_loglevel_type = "loglevel_type";
const char * const config_element_filter = "filter";
LTTNG_HIDDEN const char * const config_element_filter_expression = "filter_expression";
const char * const config_element_snapshot_outputs = "snapshot_outputs";
const char * const config_element_consumer_output = "consumer_output";
const char * const config_element_destination = "destination";
const char * const config_element_path = "path";
const char * const config_element_net_output = "net_output";
const char * const config_element_control_uri = "control_uri";
const char * const config_element_data_uri = "data_uri";
const char * const config_element_max_size = "max_size";
const char * const config_element_pid = "pid";
const char * const config_element_pids = "pids";
const char * const config_element_shared_memory_path = "shared_memory_path";
const char * const config_element_pid_tracker = "pid_tracker";
const char * const config_element_trackers = "trackers";
const char * const config_element_targets = "targets";
const char * const config_element_target_pid = "pid_target";

const char * const config_domain_type_kernel = "KERNEL";
const char * const config_domain_type_ust = "UST";
const char * const config_domain_type_jul = "JUL";
const char * const config_domain_type_log4j = "LOG4J";
const char * const config_domain_type_python = "PYTHON";

const char * const config_buffer_type_per_pid = "PER_PID";
const char * const config_buffer_type_per_uid = "PER_UID";
const char * const config_buffer_type_global = "GLOBAL";

const char * const config_overwrite_mode_discard = "DISCARD";
const char * const config_overwrite_mode_overwrite = "OVERWRITE";

const char * const config_output_type_splice = "SPLICE";
const char * const config_output_type_mmap = "MMAP";

const char * const config_loglevel_type_all = "ALL";
const char * const config_loglevel_type_range = "RANGE";
const char * const config_loglevel_type_single = "SINGLE";

const char * const config_event_type_all = "ALL";
const char * const config_event_type_tracepoint = "TRACEPOINT";
const char * const config_event_type_probe = "PROBE";
const char * const config_event_type_function = "FUNCTION";
const char * const config_event_type_function_entry = "FUNCTION_ENTRY";
const char * const config_event_type_noop = "NOOP";
const char * const config_event_type_syscall = "SYSCALL";
const char * const config_event_type_kprobe = "KPROBE";
const char * const config_event_type_kretprobe = "KRETPROBE";

const char * const config_event_context_pid = "PID";
const char * const config_event_context_procname = "PROCNAME";
const char * const config_event_context_prio = "PRIO";
const char * const config_event_context_nice = "NICE";
const char * const config_event_context_vpid = "VPID";
const char * const config_event_context_tid = "TID";
const char * const config_event_context_vtid = "VTID";
const char * const config_event_context_ppid = "PPID";
const char * const config_event_context_vppid = "VPPID";
const char * const config_event_context_pthread_id = "PTHREAD_ID";
const char * const config_event_context_hostname = "HOSTNAME";
const char * const config_event_context_ip = "IP";
const char * const config_event_context_perf_thread_counter = "PERF_THREAD_COUNTER";
LTTNG_HIDDEN const char * const config_event_context_app = "APP";
LTTNG_HIDDEN const char * const config_event_context_interruptible = "INTERRUPTIBLE";
LTTNG_HIDDEN const char * const config_event_context_preemptible = "PREEMPTIBLE";
LTTNG_HIDDEN const char * const config_event_context_need_reschedule = "NEED_RESCHEDULE";
LTTNG_HIDDEN const char * const config_event_context_migratable = "MIGRATABLE";

/* Deprecated symbols */
const char * const config_element_perf;

enum process_event_node_phase {
	CREATION = 0,
	ENABLE = 1,
};

struct consumer_output {
	int enabled;
	char *path;
	char *control_uri;
	char *data_uri;
};

static int config_entry_handler_filter(struct handler_filter_args *args,
		const char *section, const char *name, const char *value)
{
	int ret = 0;
	struct config_entry entry = { section, name, value };

	assert(args);

	if (!section || !name || !value) {
		ret = -EIO;
		goto end;
	}

	if (args->section) {
		if (strcmp(args->section, section)) {
			goto end;
		}
	}

	ret = args->handler(&entry, args->user_data);
end:
	return ret;
}

LTTNG_HIDDEN
int config_get_section_entries(const char *override_path, const char *section,
		config_entry_handler_cb handler, void *user_data)
{
	int ret = 0;
	char *path;
	FILE *config_file = NULL;
	struct handler_filter_args filter = { section, handler, user_data };

	/* First, try system-wide conf. file. */
	path = DEFAULT_DAEMON_SYSTEM_CONFIGPATH;

	config_file = fopen(path, "r");
	if (config_file) {
		DBG("Loading daemon conf file at %s", path);
		/*
		 * Return value is not very important here since error or not, we
		 * continue and try the next possible conf. file.
		 */
		(void) ini_parse_file(config_file,
				(ini_entry_handler) config_entry_handler_filter,
				(void *) &filter);
		fclose(config_file);
	}

	/* Second is the user local configuration. */
	path = utils_get_home_dir();
	if (path) {
		char fullpath[PATH_MAX];

		ret = snprintf(fullpath, sizeof(fullpath),
				DEFAULT_DAEMON_HOME_CONFIGPATH, path);
		if (ret < 0) {
			PERROR("snprintf user conf. path");
			goto error;
		}

		config_file = fopen(fullpath, "r");
		if (config_file) {
			DBG("Loading daemon user conf file at %s", path);
			/*
			 * Return value is not very important here since error or not, we
			 * continue and try the next possible conf. file.
			 */
			(void) ini_parse_file(config_file,
					(ini_entry_handler) config_entry_handler_filter,
					(void *) &filter);
			fclose(config_file);
		}
	}

	/* Final path is the one that the user might have provided. */
	if (override_path) {
		config_file = fopen(override_path, "r");
		if (config_file) {
			DBG("Loading daemon command line conf file at %s", override_path);
			(void) ini_parse_file(config_file,
					(ini_entry_handler) config_entry_handler_filter,
					(void *) &filter);
			fclose(config_file);
		} else {
			ERR("Failed to open daemon configuration file at %s",
				override_path);
			ret = -ENOENT;
			goto error;
		}
	}

	/* Everything went well. */
	ret = 0;

error:
	return ret;
}

LTTNG_HIDDEN
int config_parse_value(const char *value)
{
	int i, ret = 0;
	char *endptr, *lower_str;
	size_t len;
	unsigned long v;

	len = strlen(value);
	if (!len) {
		ret = -1;
		goto end;
	}

	v = strtoul(value, &endptr, 10);
	if (endptr != value) {
		ret = v;
		goto end;
	}

	lower_str = zmalloc(len + 1);
	if (!lower_str) {
		PERROR("zmalloc");
		ret = -errno;
		goto end;
	}

	for (i = 0; i < len; i++) {
		lower_str[i] = tolower(value[i]);
	}

	if (!strcmp(lower_str, config_str_yes) ||
		!strcmp(lower_str, config_str_true) ||
		!strcmp(lower_str, config_str_on)) {
		ret = 1;
	} else if (!strcmp(lower_str, config_str_no) ||
		!strcmp(lower_str, config_str_false) ||
		!strcmp(lower_str, config_str_off)) {
		ret = 0;
	} else {
		ret = -1;
	}

	free(lower_str);
end:
	return ret;
}

/*
 * Returns a xmlChar string which must be released using xmlFree().
 */
static xmlChar *encode_string(const char *in_str)
{
	xmlChar *out_str = NULL;
	xmlCharEncodingHandlerPtr handler;
	int out_len, ret, in_len;

	assert(in_str);

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
	out_str = xmlMalloc(out_len);
	if (!out_str) {
		goto end;
	}

	ret = handler->input(out_str, &out_len, (const xmlChar *) in_str, &in_len);
	if (ret < 0) {
		xmlFree(out_str);
		out_str = NULL;
		goto end;
	}

	/* out_len is now the size of out_str */
	out_str[out_len] = '\0';
end:
	return out_str;
}

LTTNG_HIDDEN
struct config_writer *config_writer_create(int fd_output, int indent)
{
	int ret;
	struct config_writer *writer;
	xmlOutputBufferPtr buffer;

	writer = zmalloc(sizeof(struct config_writer));
	if (!writer) {
		PERROR("zmalloc config_writer_create");
		goto end;
	}

	buffer = xmlOutputBufferCreateFd(fd_output, NULL);
	if (!buffer) {
		goto error_destroy;
	}

	writer->writer = xmlNewTextWriter(buffer);
	ret = xmlTextWriterStartDocument(writer->writer, NULL,
		config_xml_encoding, NULL);
	if (ret < 0) {
		goto error_destroy;
	}

	ret = xmlTextWriterSetIndentString(writer->writer,
		BAD_CAST config_xml_indent_string);
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
	return NULL;
}

LTTNG_HIDDEN
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

LTTNG_HIDDEN
int config_writer_open_element(struct config_writer *writer,
	const char *element_name)
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

LTTNG_HIDDEN
int config_writer_write_attribute(struct config_writer *writer,
		const char *name, const char *value)
{
	int ret;
	xmlChar *encoded_name = NULL;
	xmlChar *encoded_value = NULL;

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

	ret = xmlTextWriterWriteAttribute(writer->writer, encoded_name,
			encoded_value);
end:
	xmlFree(encoded_name);
	xmlFree(encoded_value);
	return ret >= 0 ? 0 : ret;
}

LTTNG_HIDDEN
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

LTTNG_HIDDEN
int config_writer_write_element_unsigned_int(struct config_writer *writer,
		const char *element_name, uint64_t value)
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

	ret = xmlTextWriterWriteFormatElement(writer->writer,
		encoded_element_name, "%" PRIu64, value);
	xmlFree(encoded_element_name);
end:
	return ret >= 0 ? 0 : ret;
}

LTTNG_HIDDEN
int config_writer_write_element_signed_int(struct config_writer *writer,
		const char *element_name, int64_t value)
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

	ret = xmlTextWriterWriteFormatElement(writer->writer,
		encoded_element_name, "%" PRIi64, value);
	xmlFree(encoded_element_name);
end:
	return ret >= 0 ? 0 : ret;
}

LTTNG_HIDDEN
int config_writer_write_element_bool(struct config_writer *writer,
		const char *element_name, int value)
{
	return config_writer_write_element_string(writer, element_name,
		value ? config_xml_true : config_xml_false);
}

LTTNG_HIDDEN
int config_writer_write_element_string(struct config_writer *writer,
		const char *element_name, const char *value)
{
	int ret;
	xmlChar *encoded_element_name = NULL;
	xmlChar *encoded_value = NULL;

	if (!writer || !writer->writer || !element_name || !element_name[0] ||
		!value) {
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

	ret = xmlTextWriterWriteElement(writer->writer, encoded_element_name,
			encoded_value);
end:
	xmlFree(encoded_element_name);
	xmlFree(encoded_value);
	return ret >= 0 ? 0 : ret;
}

static
void xml_error_handler(void *ctx, const char *format, ...)
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

static
void fini_session_config_validation_ctx(
	struct session_config_validation_ctx *ctx)
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

static
char *get_session_config_xsd_path()
{
	char *xsd_path;
	const char *base_path = lttng_secure_getenv(DEFAULT_SESSION_CONFIG_XSD_PATH_ENV);
	size_t base_path_len;
	size_t max_path_len;

	if (!base_path) {
		base_path = DEFAULT_SESSION_CONFIG_XSD_PATH;
	}

	base_path_len = strlen(base_path);
	max_path_len = base_path_len +
		sizeof(DEFAULT_SESSION_CONFIG_XSD_FILENAME) + 1;
	xsd_path = zmalloc(max_path_len);
	if (!xsd_path) {
		goto end;
	}

	strncpy(xsd_path, base_path, max_path_len);
	if (xsd_path[base_path_len - 1] != '/') {
		xsd_path[base_path_len++] = '/';
	}

	strncpy(xsd_path + base_path_len, DEFAULT_SESSION_CONFIG_XSD_FILENAME,
		max_path_len - base_path_len);
end:
	return xsd_path;
}

static
int init_session_config_validation_ctx(
	struct session_config_validation_ctx *ctx)
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
	xmlSchemaSetParserErrors(ctx->parser_ctx, xml_error_handler,
		xml_error_handler, NULL);

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

	xmlSchemaSetValidErrors(ctx->schema_validation_ctx, xml_error_handler,
			xml_error_handler, NULL);
	ret = 0;

end:
	if (ret) {
		fini_session_config_validation_ctx(ctx);
	}

	free(xsd_path);
	return ret;
}

static
int parse_uint(xmlChar *str, uint64_t *val)
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

static
int parse_int(xmlChar *str, int64_t *val)
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

static
int parse_bool(xmlChar *str, int *val)
{
	int ret = 0;

	if (!str || !val) {
		ret = -1;
		goto end;
	}

	if (!strcmp((const char *) str, config_xml_true)) {
		*val = 1;
	} else if (!strcmp((const char *) str, config_xml_false)) {
		*val = 0;
	} else {
		WARN("Invalid boolean value encoutered (%s).",
			(const char *) str);
		ret = -1;
	}
end:
	return ret;
}

static
int get_domain_type(xmlChar *domain)
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

static
int get_buffer_type(xmlChar *buffer_type)
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

static
int get_overwrite_mode(xmlChar *overwrite_mode)
{
	int ret;

	if (!overwrite_mode) {
		goto error;
	}

	if (!strcmp((char *) overwrite_mode, config_overwrite_mode_overwrite)) {
		ret = 1;
	} else if (!strcmp((char *) overwrite_mode,
		config_overwrite_mode_discard)) {
		ret = 0;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static
int get_output_type(xmlChar *output_type)
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

static
int get_event_type(xmlChar *event_type)
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
	} else if (!strcmp((char *) event_type, config_event_type_function)) {
		ret = LTTNG_EVENT_FUNCTION;
	} else if (!strcmp((char *) event_type,
		config_event_type_function_entry)) {
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

static
int get_loglevel_type(xmlChar *loglevel_type)
{
	int ret;

	if (!loglevel_type) {
		goto error;
	}

	if (!strcmp((char *) loglevel_type, config_loglevel_type_all)) {
		ret = LTTNG_EVENT_LOGLEVEL_ALL;
	} else if (!strcmp((char *) loglevel_type,
		config_loglevel_type_range)) {
		ret = LTTNG_EVENT_LOGLEVEL_RANGE;
	} else if (!strcmp((char *) loglevel_type,
		config_loglevel_type_single)) {
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
static
int get_context_type(xmlChar *context_type)
{
	int ret;

	if (!context_type) {
		goto error;
	}

	if (!strcmp((char *) context_type, config_event_context_pid)) {
		ret = LTTNG_EVENT_CONTEXT_PID;
	} else if (!strcmp((char *) context_type,
		config_event_context_procname)) {
		ret = LTTNG_EVENT_CONTEXT_PROCNAME;
	} else if (!strcmp((char *) context_type,
		config_event_context_prio)) {
		ret = LTTNG_EVENT_CONTEXT_PRIO;
	} else if (!strcmp((char *) context_type,
		config_event_context_nice)) {
		ret = LTTNG_EVENT_CONTEXT_NICE;
	} else if (!strcmp((char *) context_type,
		config_event_context_vpid)) {
		ret = LTTNG_EVENT_CONTEXT_VPID;
	} else if (!strcmp((char *) context_type,
		config_event_context_tid)) {
		ret = LTTNG_EVENT_CONTEXT_TID;
	} else if (!strcmp((char *) context_type,
		config_event_context_vtid)) {
		ret = LTTNG_EVENT_CONTEXT_VTID;
	} else if (!strcmp((char *) context_type,
		config_event_context_ppid)) {
		ret = LTTNG_EVENT_CONTEXT_PPID;
	} else if (!strcmp((char *) context_type,
		config_event_context_vppid)) {
		ret = LTTNG_EVENT_CONTEXT_VPPID;
	} else if (!strcmp((char *) context_type,
		config_event_context_pthread_id)) {
		ret = LTTNG_EVENT_CONTEXT_PTHREAD_ID;
	} else if (!strcmp((char *) context_type,
		config_event_context_hostname)) {
		ret = LTTNG_EVENT_CONTEXT_HOSTNAME;
	} else if (!strcmp((char *) context_type,
		config_event_context_ip)) {
		ret = LTTNG_EVENT_CONTEXT_IP;
	} else if (!strcmp((char *) context_type,
		config_event_context_interruptible)) {
		ret = LTTNG_EVENT_CONTEXT_INTERRUPTIBLE;
	} else if (!strcmp((char *) context_type,
		config_event_context_preemptible)) {
		ret = LTTNG_EVENT_CONTEXT_PREEMPTIBLE;
	} else if (!strcmp((char *) context_type,
		config_event_context_need_reschedule)) {
		ret = LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE;
	} else if (!strcmp((char *) context_type,
		config_event_context_migratable)) {
		ret = LTTNG_EVENT_CONTEXT_MIGRATABLE;
	} else {
		goto error;
	}

	return ret;
error:
	return -1;
}

static
int init_domain(xmlNodePtr domain_node, struct lttng_domain *domain)
{
	int ret;
	xmlNodePtr node;

	for (node = xmlFirstElementChild(domain_node); node;
		node = xmlNextElementSibling(node)) {
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

			domain->type = ret;
		} else if (!strcmp((const char *) node->name,
			config_element_buffer_type)) {
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

			domain->buf_type = ret;
		}
	}
	ret = 0;
end:
	return ret;
}

static
int get_net_output_uris(xmlNodePtr net_output_node, char **control_uri,
	char **data_uri)
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

static
int process_consumer_output(xmlNodePtr consumer_output_node,
	struct consumer_output *output)
{
	int ret;
	xmlNodePtr node;

	assert(output);

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

			if (!strcmp((const char *) output_type_node->name,
					config_element_path)) {
				/* path */
				output->path = (char *) xmlNodeGetContent(output_type_node);
				if (!output->path) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}
			} else {
				/* net_output */
				ret = get_net_output_uris(output_type_node,
						&output->control_uri, &output->data_uri);
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

static
int create_session_net_output(const char *name, const char *control_uri,
		const char *data_uri)
{
	int ret;
	struct lttng_handle *handle;
	const char *uri = NULL;

	assert(name);

	handle = lttng_create_handle(name, NULL);
	if (!handle) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	if (!control_uri || !data_uri) {
		uri = control_uri ? control_uri : data_uri;
		control_uri = uri;
		data_uri = uri;
	}

	ret = lttng_set_consumer_url(handle, control_uri, data_uri);
	lttng_destroy_handle(handle);
end:
	return ret;
}

static
int create_snapshot_session(const char *session_name, xmlNodePtr output_node,
		const struct config_load_session_override_attr *overrides)
{
	int ret;
	xmlNodePtr node = NULL;
	xmlNodePtr snapshot_output_list_node;
	xmlNodePtr snapshot_output_node;

	assert(session_name);

	ret = lttng_create_session_snapshot(session_name, NULL);
	if (ret) {
		goto end;
	}

	if (!output_node) {
		goto end;
	}

	snapshot_output_list_node = xmlFirstElementChild(output_node);

	/* Parse and create snapshot outputs */

	for (snapshot_output_node =
			xmlFirstElementChild(snapshot_output_list_node);
			snapshot_output_node; snapshot_output_node =
			xmlNextElementSibling(snapshot_output_node)) {
		char *name = NULL;
		uint64_t max_size = UINT64_MAX;
		struct consumer_output output = { 0 };
		struct lttng_snapshot_output *snapshot_output = NULL;
		const char *control_uri = NULL;
		const char *data_uri = NULL;
		const char *path = NULL;

		for (node = xmlFirstElementChild(snapshot_output_node); node;
				node = xmlNextElementSibling(node)) {
			if (!strcmp((const char *) node->name,
				config_element_name)) {
				/* name */
				name = (char *) xmlNodeGetContent(node);
				if (!name) {
					ret = -LTTNG_ERR_NOMEM;
					goto error_snapshot_output;
				}
			} else if (!strcmp((const char *) node->name,
				config_element_max_size)) {
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
				control_uri = NULL;
				data_uri = NULL;
			} else {
				if (overrides->ctrl_url) {
					control_uri = overrides->ctrl_url;
					/* path is null */
					path = NULL;
				}
				if (overrides->data_url) {
					data_uri = overrides->data_url;
					/* path is null */
					path = NULL;
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
			ret = lttng_snapshot_output_set_ctrl_url(path,
					snapshot_output);
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
				ret = lttng_snapshot_output_set_data_url(data_uri,
						snapshot_output);
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
	return ret;
}

static
int create_session(const char *name,
	struct lttng_domain *kernel_domain,
	struct lttng_domain *ust_domain,
	struct lttng_domain *jul_domain,
	struct lttng_domain *log4j_domain,
	xmlNodePtr output_node,
	uint64_t live_timer_interval,
	const struct config_load_session_override_attr *overrides)
{
	int ret;
	struct consumer_output output = { 0 };
	xmlNodePtr consumer_output_node;
	const char *control_uri = NULL;
	const char *data_uri = NULL;
	const char *path = NULL;

	assert(name);

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
			control_uri = NULL;
			data_uri = NULL;
		} else {
			if (overrides->ctrl_url) {
				control_uri = overrides->ctrl_url;
				/* path is null */
				path = NULL;
			}
			if (overrides->data_url) {
				data_uri = overrides->data_url;
				/* path is null */
				path = NULL;
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
			ret = lttng_create_session_live(name, NULL, live_timer_interval);
		} else {
			ret = lttng_create_session(name, NULL);
		}
		if (ret) {
			goto end;
		}

		ret = create_session_net_output(name, control_uri, data_uri);
		if (ret) {
			goto end;
		}

	} else {
		/* either local output or no output */
		ret = lttng_create_session(name, path);
		if (ret) {
			goto end;
		}
	}
end:
	free(output.path);
	free(output.control_uri);
	free(output.data_uri);
	return ret;
}
static
int process_probe_attribute_node(xmlNodePtr probe_attribute_node,
	struct lttng_event_probe_attr *attr)
{
	int ret;

	assert(probe_attribute_node);
	assert(attr);

	if (!strcmp((const char *) probe_attribute_node->name,
		config_element_address)) {
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
	} else if (!strcmp((const char *) probe_attribute_node->name,
		config_element_offset)) {
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
	} else if (!strcmp((const char *) probe_attribute_node->name,
		config_element_symbol_name)) {
		xmlChar *content;
		size_t name_len;

		/* symbol_name */
		content = xmlNodeGetContent(probe_attribute_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		name_len = strlen((char *) content);
		if (name_len >= LTTNG_SYMBOL_NAME_LEN) {
			WARN("symbol_name too long.");
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			free(content);
			goto end;
		}

		strncpy(attr->symbol_name, (const char *) content, name_len);
		free(content);
	}
	ret = 0;
end:
	return ret;
}

static
int process_event_node(xmlNodePtr event_node, struct lttng_handle *handle,
	const char *channel_name, const enum process_event_node_phase phase)
{
	int ret = 0, i;
	xmlNodePtr node;
	struct lttng_event event;
	char **exclusions = NULL;
	unsigned long exclusion_count = 0;
	char *filter_expression = NULL;

	assert(event_node);
	assert(handle);
	assert(channel_name);

	memset(&event, 0, sizeof(event));

	/* Initialize default log level which varies by domain */
	switch (handle->domain.type)
	{
	case LTTNG_DOMAIN_JUL:
		event.loglevel = LTTNG_LOGLEVEL_JUL_ALL;
		break;
	case LTTNG_DOMAIN_LOG4J:
		event.loglevel = LTTNG_LOGLEVEL_LOG4J_ALL;
		break;
	case LTTNG_DOMAIN_PYTHON:
		event.loglevel = LTTNG_LOGLEVEL_PYTHON_DEBUG;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_KERNEL:
		event.loglevel = LTTNG_LOGLEVEL_DEBUG;
		break;
	default:
		assert(0);
	}

	for (node = xmlFirstElementChild(event_node); node;
		node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name, config_element_name)) {
			xmlChar *content;
			size_t name_len;

			/* name */
			content = xmlNodeGetContent(node);
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			name_len = strlen((char *) content);
			if (name_len >= LTTNG_SYMBOL_NAME_LEN) {
				WARN("Channel name too long.");
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				free(content);
				goto end;
			}

			strncpy(event.name, (const char *) content, name_len);
			free(content);
		} else if (!strcmp((const char *) node->name,
			config_element_enabled)) {
			xmlChar *content = xmlNodeGetContent(node);

			/* enabled */
			if (!content) {
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			ret = parse_bool(content, &event.enabled);
			free(content);
			if (ret) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}
		} else if (!strcmp((const char *) node->name,
			config_element_type)) {
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

			event.type = ret;
		} else if (!strcmp((const char *) node->name,
			config_element_loglevel_type)) {
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

			event.loglevel_type = ret;
		} else if (!strcmp((const char *) node->name,
			config_element_loglevel)) {
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

			event.loglevel = loglevel;
		} else if (!strcmp((const char *) node->name,
			config_element_filter)) {
			xmlChar *content =
				xmlNodeGetContent(node);

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
		} else if (!strcmp((const char *) node->name,
			config_element_exclusions)) {
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

			exclusions = zmalloc(exclusion_count * sizeof(char *));
			if (!exclusions) {
				exclusion_count = 0;
				ret = -LTTNG_ERR_NOMEM;
				goto end;
			}

			for (exclusion_node = xmlFirstElementChild(node); exclusion_node;
					exclusion_node = xmlNextElementSibling(exclusion_node)) {
				xmlChar *content =
					xmlNodeGetContent(exclusion_node);

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

			event.exclusion = 1;
		} else if (!strcmp((const char *) node->name,
			config_element_attributes)) {
			xmlNodePtr attribute_node = xmlFirstElementChild(node);

			/* attributes */
			if (!attribute_node) {
				ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
				goto end;
			}

			if (!strcmp((const char *) node->name,
						config_element_probe_attributes)) {
				xmlNodePtr probe_attribute_node;

				/* probe_attributes */
				for (probe_attribute_node =
					xmlFirstElementChild(attribute_node); probe_attribute_node;
					probe_attribute_node = xmlNextElementSibling(
							probe_attribute_node)) {

					ret = process_probe_attribute_node(probe_attribute_node,
							&event.attr.probe);
					if (ret) {
						goto end;
					}
				}
			} else {
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

				strncpy(event.attr.ftrace.symbol_name, (char *) content,
						sym_len);
				free(content);
			}
		}
	}

	if ((event.enabled && phase == ENABLE) || phase == CREATION) {
		ret = lttng_enable_event_with_exclusions(handle, &event, channel_name,
				filter_expression, exclusion_count, exclusions);
		if (ret < 0) {
			WARN("Enabling event (name:%s) on load failed.", event.name);
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	}
end:
	for (i = 0; i < exclusion_count; i++) {
		free(exclusions[i]);
	}

	free(exclusions);
	free(filter_expression);
	return ret;
}

static
int process_events_node(xmlNodePtr events_node, struct lttng_handle *handle,
	const char *channel_name)
{
	int ret = 0;
	struct lttng_event event;
	xmlNodePtr node;

	assert(events_node);
	assert(handle);
	assert(channel_name);

	for (node = xmlFirstElementChild(events_node); node;
		node = xmlNextElementSibling(node)) {
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
	ret = lttng_disable_event_ext(handle, &event, channel_name, NULL);
	if (ret) {
		goto end;
	}

	for (node = xmlFirstElementChild(events_node); node;
			node = xmlNextElementSibling(node)) {
		ret = process_event_node(node, handle, channel_name, ENABLE);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static
int process_channel_attr_node(xmlNodePtr attr_node,
		struct lttng_channel *channel, xmlNodePtr *contexts_node,
		xmlNodePtr *events_node)
{
	int ret;

	assert(attr_node);
	assert(channel);
	assert(contexts_node);
	assert(events_node);

	if (!strcmp((const char *) attr_node->name, config_element_name)) {
		xmlChar *content;
		size_t name_len;

		/* name */
		content = xmlNodeGetContent(attr_node);
		if (!content) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		name_len = strlen((char *) content);
		if (name_len >= LTTNG_SYMBOL_NAME_LEN) {
			WARN("Channel name too long.");
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			free(content);
			goto end;
		}

		strncpy(channel->name, (const char *) content, name_len);
		free(content);
	} else if (!strcmp((const char *) attr_node->name,
			config_element_enabled)) {
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
	} else if (!strcmp((const char *) attr_node->name,
			config_element_overwrite_mode)) {
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
	} else if (!strcmp((const char *) attr_node->name,
			config_element_subbuf_size)) {
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
	} else if (!strcmp((const char *) attr_node->name,
			config_element_num_subbuf)) {
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
	} else if (!strcmp((const char *) attr_node->name,
			config_element_switch_timer_interval)) {
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

		channel->attr.switch_timer_interval =
			switch_timer_interval;
	} else if (!strcmp((const char *) attr_node->name,
			config_element_read_timer_interval)) {
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

		channel->attr.read_timer_interval =
			read_timer_interval;
	} else if (!strcmp((const char *) attr_node->name,
			config_element_output_type)) {
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

		channel->attr.output = ret;
	} else if (!strcmp((const char *) attr_node->name,
			config_element_tracefile_size)) {
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
	} else if (!strcmp((const char *) attr_node->name,
			config_element_tracefile_count)) {
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
	} else if (!strcmp((const char *) attr_node->name,
			config_element_live_timer_interval)) {
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

		channel->attr.live_timer_interval =
			live_timer_interval;
	} else if (!strcmp((const char *) attr_node->name,
			config_element_monitor_timer_interval)) {
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

		ret = lttng_channel_set_monitor_timer_interval(channel,
			monitor_timer_interval);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name,
			config_element_blocking_timeout)) {
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

		ret = lttng_channel_set_blocking_timeout(channel,
			blocking_timeout);
		if (ret) {
			ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
			goto end;
		}
	} else if (!strcmp((const char *) attr_node->name,
			config_element_events)) {
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

static
int process_context_node(xmlNodePtr context_node,
	struct lttng_handle *handle, const char *channel_name)
{
	int ret;
	struct lttng_event_context context;
	xmlNodePtr context_child_node = xmlFirstElementChild(context_node);

	assert(handle);
	assert(channel_name);

	if (!context_child_node) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	memset(&context, 0, sizeof(context));

	if (!strcmp((const char *) context_child_node->name,
		config_element_type)) {
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

		context.ctx = ret;
	} else if (!strcmp((const char *) context_child_node->name,
		config_element_context_perf)) {
		/* perf */
		xmlNodePtr perf_attr_node;

		context.ctx = handle->domain.type == LTTNG_DOMAIN_KERNEL ?
			LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER :
			LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER;
		for (perf_attr_node = xmlFirstElementChild(context_child_node);
			perf_attr_node; perf_attr_node =
				xmlNextElementSibling(perf_attr_node)) {
			if (!strcmp((const char *) perf_attr_node->name,
				config_element_type)) {
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
				size_t name_len;

				/* name */
				content = xmlNodeGetContent(perf_attr_node);
				if (!content) {
					ret = -LTTNG_ERR_NOMEM;
					goto end;
				}

				name_len = strlen((char *) content);
				if (name_len >= LTTNG_SYMBOL_NAME_LEN) {
					WARN("perf context name too long.");
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					free(content);
					goto end;
				}

				strncpy(context.u.perf_counter.name, (const char *) content,
						name_len);
				free(content);
			}
		}
	} else if (!strcmp((const char *) context_child_node->name,
		config_element_context_app)) {
		/* application context */
		xmlNodePtr app_ctx_node;

		context.ctx = LTTNG_EVENT_CONTEXT_APP_CONTEXT;
		for (app_ctx_node = xmlFirstElementChild(context_child_node);
				app_ctx_node; app_ctx_node =
				xmlNextElementSibling(app_ctx_node)) {
			xmlChar *content;
			char **target = strcmp(
				(const char *) app_ctx_node->name,
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

	ret = lttng_add_context(handle, &context, NULL, channel_name);
	if (context.ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		free(context.u.app_ctx.provider_name);
		free(context.u.app_ctx.ctx_name);
	}
end:
	return ret;
}

static
int process_contexts_node(xmlNodePtr contexts_node,
	struct lttng_handle *handle, const char *channel_name)
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

static
int process_pid_tracker_node(xmlNodePtr pid_tracker_node,
	struct lttng_handle *handle)
{
	int ret = 0, child;
	xmlNodePtr targets_node = NULL;
	xmlNodePtr node;

	assert(handle);
	assert(pid_tracker_node);
	/* get the targets node */
	for (node = xmlFirstElementChild(pid_tracker_node); node;
		node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name,
				config_element_targets)) {
			targets_node = node;
			break;
		}
	}

	if (!targets_node) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* Go through all pid_target node */
	child = xmlChildElementCount(targets_node);
	if (child == 0) {
		/* The session is explicitly set to target nothing. */
		ret = lttng_untrack_pid(handle, -1);
		if (ret) {
			goto end;
		}
	}
	for (node = xmlFirstElementChild(targets_node); node;
			node = xmlNextElementSibling(node)) {
		xmlNodePtr pid_target_node = node;

		/* get pid node and track it */
		for (node = xmlFirstElementChild(pid_target_node); node;
			node = xmlNextElementSibling(node)) {
			if (!strcmp((const char *) node->name,
					config_element_pid)) {
				int64_t pid;
				xmlChar *content = NULL;

				content = xmlNodeGetContent(node);
				if (!content) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				ret = parse_int(content, &pid);
				free(content);
				if (ret) {
					ret = LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto end;
				}

				ret = lttng_track_pid(handle, (int) pid);
				if (ret) {
					goto end;
				}
			}
		}
		node = pid_target_node;
	}

end:
	return ret;
}

static
int process_domain_node(xmlNodePtr domain_node, const char *session_name)
{
	int ret;
	struct lttng_domain domain = { 0 };
	struct lttng_handle *handle = NULL;
	struct lttng_channel *channel = NULL;
	xmlNodePtr channels_node = NULL;
	xmlNodePtr trackers_node = NULL;
	xmlNodePtr pid_tracker_node = NULL;
	xmlNodePtr node;

	assert(session_name);

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
	for (node = xmlFirstElementChild(domain_node); node;
		node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name,
			config_element_channels)) {
			channels_node = node;
			break;
		}
	}

	if (!channels_node) {
		goto end;
	}

	/* create all channels */
	for (node = xmlFirstElementChild(channels_node); node;
		node = xmlNextElementSibling(node)) {
		xmlNodePtr contexts_node = NULL;
		xmlNodePtr events_node = NULL;
		xmlNodePtr channel_attr_node;

		channel = lttng_channel_create(&domain);
		if (!channel) {
			ret = -1;
			goto end;
		}

		for (channel_attr_node = xmlFirstElementChild(node);
			channel_attr_node; channel_attr_node =
			xmlNextElementSibling(channel_attr_node)) {
			ret = process_channel_attr_node(channel_attr_node,
				channel, &contexts_node, &events_node);
			if (ret) {
				goto end;
			}
		}

		ret = lttng_enable_channel(handle, channel);
		if (ret < 0) {
			goto end;
		}

		ret = process_events_node(events_node, handle, channel->name);
		if (ret) {
			goto end;
		}

		ret = process_contexts_node(contexts_node, handle,
			channel->name);
		if (ret) {
			goto end;
		}

		lttng_channel_destroy(channel);
	}
	channel = NULL;

	/* get the trackers node */
	for (node = xmlFirstElementChild(domain_node); node;
			node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *) node->name,
					config_element_trackers)) {
			trackers_node = node;
			break;
		}
	}

	if (!trackers_node) {
		goto end;
	}

	for (node = xmlFirstElementChild(trackers_node); node;
			node = xmlNextElementSibling(node)) {
		if (!strcmp((const char *)node->name,config_element_pid_tracker)) {
			pid_tracker_node = node;
			ret = process_pid_tracker_node(pid_tracker_node, handle);
			if (ret) {
				goto end;
			}
		}
	}

	if (!pid_tracker_node) {
		lttng_track_pid(handle, -1);
	}

end:
	lttng_channel_destroy(channel);
	lttng_destroy_handle(handle);
	return ret;
}

static
int process_session_node(xmlNodePtr session_node, const char *session_name,
		int overwrite,
		const struct config_load_session_override_attr *overrides)
{
	int ret, started = -1, snapshot_mode = -1;
	uint64_t live_timer_interval = UINT64_MAX;
	xmlChar *name = NULL;
	xmlChar *shm_path = NULL;
	xmlNodePtr domains_node = NULL;
	xmlNodePtr output_node = NULL;
	xmlNodePtr node;
	struct lttng_domain *kernel_domain = NULL;
	struct lttng_domain *ust_domain = NULL;
	struct lttng_domain *jul_domain = NULL;
	struct lttng_domain *log4j_domain = NULL;
	struct lttng_domain *python_domain = NULL;

	for (node = xmlFirstElementChild(session_node); node;
		node = xmlNextElementSibling(node)) {
		if (!name && !strcmp((const char *) node->name,
			config_element_name)) {
			/* name */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			name = node_content;
		} else if (!domains_node && !strcmp((const char *) node->name,
			config_element_domains)) {
			/* domains */
			domains_node = node;
		} else if (started == -1 && !strcmp((const char *) node->name,
			config_element_started)) {
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
		} else if (!output_node && !strcmp((const char *) node->name,
			config_element_output)) {
			/* output */
			output_node = node;
		} else if (!shm_path && !strcmp((const char *) node->name,
			config_element_shared_memory_path)) {
			/* shared memory path */
			xmlChar *node_content = xmlNodeGetContent(node);
			if (!node_content) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			shm_path = node_content;
		} else {
			/* attributes, snapshot_mode or live_timer_interval */
			xmlNodePtr attributes_child =
				xmlFirstElementChild(node);

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
			} else {
				/* live_timer_interval */
				xmlChar *timer_interval_content =
					xmlNodeGetContent(attributes_child);
				if (!timer_interval_content) {
					ret = -LTTNG_ERR_NOMEM;
					goto error;
				}

				ret = parse_uint(timer_interval_content, &live_timer_interval);
				free(timer_interval_content);
				if (ret) {
					ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
					goto error;
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
	for (node = xmlFirstElementChild(domains_node); node;
		node = xmlNextElementSibling(node)) {
		struct lttng_domain *domain;

		domain = zmalloc(sizeof(*domain));
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
		ret = create_snapshot_session((const char *) name, output_node,
				overrides);
	} else if (live_timer_interval &&
		live_timer_interval != UINT64_MAX) {
		ret = create_session((const char *) name, kernel_domain,
				ust_domain, jul_domain, log4j_domain,
				output_node, live_timer_interval, overrides);
	} else {
		/* regular session */
		ret = create_session((const char *) name, kernel_domain,
				ust_domain, jul_domain, log4j_domain,
				output_node, UINT64_MAX, overrides);
	}
	if (ret) {
		goto error;
	}

	if (shm_path) {
		ret = lttng_set_session_shm_path((const char *) name,
				(const char *) shm_path);
		if (ret) {
			goto error;
		}
	}

	for (node = xmlFirstElementChild(domains_node); node;
		node = xmlNextElementSibling(node)) {
		ret = process_domain_node(node, (const char *) name);
		if (ret) {
			goto end;
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
		ERR("Failed to load session %s: %s", (const char *) name,
			lttng_strerror(ret));
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

	assert(path);

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

static
int load_session_from_file(const char *path, const char *session_name,
	struct session_config_validation_ctx *validation_ctx, int overwrite,
	const struct config_load_session_override_attr *overrides)
{
	int ret, session_found = !session_name;
	xmlDocPtr doc = NULL;
	xmlNodePtr sessions_node;
	xmlNodePtr session_node;

	assert(path);
	assert(validation_ctx);

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
		goto end;
	}

	for (session_node = xmlFirstElementChild(sessions_node);
		session_node; session_node =
			xmlNextElementSibling(session_node)) {
		ret = process_session_node(session_node,
			session_name, overwrite, overrides);
		if (session_name && ret == 0) {
			/* Target session found and loaded */
			session_found = 1;
			break;
		}
	}
end:
	xmlFreeDoc(doc);
	if (!ret) {
		ret = session_found ? 0 : -LTTNG_ERR_LOAD_SESSION_NOENT;
	}
	return ret;
}

/* Allocate dirent as recommended by READDIR(3), NOTES on readdir_r */
static
struct dirent *alloc_dirent(const char *path)
{
	size_t len;
	long name_max;
	struct dirent *entry;

	name_max = pathconf(path, _PC_NAME_MAX);
	if (name_max == -1) {
		name_max = PATH_MAX;
	}
	len = offsetof(struct dirent, d_name) + name_max + 1;
	entry = zmalloc(len);
	return entry;
}

static
int load_session_from_path(const char *path, const char *session_name,
	struct session_config_validation_ctx *validation_ctx, int overwrite,
	const struct config_load_session_override_attr *overrides)
{
	int ret, session_found = !session_name;
	DIR *directory = NULL;

	assert(path);
	assert(validation_ctx);

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
		struct dirent *entry;
		struct dirent *result;
		char *file_path = NULL;
		size_t path_len = strlen(path);

		if (path_len >= PATH_MAX) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		entry = alloc_dirent(path);
		if (!entry) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		file_path = zmalloc(PATH_MAX);
		if (!file_path) {
			ret = -LTTNG_ERR_NOMEM;
			free(entry);
			goto end;
		}

		strncpy(file_path, path, path_len);
		if (file_path[path_len - 1] != '/') {
			file_path[path_len++] = '/';
		}

		ret = 0;
		/* Search for *.lttng files */
		while (!readdir_r(directory, entry, &result) && result) {
			size_t file_name_len = strlen(result->d_name);

			if (file_name_len <=
				sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION)) {
				continue;
			}

			if (path_len + file_name_len >= PATH_MAX) {
				continue;
			}

			if (strcmp(DEFAULT_SESSION_CONFIG_FILE_EXTENSION,
				result->d_name + file_name_len - sizeof(
				DEFAULT_SESSION_CONFIG_FILE_EXTENSION) + 1)) {
				continue;
			}

			strncpy(file_path + path_len, result->d_name, file_name_len);
			file_path[path_len + file_name_len] = '\0';

			ret = load_session_from_file(file_path, session_name,
				validation_ctx, overwrite, overrides);
			if (session_name && !ret) {
				session_found = 1;
				break;
			}
		}

		free(entry);
		free(file_path);
	} else {
		ret = load_session_from_file(path, session_name,
			validation_ctx, overwrite, overrides);
		if (ret) {
			goto end;
		} else {
			session_found = 1;
		}
	}

end:
	if (directory) {
		if (closedir(directory)) {
			PERROR("closedir");
		}
	}

	if (session_found && !ret) {
		ret = 0;
	}

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

	assert(path);

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

LTTNG_HIDDEN
int config_load_session(const char *path, const char *session_name,
		int overwrite, unsigned int autoload,
		const struct config_load_session_override_attr *overrides)
{
	int ret;
	bool session_loaded = false;
	const char *path_ptr = NULL;
	struct session_config_validation_ctx validation_ctx = { 0 };

	ret = init_session_config_validation_ctx(&validation_ctx);
	if (ret) {
		goto end;
	}

	if (!path) {
		char *home_path;
		const char *sys_path;

		/* Try home path */
		home_path = utils_get_home_dir();
		if (home_path) {
			char path[PATH_MAX];

			/*
			 * Try user session configuration path. Ignore error here so we can
			 * continue loading the system wide sessions.
			 */
			if (autoload) {
				ret = snprintf(path, sizeof(path),
						DEFAULT_SESSION_HOME_CONFIGPATH "/"
						DEFAULT_SESSION_CONFIG_AUTOLOAD, home_path);
				if (ret < 0) {
					PERROR("snprintf session autoload home config path");
					goto end;
				}

				/*
				 * Credentials are only validated for the autoload in order to
				 * avoid any user session daemon to try to load kernel sessions
				 * automatically and failing all the times.
				 */
				ret = validate_path_creds(path);
				if (ret) {
					path_ptr = path;
				}
			} else {
				ret = snprintf(path, sizeof(path),
						DEFAULT_SESSION_HOME_CONFIGPATH, home_path);
				if (ret < 0) {
					PERROR("snprintf session home config path");
					goto end;
				}
				path_ptr = path;
			}
			if (path_ptr) {
				ret = load_session_from_path(path_ptr, session_name,
						&validation_ctx, overwrite, overrides);
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
		path_ptr = NULL;

		/* Try system wide configuration directory. */
		if (autoload) {
			sys_path = DEFAULT_SESSION_SYSTEM_CONFIGPATH "/"
				DEFAULT_SESSION_CONFIG_AUTOLOAD;
			ret = validate_path_creds(sys_path);
			if (ret) {
				path_ptr = sys_path;
			}
		} else {
			sys_path = DEFAULT_SESSION_SYSTEM_CONFIGPATH;
			path_ptr = sys_path;
		}

		if (path_ptr) {
			ret = load_session_from_path(path_ptr, session_name,
					&validation_ctx, overwrite, overrides);
			if (!ret) {
				session_loaded = true;
			}
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

		ret = load_session_from_path(path, session_name,
			&validation_ctx, overwrite, overrides);
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

static
void __attribute__((destructor)) session_config_exit(void)
{
	xmlCleanupParser();
}
