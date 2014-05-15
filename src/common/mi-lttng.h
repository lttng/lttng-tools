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

#ifndef _MI_LTTNG_H
#define _MI_LTTNG_H

#include <stdint.h>

#include <common/error.h>
#include <common/macros.h>
#include <common/config/config.h>
#include <lttng/lttng.h>

/* Instance of a machine interface writer. */
struct mi_writer {
	struct config_writer *writer;
	enum lttng_mi_output_type type;
};

/*
 * Version information for the machine interface.
 */
struct mi_lttng_version {
	char version[NAME_MAX]; /* Version number of package */
	uint32_t version_major; /* LTTng-Tools major version number */
	uint32_t version_minor; /* LTTng-Tools minor version number */
	uint32_t version_patchlevel; /* LTTng-Tools patchlevel version number */
	char version_commit[NAME_MAX]; /* Commit hash of the current version */
	char version_name[NAME_MAX];
	char package_url[NAME_MAX]; /* Define to the home page for this package. */
};

/* Strings related to command */
const char * const mi_lttng_element_command;
const char * const mi_lttng_element_command_version;
const char * const mi_lttng_element_command_list;
const char * const mi_lttng_element_command_name;
const char * const mi_lttng_element_command_output;

/* Strings related to command: version */
const char * const mi_lttng_element_version;
const char * const mi_lttng_element_version_str;
const char * const mi_lttng_element_version_web;
const char * const mi_lttng_element_version_major;
const char * const mi_lttng_element_version_minor;
const char * const mi_lttng_element_version_license;
const char * const mi_lttng_element_version_commit;
const char * const mi_lttng_element_version_patch_level;
const char * const mi_lttng_element_version_description;

/* String related to a lttng_event_field */
const char * const mi_lttng_element_event_field;
const char * const mi_lttng_element_event_fields;

/* Strings related to pid */
const char * const mi_lttng_element_pids;
const char * const mi_lttng_element_pid;
const char * const mi_lttng_element_pid_id;

/* General element of mi_lttng */
const char * const mi_lttng_element_type_other;
const char * const mi_lttng_element_type_integer;
const char * const mi_lttng_element_type_enum;
const char * const mi_lttng_element_type_float;
const char * const mi_lttng_element_type_string;
const char * const mi_lttng_element_nowrite;

/* String related to loglevel */
const char * const mi_lttng_loglevel_str_alert;
const char * const mi_lttng_loglevel_str_crit;
const char * const mi_lttng_loglevel_str_debug;
const char * const mi_lttng_loglevel_str_debug_function;
const char * const mi_lttng_loglevel_str_debug_line;
const char * const mi_lttng_loglevel_str_debug_module;
const char * const mi_lttng_loglevel_str_debug_process;
const char * const mi_lttng_loglevel_str_debug_program;
const char * const mi_lttng_loglevel_str_debug_system;
const char * const mi_lttng_loglevel_str_debug_unit;
const char * const mi_lttng_loglevel_str_emerg;
const char * const mi_lttng_loglevel_str_err;
const char * const mi_lttng_loglevel_str_info;
const char * const mi_lttng_loglevel_str_notice;
const char * const mi_lttng_loglevel_str_unknown;
const char * const mi_lttng_loglevel_str_warning;

const char * const mi_lttng_loglevel_type_all;
const char * const mi_lttng_loglevel_type_range;
const char * const mi_lttng_loglevel_type_single;
const char * const mi_lttng_loglevel_type_unknown;

/* Utility string function  */
const char *mi_lttng_loglevel_string(int value);
const char *mi_lttng_logleveltype_string(enum lttng_loglevel_type value);
const char *mi_lttng_eventfieldtype_string(enum lttng_event_field_type value);
const char *mi_lttng_domaintype_string(enum lttng_domain_type value);
const char *mi_lttng_buffertype_string(enum lttng_buffer_type value);

/*
 * Create an instance of a machine interface writer.
 *
 * fd_output File to which the XML content must be written. The file will be
 * closed once the mi_writer has been destroyed.
 *
 * Returns an instance of a machine interface writer on success, NULL on
 * error.
 */
struct mi_writer *mi_lttng_writer_create(int fd_output, int mi_output_type);

/*
 * Destroy an instance of a machine interface writer.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the XML document could be closed cleanly. Negative values
 * indicate an error.
 */
int mi_lttng_writer_destroy(struct mi_writer *writer);

/*
 * Open a command tag and add it's name node.
 *
 * writer An instance of a machine interface writer.
 * command The command name.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
int mi_lttng_writer_command_open(struct mi_writer *writer, const char *command);

/*
 * Close a command tag.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
int mi_lttng_writer_command_close(struct mi_writer *writer);

/*
 * Open an element tag.
 *
 * writer An instance of a machine interface writer.
 * element_name Element tag name.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
int mi_lttng_writer_open_element(struct mi_writer *writer,
		const char *element_name);

/*
 * Close the current element tag.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
int mi_lttng_writer_close_element(struct mi_writer *writer);

/*
 * Close multiple element.
 *
 * writer An instance of a machine interface writer.
 * nb_element Number of elements.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
int mi_lttng_close_multi_element(struct mi_writer *writer,
		unsigned int nb_element);

/*
 * Write an element of type unsigned int.
 *
 * writer An instance of a machine interface writer.
 * element_name Element name.
 * value Unsigned int value of the element
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_writer_write_element_unsigned_int(struct mi_writer *writer,
		const char *element_name, uint64_t value);

/*
 * Write an element of type signed int.
 *
 * writer An instance of a machine interface writer.
 * element_name Element name.
 * value Signed int value of the element.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_writer_write_element_signed_int(struct mi_writer *writer,
		const char *element_name, int64_t value);

/*
 * Write an element of type boolean.
 *
 * writer An instance of a machine interface writer.
 * element_name Element name.
 * value Boolean value of the element.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_writer_write_element_bool(struct mi_writer *writer,
		const char *element_name, int value);

/*
 * Write an element of type string.
 *
 * writer An instance of a machine interface writer.
 * element_name Element name.
 * value String value of the element.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_writer_write_element_string(struct mi_writer *writer,
		const char *element_name, const char *value);

/*
 * Machine interface of struct version.
 *
 * writer An instance of a machine interface writer.
 * version Version struct.
 * lttng_description String value of the version description.
 * lttng_license String value of the version license.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_version(struct mi_writer *writer, struct mi_lttng_version *version,
		const char *lttng_description, const char *lttng_license);

/*
 * Machine interface: open a sessions element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_sessions_open(struct mi_writer *writer);

/*
 * Machine interface of struct session.
 *
 * writer An instance of a machine interface writer.
 * session An instance of a session.
 * is_open Defines whether or not the session element shall be closed.
 *         This should be used carefully and the client
 *         must close the session element.
 *         Use case: nested addtionnal information on a session
 *                  ex: domain,channel event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_session(struct mi_writer *writer,
		struct lttng_session *session, int is_open);

/*
 * Machine interface: open a domains element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_domains_open(struct mi_writer *writer);

/*
 * Machine interface of struct domain.
 *
 * writer An instance of a machine interface writer.
 * domain An instance of a domain.
 *
 * is_open Defines whether or not the session element shall be closed.
 *         This should be used carefully and the client
 *         must close the domain element.
 *         Use case: nested addition information on a domain
 *                  ex: channel event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_domain(struct mi_writer *writer,
		struct lttng_domain *domain, int is_open);

/*
 * Machine interface: open a channels element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_channels_open(struct mi_writer *writer);

/*
 * Machine interface of struct channel.
 *
 * writer An instance of a machine interface writer.
 * channel An instance of a channel.
 *
 * is_open Defines whether or not the session element shall be closed.
 *         This should be used carefully and the client
 *         must close the channel element.
 *         Use case: nested addition information on a channel.
 *                  ex: channel event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_channel(struct mi_writer *writer,
		struct lttng_channel *channel, int is_open);

/*
 * Machine interface of struct channel_attr.
 *
 * writer An instance of a machine interface writer.
 * attr An instance of a channel_attr struct.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_channel_attr(struct mi_writer *writer,
		struct lttng_channel_attr *attr);

/*
* Machine interface for event common attributes.
*
* writer An instance of a mi writer.
* event single trace event.
*
* The common attribute are:
* - mi event element
* - event name
* - event type
* - enabled tag
* - event filter
*
* Returns zero if the element's value could be written.
* Negative values indicate an error.
*/
int mi_lttng_event_common_attributes(struct mi_writer *writer,
		struct lttng_event *event);

/*
 * Machine interface for kernel tracepoint event with a loglevel.
 *
 * writer An instance of a mi writer.
 * event single trace event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_tracepoint_loglevel(struct mi_writer *writer,
		struct lttng_event *event);

/*
 * Machine interface for kernel tracepoint event with no loglevel.
 *
 * writer An instance of a mi writer.
 * event single trace event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_tracepoint_no_loglevel(struct mi_writer *writer,
		struct lttng_event *event);

/*
 * Machine interface for kernel function and probe event.
 *
 * writer An instance of a mi writer.
 * event single trace event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_function_probe(struct mi_writer *writer,
		struct lttng_event *event);

/*
 * Machine interface for kernel function entry event.
 *
 * writer An instance of a mi writer.
 * event single trace event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_function_entry(struct mi_writer *writer,
		struct lttng_event *event);

/*
 * Machine interface: open an events element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_events_open(struct mi_writer *writer);

/*
 * Machine interface for printing an event.
 * The trace event type currently supported are:
 *  TRACEPOINT,
 *  PROBE,
 *  FUNCTION,
 *  FUNCTION_ENTRY,
 *  SYSCALL
 *
 * writer An instance of a mi writer.
 * event single trace event.
 * is_open Defines whether or not the session element shall be closed.
 *         This should be used carefully and the client
 *         must close the event element.
 *         Use case: nested additional information
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event(struct mi_writer *writer, struct lttng_event *event,
		int is_open);

/*
 * Machine interface for struct lttng_event_field.
 *
 * writer An instance of a mi writer.
 * field An event_field instance.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_field(struct mi_writer *writer,
		struct lttng_event_field *field);

/*
 * Machine interface: open a event_fields element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_fields_open(struct mi_writer *writer);

/*
 * Machine interface: open a PIDs element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_pids_open(struct mi_writer *writer);

/*
 * Machine interface of a PID.
 *
 * writer An instance of a machine interface writer.
 * pid A PID.
 *
 * is_open Defines whether or not the session element shall be closed.
 *         This should be used carefully and the client
 *         must close the pid element.
 *         Use case: nested addition information on a domain
 *                  ex: channel event.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_pid(struct mi_writer *writer, pid_t pid , const char *cmdline,
		int is_open);

#endif /* _MI_LTTNG_H */
