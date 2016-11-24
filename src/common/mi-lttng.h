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

#ifndef _MI_LTTNG_H
#define _MI_LTTNG_H

#include <stdint.h>

#include <common/error.h>
#include <common/macros.h>
#include <common/config/session-config.h>
#include <lttng/lttng.h>

/* Don't want to reference snapshot-internal.h here */
struct lttng_snapshot_output;

/* Instance of a machine interface writer. */
struct mi_writer {
	struct config_writer *writer;
	enum lttng_mi_output_type type;
};

/*
 * Version information for the machine interface.
 */
struct mi_lttng_version {
	char version[LTTNG_NAME_MAX]; /* Version number of package */
	uint32_t version_major; /* LTTng-Tools major version number */
	uint32_t version_minor; /* LTTng-Tools minor version number */
	uint32_t version_patchlevel; /* LTTng-Tools patchlevel version number */
	char version_commit[LTTNG_NAME_MAX]; /* Commit hash of the current version */
	char version_name[LTTNG_NAME_MAX];
	char package_url[LTTNG_NAME_MAX]; /* Define to the home page for this package. */
};

/* Strings related to command */
extern const char * const mi_lttng_element_command;
extern const char * const mi_lttng_element_command_action;
extern const char * const mi_lttng_element_command_add_context;
extern const char * const mi_lttng_element_command_create;
extern const char * const mi_lttng_element_command_destroy;
extern const char * const mi_lttng_element_command_disable_channel;
extern const char * const mi_lttng_element_command_disable_event;
extern const char * const mi_lttng_element_command_enable_channels;
extern const char * const mi_lttng_element_command_enable_event;
extern const char * const mi_lttng_element_command_list;
extern const char * const mi_lttng_element_command_load;
extern const char * const mi_lttng_element_command_metadata;
extern const char * const mi_lttng_element_command_metadata_action;
extern const char * const mi_lttng_element_command_regenerate;
extern const char * const mi_lttng_element_command_regenerate_action;
extern const char * const mi_lttng_element_command_name;
extern const char * const mi_lttng_element_command_output;
extern const char * const mi_lttng_element_command_save;
extern const char * const mi_lttng_element_command_set_session;
extern const char * const mi_lttng_element_command_snapshot;
extern const char * const mi_lttng_element_command_snapshot_add;
extern const char * const mi_lttng_element_command_snapshot_del;
extern const char * const mi_lttng_element_command_snapshot_list;
extern const char * const mi_lttng_element_command_snapshot_record;
extern const char * const mi_lttng_element_command_start;
extern const char * const mi_lttng_element_command_stop;
extern const char * const mi_lttng_element_command_success;
extern const char * const mi_lttng_element_command_track;
extern const char * const mi_lttng_element_command_untrack;
extern const char * const mi_lttng_element_command_version;

/* Strings related to version command */
extern const char * const mi_lttng_element_version;
extern const char * const mi_lttng_element_version_commit;
extern const char * const mi_lttng_element_version_description;
extern const char * const mi_lttng_element_version_license;
extern const char * const mi_lttng_element_version_major;
extern const char * const mi_lttng_element_version_minor;
extern const char * const mi_lttng_element_version_patch_level;
extern const char * const mi_lttng_element_version_str;
extern const char * const mi_lttng_element_version_web;

/* String related to a lttng_event_field */
extern const char * const mi_lttng_element_event_field;
extern const char * const mi_lttng_element_event_fields;

/* String related to lttng_event_perf_counter_ctx */
extern const char * const mi_lttng_element_perf_counter_context;

/* Strings related to pid */
extern const char * const mi_lttng_element_pid_id;

/* Strings related to save command */
extern const char * const mi_lttng_element_save;

/* Strings related to load command */
extern const char * const mi_lttng_element_load;
LTTNG_HIDDEN const char * const mi_lttng_element_load_overrides;
LTTNG_HIDDEN const char * const mi_lttng_element_load_override_url;

/* General element of mi_lttng */
extern const char * const mi_lttng_element_empty;
extern const char * const mi_lttng_element_id;
extern const char * const mi_lttng_element_nowrite;
extern const char * const mi_lttng_element_success;
extern const char * const mi_lttng_element_type_enum;
extern const char * const mi_lttng_element_type_float;
extern const char * const mi_lttng_element_type_integer;
extern const char * const mi_lttng_element_type_other;
extern const char * const mi_lttng_element_type_string;

/* String related to loglevel */
extern const char * const mi_lttng_loglevel_str_alert;
extern const char * const mi_lttng_loglevel_str_crit;
extern const char * const mi_lttng_loglevel_str_debug;
extern const char * const mi_lttng_loglevel_str_debug_function;
extern const char * const mi_lttng_loglevel_str_debug_line;
extern const char * const mi_lttng_loglevel_str_debug_module;
extern const char * const mi_lttng_loglevel_str_debug_process;
extern const char * const mi_lttng_loglevel_str_debug_program;
extern const char * const mi_lttng_loglevel_str_debug_system;
extern const char * const mi_lttng_loglevel_str_debug_unit;
extern const char * const mi_lttng_loglevel_str_emerg;
extern const char * const mi_lttng_loglevel_str_err;
extern const char * const mi_lttng_loglevel_str_info;
extern const char * const mi_lttng_loglevel_str_notice;
extern const char * const mi_lttng_loglevel_str_unknown;
extern const char * const mi_lttng_loglevel_str_warning;

/* String related to loglevel JUL */
extern const char * const mi_lttng_loglevel_str_jul_all;
extern const char * const mi_lttng_loglevel_str_jul_config;
extern const char * const mi_lttng_loglevel_str_jul_fine;
extern const char * const mi_lttng_loglevel_str_jul_finer;
extern const char * const mi_lttng_loglevel_str_jul_finest;
extern const char * const mi_lttng_loglevel_str_jul_info;
extern const char * const mi_lttng_loglevel_str_jul_off;
extern const char * const mi_lttng_loglevel_str_jul_severe;
extern const char * const mi_lttng_loglevel_str_jul_warning;

/* String related to loglevel Log4j */
extern const char * const mi_lttng_loglevel_str_log4j_off;
extern const char * const mi_lttng_loglevel_str_log4j_fatal;
extern const char * const mi_lttng_loglevel_str_log4j_error;
extern const char * const mi_lttng_loglevel_str_log4j_warn;
extern const char * const mi_lttng_loglevel_str_log4j_info;
extern const char * const mi_lttng_loglevel_str_log4j_debug;
extern const char * const mi_lttng_loglevel_str_log4j_trace;
extern const char * const mi_lttng_loglevel_str_log4j_all;

/* String related to loglevel Python */
extern const char * const mi_lttng_loglevel_str_python_critical;
extern const char * const mi_lttng_loglevel_str_python_error;
extern const char * const mi_lttng_loglevel_str_python_warning;
extern const char * const mi_lttng_loglevel_str_python_info;
extern const char * const mi_lttng_loglevel_str_python_debug;
extern const char * const mi_lttng_loglevel_str_python_notset;

/* String related to loglevel type */
extern const char * const mi_lttng_loglevel_type_all;
extern const char * const mi_lttng_loglevel_type_range;
extern const char * const mi_lttng_loglevel_type_single;
extern const char * const mi_lttng_loglevel_type_unknown;

/* String related to a lttng_snapshot */
extern const char * const mi_lttng_element_snapshot_ctrl_url;
extern const char * const mi_lttng_element_snapshot_data_url;
extern const char * const mi_lttng_element_snapshot_max_size;
extern const char * const mi_lttng_element_snapshot_n_ptr;
extern const char * const mi_lttng_element_snapshot_session_name;
extern const char * const mi_lttng_element_snapshots;

/* String related to track/untrack command */
const char * const mi_lttng_element_track_untrack_all_wildcard;

/* Utility string function  */
const char *mi_lttng_loglevel_string(int value, enum lttng_domain_type domain);
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
 *         Use case: nested additional information on a session
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
 * domain Event's domain
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_tracepoint_loglevel(struct mi_writer *writer,
		struct lttng_event *event, enum lttng_domain_type domain);

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
 * domain Event's domain
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_event(struct mi_writer *writer, struct lttng_event *event,
		int is_open, enum lttng_domain_type domain);

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
 * Returns zero if the element have be written.
 * Negative values indicate an error.
 */
int mi_lttng_event_fields_open(struct mi_writer *writer);

/*
 * Machine interface: open a trackers element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_trackers_open(struct mi_writer *writer);

/*
 * Machine interface: open a pid_tracker element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 *
 * Note: A targets element is also opened for each tracker definition
 */
int mi_lttng_pid_tracker_open(struct mi_writer *writer);

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
 * Machine interface: open a processes element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_processes_open(struct mi_writer *writer);

/*
 * Machine interface of a Process.
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
int mi_lttng_process(struct mi_writer *writer, pid_t pid , const char *name,
		int is_open);

/*
 * TODO: move pid of lttng list -u to process semantic on mi api bump
 * Machine interface of a Process.
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
int mi_lttng_pid(struct mi_writer *writer, pid_t pid , const char *name,
		int is_open);
/*
 * Machine interface: open a targets element.
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_targets_open(struct mi_writer *writer);

/*
 * Machine interface for track/untrack a pid_target
 *
 * writer An instance of a machine interface writer.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_pid_target(struct mi_writer *writer, pid_t pid, int is_open);

/*
 * Machine interface of a context.
 *
 * writer An instance of a machine interface writer
 *
 * context An instance of a lttng_event_context
 *
 * is_open Define if we close the context element
 *         This should be used carefully and the client
 *         need to close the context element.
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_context(struct mi_writer *writer,
		struct lttng_event_context *context, int is_open);

/*
 * Machine interface of a perf_counter_context.
 *
 * writer An instance of a machine interface writer
 *
 * contest An instance of a lttng_event_perf_counter_ctx
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_perf_counter_context(struct mi_writer *writer,
		struct lttng_event_perf_counter_ctx  *perf_context);

/*
 * Machine interface of the snapshot list_output.
 * It specifies the session for which we are listing snapshots,
 * and it opens a snapshots element to list a sequence
 * of snapshots.
 *
 * writer An instance of a machine interface writer.
 *
 * session_name: Snapshot output for session "session_name".
 *
 * Note: The client has to close the session and the snapshots elements after
 * having listed every lttng_snapshot_output.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_snapshot_output_session_name(struct mi_writer *writer,
		const char *session_name);

/*
 * Machine interface of the snapshot output.
 * The machine interface serializes the following attributes:
 * - id: ID of the snapshot output.
 * - name: Name of the output.
 * - data_url : Destination of the output.
 * - ctrl_url: Destination of the output.
 * - max_size: total size of all stream combined.
 *
 * writer An instance of a machine interface writer.
 *
 * output: A list of snapshot_output.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_snapshot_list_output(struct mi_writer *writer,
		struct lttng_snapshot_output *output);

/*
 * Machine interface of the output of the command snapshot del output
 * when deleting a snapshot either by id or by name.
 * If the snapshot was found and successfully deleted using its id,
 * it return the id of the snapshot and the current session name on which it
 * was attached.
 *
 * Otherwise, it do the same process with the name of the snapshot, if the
 * snapshot output id is undefined.
 *
 * writer An instance of a machine interface writer.
 *
 * id: ID of the snapshot output.
 *
 * name: Name of the snapshot.
 *
 * current_session_name: Session to which the snapshot belongs.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_snapshot_del_output(struct mi_writer *writer, int id,
		const char *name, const char *current_session_name);

/*
 * Machine interface of the output of the command snapshot add output
 * when adding a snapshot from a user URL.
 *
 * If the snapshot was successfully added, the machine interface lists
 * these information:
 * - id: ID of the newly add snapshot output.
 * - current_session_name: Name of the session to which the output was added.
 * - ctrl_url: Destination of the output.
 * - max_size: total size of all stream combined.
 *
 * writer An instance of a machine interface writer.
 *
 * current_session_name: Session to which the snapshot belongs.
 *
 * n_ptr:
 *
 * output: iterator over a lttng_snapshot_output_list which contain
 * the snapshot output informations.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_snapshot_add_output(struct mi_writer *writer,
		const char *current_session_name, const char *n_ptr,
		struct lttng_snapshot_output *output);

/*
 * Machine interface of the output of the command snapshot
 * record  from a URL (if given).
 *
 * If the snapshot is successfully recorded from a url, the machine interface
 * output the following information:
 * - url: Destination of the output stored in the snapshot.
 *
 * Otherwise, the machine interface output the data and ctrl url received
 * from the command-line.
 *
 * writer An instance of a machine interface writer.
 *
 * current_session_name: Snapshot record for session "current_session_name".
 *
 * ctrl_url, data_url: Destination of the output receive from the command-line.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_snapshot_record(struct mi_writer *writer,
		const char *current_session_name, const char *url,
		const char *cmdline_ctrl_url, const char *cmdline_data_url);

#endif /* _MI_LTTNG_H */
