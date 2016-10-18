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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <common/config/ini.h>
#include <common/config/config-session-abi.h>
#include <common/macros.h>
#include <stdint.h>

struct config_entry {
	/* section is NULL if the entry is not in a section */
	const char *section;
	const char *name;
	const char *value;
};

struct config_load_session_override_attr {
	char *path_url;
	char *ctrl_url;
	char *data_url;
	char *session_name;
};

/* Instance of a configuration writer. */
struct config_writer;

/*
 * A config_entry_handler_cb receives config_entry structures belonging to the
 * sections the handler has been registered to.
 *
 * The config_entry and its members are only valid for the duration of the call
 * and must not be freed.
 *
 * config_entry_handler_cb may return negative value to indicate an error in
 * the configuration file.
 */
typedef int (*config_entry_handler_cb)(const struct config_entry *, void *);

/*
 * Read a section's entries in an INI configuration file.
 *
 * path may be NULL, in which case the following paths will be tried:
 *	1) $HOME/.lttng/lttng.conf
 *	2) /etc/lttng/lttng.conf
 *
 * handler will only be called with entries belonging to the provided section.
 * If section is NULL, all entries will be relayed to handler. If section is
 * "", only the global entries are relayed.
 *
 * Returns 0 on success. Negative values are error codes. If the return value
 * is positive, it represents the line number on which a parsing error occurred.
 */
LTTNG_HIDDEN
int config_get_section_entries(const char *path, const char *section,
		config_entry_handler_cb handler, void *user_data);

/*
 * Parse a configuration value.
 *
 * This function expects either an unsigned integer or a boolean text option.
 * The following strings are recognized: true, yes, on, false, no and off.
 *
 * Returns either the value of the parsed integer, or 0/1 if a boolean text
 * string was recognized. Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_parse_value(const char *value);

/*
 * Create an instance of a configuration writer.
 *
 * fd_output File to which the XML content must be written. fd_output is
 * owned by the caller.
 *
 * indent If other than 0 the XML will be pretty printed
 * with indentation and newline.
 *
 * Returns an instance of a configuration writer on success, NULL on
 * error.
 */
LTTNG_HIDDEN
struct config_writer *config_writer_create(int fd_output, int indent);

/*
 * Destroy an instance of a configuration writer.
 *
 * writer An instance of a configuration writer.
 *
 * Returns zero if the XML document could be closed cleanly. Negative values
 * indicate an error.
 */
LTTNG_HIDDEN
int config_writer_destroy(struct config_writer *writer);

/*
 * Open an element tag.
 *
 * writer An instance of a configuration writer.
 *
 * element_name Element tag name.
 *
 * Returns zero if the XML element could be opened.
 * Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_writer_open_element(struct config_writer *writer,
		const char *element_name);

/*
 * Write an element tag attribute.
 *
 * writer An instance of a configuration writer.
 *
 * name Attribute name.
 *
 * Returns zero if the XML element's attribute could be written.
 * Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_writer_write_attribute(struct config_writer *writer,
		const char *name, const char *value);

/*
 * Close the current element tag.
 *
 * writer An instance of a configuration writer.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_writer_close_element(struct config_writer *writer);

/*
 * Write an element of type unsigned int.
 *
 * writer An instance of a configuration writer.
 *
 * element_name Element name.
 *
 * value Unsigned int value of the element
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_writer_write_element_unsigned_int(struct config_writer *writer,
		const char *element_name, uint64_t value);

/*
 * Write an element of type signed int.
 *
 * writer An instance of a configuration writer.
 *
 * element_name Element name.
 *
 * value Signed int value of the element
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */LTTNG_HIDDEN
int config_writer_write_element_signed_int(struct config_writer *writer,
		const char *element_name, int64_t value);

/*
 * Write an element of type boolean.
 *
 * writer An instance of a configuration writer.
 *
 * element_name Element name.
 *
 * value Boolean value of the element
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_writer_write_element_bool(struct config_writer *writer,
		const char *element_name, int value);

/*
 * Write an element of type string.
 *
 * writer An instance of a configuration writer.
 *
 * element_name Element name.
 *
 * value String value of the element
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
LTTNG_HIDDEN
int config_writer_write_element_string(struct config_writer *writer,
		const char *element_name, const char *value);

/*
 * Load session configurations from a file.
 *
 * path Path to an LTTng session configuration file. All *.lttng files
 * will be loaded if path is a directory. If path is NULL, the default
 * paths will be searched in the following order:
 *	1) $HOME/.lttng/sessions
 *	2) /etc/lttng/sessions
 *
 * session_name Name of the session to load. Will load all
 * sessions from path if NULL.
 *
 * overwrite Overwrite current session configuration if it exists.
 * autoload Tell to load the auto session(s).
 * overrides The override attribute structure specifying override parameters.
 *
 * Returns zero if the session could be loaded successfully. Returns
 * a negative LTTNG_ERR code on error.
 */
LTTNG_HIDDEN
int config_load_session(const char *path, const char *session_name,
		int overwrite, unsigned int autoload,
		const struct config_load_session_override_attr *overrides);

#endif /* _CONFIG_H */
