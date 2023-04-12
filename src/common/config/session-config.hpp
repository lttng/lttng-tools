/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include <common/config/config-session-abi.hpp>
#include <common/macros.hpp>

#include <stdint.h>

struct config_load_session_override_attr {
	char *path_url;
	char *ctrl_url;
	char *data_url;
	char *session_name;
};

/* Instance of a configuration writer. */
struct config_writer;

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
struct config_writer *config_writer_create(int fd_output, int indent);

/*
 * Destroy an instance of a configuration writer.
 *
 * writer An instance of a configuration writer.
 *
 * Returns zero if the XML document could be closed cleanly. Negative values
 * indicate an error.
 */
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
int config_writer_open_element(struct config_writer *writer, const char *element_name);

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
int config_writer_write_attribute(struct config_writer *writer,
				  const char *name,
				  const char *value);

/*
 * Close the current element tag.
 *
 * writer An instance of a configuration writer.
 *
 * Returns zero if the XML document could be closed cleanly.
 * Negative values indicate an error.
 */
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
int config_writer_write_element_unsigned_int(struct config_writer *writer,
					     const char *element_name,
					     uint64_t value);

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
 */
int config_writer_write_element_signed_int(struct config_writer *writer,
					   const char *element_name,
					   int64_t value);

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
int config_writer_write_element_bool(struct config_writer *writer,
				     const char *element_name,
				     int value);

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
int config_writer_write_element_string(struct config_writer *writer,
				       const char *element_name,
				       const char *value);

/*
 * Write an element of type double.
 *
 * writer An instance of a configuration writer.
 *
 * element_name Element name.
 *
 * value Double value of the element
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int config_writer_write_element_double(struct config_writer *writer,
				       const char *element_name,
				       double value);

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
int config_load_session(const char *path,
			const char *session_name,
			int overwrite,
			unsigned int autoload,
			const struct config_load_session_override_attr *overrides);

#endif /* _CONFIG_H */
