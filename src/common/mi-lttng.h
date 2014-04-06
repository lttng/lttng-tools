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
const char * const mi_lttng_element_version_patch_level;
const char * const mi_lttng_element_version_description;

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
 *
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
 *
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
 * Write an element of type unsigned int.
 *
 * writer An instance of a machine interface writer.
 *
 * element_name Element name.
 *
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
 *
 * element_name Element name.
 *
 * value Signed int value of the element
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
 *
 * element_name Element name.
 *
 * value Boolean value of the element
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
 *
 * element_name Element name.
 *
 * value String value of the element
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
 *
 * version Version struct.
 *
 * lttng_description String value of the version description.
 *
 * lttng_license String value of the version license.
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_version(struct mi_writer *writer, struct mi_lttng_version *version,
		const char *lttng_description, const char *lttng_license);

/*
 * Machine interface of struct session.
 *
 * writer An instance of a machine interface writer
 *
 * session An instance of a session
 *
 * isOpen Define if we close the session element
 *        This should be use carefully and the client
 *        need to close the session element.
 *        Use case: nested addition information on a session
 *                  ex: domain,channel event.
 *        0-> False
 *        1-> True
 *
 * Returns zero if the element's value could be written.
 * Negative values indicate an error.
 */
int mi_lttng_session(struct mi_writer *writer,
		struct lttng_session *session, int isOpen);

#endif /* _MI_LTTNG_H */
