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
#include <common/macros.h>

struct config_entry {
	/* section is NULL if the entry is not in a section */
	const char *section;
	const char *name;
	const char *value;
};

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
 * is positive, it represents the line number on which a parsing error occured.
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

#endif /* _CONFIG_H */
