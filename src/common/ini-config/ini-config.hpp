/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef INI_CONFIG_H
#define INI_CONFIG_H

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
using config_entry_handler_cb = int (*)(const struct config_entry *, void *);

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
int config_get_section_entries(const char *path,
			       const char *section,
			       config_entry_handler_cb handler,
			       void *user_data);

/*
 * Parse a configuration value.
 *
 * This function expects either an unsigned integer or a boolean text option.
 * The following strings are recognized: true, yes, on, false, no and off.
 *
 * Returns either the value of the parsed integer, or 0/1 if a boolean text
 * string was recognized. Negative values indicate an error.
 */
int config_parse_value(const char *value);

#endif /* INI_CONFIG_H */
