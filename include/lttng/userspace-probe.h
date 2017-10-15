/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_USERSPACE_PROBE_H
#define LTTNG_USERSPACE_PROBE_H

#ifdef __cplusplus
extern "C" {
#endif

/* PROBE LOCATION LOOKUP METHOD */
struct lttng_userspace_probe_location_lookup_method;

enum lttng_userspace_probe_location_lookup_method_type {
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_UNKNOWN          = -1,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT = 0,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF     = 1,
};

/* DOCS */
extern enum lttng_userspace_probe_location_lookup_method_type
lttng_userspace_probe_location_lookup_method_get_type(
		struct lttng_userspace_probe_location_lookup_method *lookup_method);

/* DOCS */
extern void lttng_userspace_probe_location_lookup_method_destroy(
		struct lttng_userspace_probe_location_lookup_method *lookup_method);

/* DOCS */
extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_name_elf_create(void);


/* PROBE LOCATION */
struct lttng_userspace_probe_location;

enum lttng_userspace_probe_location_type {
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN	= -1,
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION	= 0,
};

/* DOCS */
extern enum lttng_userspace_probe_location_type lttng_userspace_probe_location_get_type(
		struct lttng_userspace_probe_location *location);

/* DOCS */
extern void lttng_userspace_probe_location_destroy(
		struct lttng_userspace_probe_location *location);

/* DOCS (ownership of the lookup method is transferred to the location). */
extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method);

/* DOCS */
extern const char *lttng_userspace_probe_location_function_get_binary_path(
		struct lttng_userspace_probe_location *location);

/* DOCS */
extern const char *lttng_userspace_probe_location_function_get_function_name(
		struct lttng_userspace_probe_location *location);

/* DOCS (ownership of the lookup method is NOT transferred. */
extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_function_get_lookup_method(
		struct lttng_userspace_probe_location *location);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_USERSPACE_PROBE_H */
