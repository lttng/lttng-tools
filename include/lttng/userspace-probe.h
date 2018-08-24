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

/*
 * Userspace probe lookup methods specifies how the userspace probe location
 * specified by the user should be interpreted.
 */
struct lttng_userspace_probe_location_lookup_method;

enum lttng_userspace_probe_location_lookup_method_type {
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_UNKNOWN	    = -1,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT  = 0,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF	    = 1,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT    = 2,
};

/*
 * Get the type of a lookup method.
 */
extern enum lttng_userspace_probe_location_lookup_method_type
lttng_userspace_probe_location_lookup_method_get_type(
		const struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Destroy a lookup method.
 */
extern void lttng_userspace_probe_location_lookup_method_destroy(
		struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Create a tracepoint ELF function lookup method struct.
 * Return NULL on failure.
 */
extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_elf_create(void);

/*
 * Create a tracepoint SDT tracepoint lookup method struct.
 * Return NULL on failure.
 */
extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create(void);


/*
 * Contains all the information needed to compute the instrumentation point in
 * the binary. It is used in conjonction with a lookup method.
 */
struct lttng_userspace_probe_location;

enum lttng_userspace_probe_location_type {
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN	= -1,
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION	= 0,
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT	= 1,
};

/*
 * Get the type of the userspace probe location.
 */
extern enum lttng_userspace_probe_location_type
lttng_userspace_probe_location_get_type(
		const struct lttng_userspace_probe_location *location);

/*
 * Destroy the userspace probe location.
 */
extern void lttng_userspace_probe_location_destroy(
		struct lttng_userspace_probe_location *location);

/*
 * Create a probe location of the function type.
 * Receives the target binary file path and function to instrument.
 * On failure, NULL is returned.
 *
 * The ownership of the lookup method is transferred to the created probe
 * location.
 */
extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create(const char *binary_path,
		const char *function_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Get the target binary path of the probe location of the function type.
 */
extern const char *lttng_userspace_probe_location_function_get_binary_path(
		const struct lttng_userspace_probe_location *location);

/*
 * Get the target function type of the probe location of the function type.
 */
extern const char *lttng_userspace_probe_location_function_get_function_name(
		const struct lttng_userspace_probe_location *location);

/*
 * Get the FD to the target binary file to the probe location of the function
 * type.
 */
extern int lttng_userspace_probe_location_function_get_binary_fd(
		const struct lttng_userspace_probe_location *location);

/*
 * Get the lookup method of the given userspace probe location.
 * Returns NULL if the probe location type is unsupported.
 *
 * The ownership of the lookup method is NOT transferred to the caller.
 */
extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_get_lookup_method(
		const struct lttng_userspace_probe_location *location);

/*
 * Create a probe location of the tracepoint type.
 * Receives the target binary file path, probename and probe provider to
 * instrument.
 * On failure, NULL is returned.
 *
 * The ownership of the lookup method is transferred to the created probe
 * location.
 */
extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_create(const char *binary_path,
		const char *probe_name, const char *provider_name,
		struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Get the target binary path of the probe location of the tracepoint type.
 */
extern const char *lttng_userspace_probe_location_tracepoint_get_binary_path(
		const struct lttng_userspace_probe_location *location);

/*
 * Get the target probe name of the probe location of the tracepoint type.
 */
extern const char *lttng_userspace_probe_location_tracepoint_get_probe_name(
		const struct lttng_userspace_probe_location *location);

/*
 * Get the target probe provider name of the probe location of the tracepoint
 * type.
 */
extern const char *lttng_userspace_probe_location_tracepoint_get_provider_name(
		const struct lttng_userspace_probe_location *location);

/*
 * Get the FD to the target binary file to the probe location of the tracepoint
 * type.
 */
extern int lttng_userspace_probe_location_tracepoint_get_binary_fd(
		const struct lttng_userspace_probe_location *location);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_USERSPACE_PROBE_H */
