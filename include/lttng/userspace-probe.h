/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_USERSPACE_PROBE_H
#define LTTNG_USERSPACE_PROBE_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Userspace probe lookup methods specifies how the userspace probe location
 * specified by the user should be interpreted.
 */
struct lttng_userspace_probe_location_lookup_method;

enum lttng_userspace_probe_location_lookup_method_type {
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_UNKNOWN = -1,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT = 0,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF = 1,
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT = 2,
};

/*
 * Get the type of a lookup method.
 */
LTTNG_EXPORT extern enum lttng_userspace_probe_location_lookup_method_type
lttng_userspace_probe_location_lookup_method_get_type(
	const struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Destroy a lookup method.
 */
LTTNG_EXPORT extern void lttng_userspace_probe_location_lookup_method_destroy(
	struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Create a tracepoint ELF function lookup method struct.
 * Return NULL on failure.
 */
LTTNG_EXPORT extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_elf_create(void);

/*
 * Create a tracepoint SDT tracepoint lookup method struct.
 * Return NULL on failure.
 */
LTTNG_EXPORT extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create(void);

/*
 * Contains all the information needed to compute the instrumentation point in
 * the binary. It is used in conjonction with a lookup method.
 */
struct lttng_userspace_probe_location;

enum lttng_userspace_probe_location_status {
	LTTNG_USERSPACE_PROBE_LOCATION_STATUS_OK = 0,
	/* Invalid parameters provided. */
	LTTNG_USERSPACE_PROBE_LOCATION_STATUS_INVALID = -1,
};

enum lttng_userspace_probe_location_type {
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN = -1,
	/* Function. */
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION = 0,
	/* SDT probe's callsites. */
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT = 1,
};

/*
 * Get the type of the userspace probe location.
 */
LTTNG_EXPORT extern enum lttng_userspace_probe_location_type
lttng_userspace_probe_location_get_type(const struct lttng_userspace_probe_location *location);

/*
 * Destroy the userspace probe location.
 */
LTTNG_EXPORT extern void
lttng_userspace_probe_location_destroy(struct lttng_userspace_probe_location *location);

enum lttng_userspace_probe_location_function_instrumentation_type {
	LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_UNKNOWN = -1,
	/* Only instrument the function's entry. */
	LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_ENTRY = 0,
};

/*
 * Create a probe location of the function type.
 * Receives the target binary file path and function to instrument.
 * On failure, NULL is returned.
 *
 * The ownership of the lookup method is transferred to the created probe
 * location.
 */
LTTNG_EXPORT extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create(
	const char *binary_path,
	const char *function_name,
	struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Get the target binary path of the probe location of the function type.
 */
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_function_get_binary_path(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the target function type of the probe location of the function type.
 */
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_function_get_function_name(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the FD to the target binary file to the probe location of the function
 * type. The FD is only valid for the duration of the lifetime of `location`.
 */
LTTNG_EXPORT extern int lttng_userspace_probe_location_function_get_binary_fd(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the instrumentation type of the function probe location.
 */
LTTNG_EXPORT extern enum lttng_userspace_probe_location_function_instrumentation_type
lttng_userspace_probe_location_function_get_instrumentation_type(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the instrumentation type of the function probe location.
 * Defaults to
 * LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_ENTRY.
 *
 * Returns LTTNG_USERSPACE_PROBE_LOCATION_STATUS_OK on success,
 * LTTNG_USERSPACE_PROBE_LOCATION_STATUS_INVALID if invalid parameters
 * are provided.
 */
LTTNG_EXPORT extern enum lttng_userspace_probe_location_status
lttng_userspace_probe_location_function_set_instrumentation_type(
	const struct lttng_userspace_probe_location *location,
	enum lttng_userspace_probe_location_function_instrumentation_type instrumentation_type);

/*
 * Get the lookup method of the given userspace probe location.
 * Returns NULL if the probe location type is unsupported.
 *
 * The ownership of the lookup method is NOT transferred to the caller.
 */
LTTNG_EXPORT extern const struct lttng_userspace_probe_location_lookup_method *
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
LTTNG_EXPORT extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_create(
	const char *binary_path,
	const char *probe_name,
	const char *provider_name,
	struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*
 * Get the target binary path of the probe location of the tracepoint type.
 */
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_tracepoint_get_binary_path(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the target probe name of the probe location of the tracepoint type.
 */
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_tracepoint_get_probe_name(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the target probe provider name of the probe location of the tracepoint
 * type.
 */
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_tracepoint_get_provider_name(
	const struct lttng_userspace_probe_location *location);

/*
 * Get the FD to the target binary file to the probe location of the tracepoint
 * type. The FD is only valid for the duration of the lifetime of `location`.
 */
LTTNG_EXPORT extern int lttng_userspace_probe_location_tracepoint_get_binary_fd(
	const struct lttng_userspace_probe_location *location);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_USERSPACE_PROBE_H */
