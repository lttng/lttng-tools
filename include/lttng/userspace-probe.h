/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

/*!
@addtogroup api_uprobe_loc
@{
*/

/*!
@struct lttng_userspace_probe_location_lookup_method

@brief
    Lookup method of a
    Linux <a href="https://lwn.net/Articles/499190/">user space probe</a>
    location (opaque type).
*/
struct lttng_userspace_probe_location_lookup_method;

/*!
@brief
    Linux user space probe location lookup method type.

Get the type of a Linux user space probe location lookup method
with lttng_userspace_probe_location_lookup_method_get_type().
*/
enum lttng_userspace_probe_location_lookup_method_type {
	/// Default.
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT = 0,

	/// Executable and Linkable Format (ELF) function.
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF = 1,

	/*!
	SystemTap Userland Statically Defined Tracing
	(USDT; a DTrace-style marker) probe.
	*/
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT = 2,

	/// Unknown (error).
	LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Returns the type of the
    Linux user space probe location lookup method \lt_p{lookup_method}.

@param[in] lookup_method
    Linux user space probe location lookup method
    of which to get the type.

@returns
    Type of \lt_p{lookup_method}.

@pre
    @lt_pre_not_null{lookup_method}
*/
LTTNG_EXPORT extern enum lttng_userspace_probe_location_lookup_method_type
lttng_userspace_probe_location_lookup_method_get_type(
	const struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*!
@brief
    Destroys the Linux user space probe location lookup method
    \lt_p{lookup_method}.

@param[in] lookup_method
    @parblock
    Linux user space probe location lookup method to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_userspace_probe_location_lookup_method_destroy(
	struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*!
@brief
    Creates an Executable and Linkable Format (ELF) Linux user space
    probe location lookup method.

@returns
    @parblock
    ELF Linux user space probe location lookup method with the type
    #LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF
    on success, or \c NULL on error.

    Destroy the returned lookup method with
    lttng_userspace_probe_location_lookup_method_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_function_elf_create(void);

/*!
@brief
    Creates an USDT probe Linux user space probe location lookup method.

@returns
    @parblock
    USDT Linux user space probe location lookup method with the type
    #LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT
    on success, or \c NULL on error.

    Destroy the returned lookup method with
    lttng_userspace_probe_location_lookup_method_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create(void);

/*!
@struct lttng_userspace_probe_location

@brief
    Linux <a href="https://lwn.net/Articles/499190/">user space probe</a>
    location (opaque type).
*/
struct lttng_userspace_probe_location;

/*!
@brief
    Return type of Linux user space probe location API functions.
*/
enum lttng_userspace_probe_location_status {
	/// Success.
	LTTNG_USERSPACE_PROBE_LOCATION_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_USERSPACE_PROBE_LOCATION_STATUS_INVALID = -1,
};

/*!
@brief
    Linux user space probe location type.

Get the type of a Linux user space probe location
with lttng_userspace_probe_location_get_type().
*/
enum lttng_userspace_probe_location_type {
	/// Function.
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION = 0,

	/// USDT probe.
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT = 1,

	/// Unknown (error).
	LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Returns the type of the
    Linux user space probe location \lt_p{location}.

@param[in] location
    Linux user space probe location of which to get the type.

@returns
    Type of \lt_p{location}.

@pre
    @lt_pre_not_null{location}
*/
LTTNG_EXPORT extern enum lttng_userspace_probe_location_type
lttng_userspace_probe_location_get_type(const struct lttng_userspace_probe_location *location);

/*!
@brief
    Destroys the Linux user space probe location \lt_p{location}.

@param[in] location
    @parblock
    Linux user space probe location to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void
lttng_userspace_probe_location_destroy(struct lttng_userspace_probe_location *location);

enum lttng_userspace_probe_location_function_instrumentation_type {
	LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_UNKNOWN = -1,
	/* Only instrument the function's entry. */
	LTTNG_USERSPACE_PROBE_LOCATION_FUNCTION_INSTRUMENTATION_TYPE_ENTRY = 0,
};

/*!
@brief
    Creates a Linux user space probe location at the entry of the
    function named \lt_p{function_name} within the binary
    \lt_p{binary_path} using the lookup method \lt_p{lookup_method}.

This function opens \lt_p{binary_path} and keeps the file open. Get the
resulting file descriptor with
lttng_userspace_probe_location_function_get_binary_fd().

@param[in] binary_path
    Path to the binary containing the function named
    \lt_p{function_name} to locate (copied).
@param[in] function_name
    Name of the function within \lt_p{binary_path} to locate (copied).
@param[in] lookup_method
    Lookup method (ownership moved to the returned location on success).

@returns
    @parblock
    Linux user space probe location with the type
    #LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION on success,
    or \c NULL on error.

    Destroy the returned location with
    lttng_userspace_probe_location_destroy().
    @endparblock

@pre
    @lt_pre_not_null{binary_path}
    @lt_pre_not_null{function_name}
    @lt_pre_not_null{lookup_method}
    @lt_pre_has_type{lookup_method,LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF}
*/
LTTNG_EXPORT extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_function_create(
	const char *binary_path,
	const char *function_name,
	struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*!
@brief
    Returns the binary path of the function Linux user space probe
    location \lt_p{location}.

@param[in] location
    Function Linux user space probe location of which to get the
    binary path.

@returns
    @parblock
    Binary path of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned string.

    The returned string remains valid as long as \lt_p{location}
    exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION}
*/
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_function_get_binary_path(
	const struct lttng_userspace_probe_location *location);

/*!
@brief
    Returns the function name of the function Linux user space probe
    location \lt_p{location}.

@param[in] location
    Function Linux user space probe location of which to get the
    function name.

@returns
    @parblock
    Function name of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned string.

    The returned string remains valid as long as \lt_p{location}
    exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION}
*/
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_function_get_function_name(
	const struct lttng_userspace_probe_location *location);

/*!
@brief
    Returns the file descriptor of the target binary of the function
    Linux user space probe location \lt_p{location}.

@param[in] location
    Function Linux user space probe location of which to get the
    binary file descriptor.

@returns
    Binary file descriptor of \lt_p{location}, or -1 on error.

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION}
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

/*!
@brief
    Returns the lookup method of the Linux user space probe
    location \lt_p{location}.

@param[in] location
    Linux user space probe location of which to get the lookup method.

@returns
    @parblock
    Lookup method of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned object.

    The returned object remains valid as long as \lt_p{location} exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
*/
LTTNG_EXPORT extern const struct lttng_userspace_probe_location_lookup_method *
lttng_userspace_probe_location_get_lookup_method(
	const struct lttng_userspace_probe_location *location);

/*!
@brief
    Creates a Linux user space probe location at the USDT probe
    named \lt_p{probe_name}, for the provider named
    \lt_p{provider_name}, within the binary
    \lt_p{binary_path} using the lookup method \lt_p{lookup_method}.

This function opens \lt_p{binary_path} and keeps the file open. Get the
resulting file descriptor with
lttng_userspace_probe_location_tracepoint_get_binary_fd().

@param[in] binary_path
    Path to the binary containing the USDT probe to locate (copied).
@param[in] probe_name
    Name of the USDT probe to locate within \lt_p{binary_path} (copied).
@param[in] provider_name
    Name of the provider of the USDT probe to locate
    within \lt_p{binary_path} (copied).
@param[in] lookup_method
    Lookup method (ownership moved to the returned location on success).

@returns
    @parblock
    Linux user space probe location with the type
    #LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT on success,
    or \c NULL on error.

    Destroy the returned location with
    lttng_userspace_probe_location_destroy().
    @endparblock

@pre
    @lt_pre_not_null{binary_path}
    @lt_pre_not_null{probe_name}
    @lt_pre_not_null{provider_name}
    @lt_pre_not_null{lookup_method}
    @lt_pre_has_type{lookup_method,LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT}
*/
LTTNG_EXPORT extern struct lttng_userspace_probe_location *
lttng_userspace_probe_location_tracepoint_create(
	const char *binary_path,
	const char *probe_name,
	const char *provider_name,
	struct lttng_userspace_probe_location_lookup_method *lookup_method);

/*!
@brief
    Returns the binary path of the USDT Linux user space probe
    location \lt_p{location}.

@param[in] location
    USDT Linux user space probe location of which to get the
    binary path.

@returns
    @parblock
    Binary path of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned string.

    The returned string remains valid as long as \lt_p{location}
    exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT}
*/
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_tracepoint_get_binary_path(
	const struct lttng_userspace_probe_location *location);

/*!
@brief
    Returns the probe name of the USDT Linux user space probe
    location \lt_p{location}.

@param[in] location
    USDT Linux user space probe location of which to get the
    probe name.

@returns
    @parblock
    Probe name of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned string.

    The returned string remains valid as long as \lt_p{location}
    exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT}
*/
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_tracepoint_get_probe_name(
	const struct lttng_userspace_probe_location *location);

/*!
@brief
    Returns the provider name of the USDT Linux user space probe
    location \lt_p{location}.

@param[in] location
    USDT Linux user space probe location of which to get the
    provider name.

@returns
    @parblock
    Probe name of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned string.

    The returned string remains valid as long as \lt_p{location}
    exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT}
*/
LTTNG_EXPORT extern const char *lttng_userspace_probe_location_tracepoint_get_provider_name(
	const struct lttng_userspace_probe_location *location);

/*!
@brief
    Returns the file descriptor of the target binary of the USDT
    Linux user space probe location \lt_p{location}.

@param[in] location
    USDT Linux user space probe location of which to get the
    binary file descriptor.

@returns
    Binary file descriptor of \lt_p{location}, or -1 on error.

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT}
*/
LTTNG_EXPORT extern int lttng_userspace_probe_location_tracepoint_get_binary_fd(
	const struct lttng_userspace_probe_location *location);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_USERSPACE_PROBE_H */
