/*
 * SPDX-FileCopyrightText: 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_KERNEL_PROBE_H
#define LTTNG_KERNEL_PROBE_H

#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_kprobe_loc
@{
*/

/*!
@struct lttng_kernel_probe_location

@brief
    Linux <a href="https://www.kernel.org/doc/html/latest/trace/kprobes.html">kprobe</a>
    location (opaque type).
*/
struct lttng_kernel_probe_location;

/*!
@brief
    Return type of Linux kprobe location API functions.
*/
enum lttng_kernel_probe_location_status {
	/// Success.
	LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_KERNEL_PROBE_LOCATION_STATUS_INVALID = -1,
};

/*!
@brief
    Linux kprobe location type.

Get the type of a Linux kprobe location with
lttng_kernel_probe_location_get_type().
*/
enum lttng_kernel_probe_location_type {
	/// Offset from a named symbol.
	LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET = 0,

	/// Address within the kernel.
	LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS = 1,

	/// Unknown (error).
	LTTNG_KERNEL_PROBE_LOCATION_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Returns the type of the Linux kprobe location \lt_p{location}.

@param[in] location
    Linux kprobe location of which to get the type.

@returns
    Type of \lt_p{location}.

@pre
    @lt_pre_not_null{location}
*/
LTTNG_EXPORT extern enum lttng_kernel_probe_location_type
lttng_kernel_probe_location_get_type(const struct lttng_kernel_probe_location *location);

/*!
@brief
    Destroys the Linux kprobe location \lt_p{location}.

@param[in] location
    @parblock
    Linux kprobe location to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void
lttng_kernel_probe_location_destroy(struct lttng_kernel_probe_location *location);

/*!
@brief
    Creates a Linux kprobe location at the offset \lt_p{offset} bytes
    from the kernel symbol named \lt_p{symbol}.

@param[in] symbol_name
    Symbol name of the Linux kprobe location to create (copied).
@param[in] offset
    Offset (bytes) from \lt_p{symbol} of the Linux kprobe location
    to create.

@returns
    @parblock
    Linux kprobe location with the type
    #LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET on success,
    or \c NULL on error.

    Destroy the returned location with
    lttng_kernel_probe_location_destroy().
    @endparblock

@pre
    @lt_pre_not_null{symbol_name}
*/
LTTNG_EXPORT extern struct lttng_kernel_probe_location *
lttng_kernel_probe_location_symbol_create(const char *symbol_name, uint64_t offset);

/*!
@brief
    Returns the symbol name of the
    Linux kprobe location \lt_p{location}.

@param[in] location
    Linux kprobe location of which to get the symbol name.

@returns
    @parblock
    Symbol name of \lt_p{location}, or \c NULL on error.

    \lt_p{location} owns the returned string.

    The returned string remains valid as long as \lt_p{location}
    exists.
    @endparblock

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET}

@sa lttng_kernel_probe_location_symbol_get_offset() --
    Get the offset from symbol of a Linux kprobe location.
*/
LTTNG_EXPORT extern const char *
lttng_kernel_probe_location_symbol_get_name(const struct lttng_kernel_probe_location *location);

/*!
@brief
    Sets \lt_p{*offset} to the offset from symbol of the
    Linux kprobe location \lt_p{location}.

@param[in] location
    Linux kprobe location of which to get the offset from symbol.
@param[out] offset
    <strong>On success</strong>, this function sets \lt_p{*offset}
    to the offset (bytes) from symbol of \lt_p{location}.

@retval #LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK
    Success.
@retval #LTTNG_KERNEL_PROBE_LOCATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET}
    @lt_pre_not_null{offset}

@sa lttng_kernel_probe_location_symbol_get_name() --
    Get the symbol name of a Linux kprobe location.
*/
LTTNG_EXPORT extern enum lttng_kernel_probe_location_status
lttng_kernel_probe_location_symbol_get_offset(const struct lttng_kernel_probe_location *location,
					      uint64_t *offset);

/*!
@brief
    Creates a Linux kprobe location at the address \lt_p{address} bytes
    within the kernel.

@param[in] address
    Address (bytes) within the kernel of the
    Linux kprobe location to create.

@returns
    @parblock
    Linux kprobe location with the type
    #LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS on success,
    or \c NULL on error.

    Destroy the returned location with
    lttng_kernel_probe_location_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_kernel_probe_location *
lttng_kernel_probe_location_address_create(uint64_t address);

/*!
@brief
    Sets \lt_p{*address} to the address within the kernel of the
    Linux kprobe location \lt_p{location}.

@param[in] location
    Linux kprobe location of which to get the address within the
    kernel.
@param[out] address
    <strong>On success</strong>, this function sets \lt_p{*address}
    to the address (bytes) within the kernel of \lt_p{location}.

@retval #LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK
    Success.
@retval #LTTNG_KERNEL_PROBE_LOCATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{location}
    @lt_pre_has_type{location,LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS}
    @lt_pre_not_null{address}
*/
LTTNG_EXPORT extern enum lttng_kernel_probe_location_status
lttng_kernel_probe_location_address_get_address(const struct lttng_kernel_probe_location *location,
						uint64_t *address);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_KERNEL_PROBE_H */
