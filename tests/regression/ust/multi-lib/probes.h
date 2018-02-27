/*
 * Copyright (C) - 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER multi

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./probes.h"

#if !defined(PROBES_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define PROBES_H

#include <lttng/tracepoint.h>

#if defined(ACTIVATE_PROBES_A)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer(unsigned long, arg_long_A, arg)
    )
)
#elif defined(ACTIVATE_PROBES_B)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer(unsigned long, arg_long_B, arg)
        ctf_float(float, arg_float_B, (float) arg)
    )
)
#elif defined(ACTIVATE_PROBES_C)
TRACEPOINT_ENUM(multi, enum_a,
    TP_ENUM_VALUES(
        ctf_enum_value("FIELD_A", 0)
        ctf_enum_value("FIELD_B", 1)
        ctf_enum_range("RANGE_C", 2, 10)
    )
)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_enum(multi, enum_a, short, enum_short_C,  0)
        ctf_enum(multi, enum_a, int, enum_int_C,  1)
        ctf_enum(multi, enum_a, unsigned long, enum_long_C,  2)
    )
)
#elif defined(ACTIVATE_PROBES_D)
TRACEPOINT_ENUM(multi, enum_a,
    TP_ENUM_VALUES(
        ctf_enum_value("FIELD_A", 0)
        ctf_enum_value("FIELD_B", 1)
        ctf_enum_range("RANGE_C_PRIME", 2, 10)
    )
)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_enum(multi, enum_a, int, enum_int_D,  1)
        ctf_enum(multi, enum_a, short, enum_short_D,  0)
        ctf_enum(multi, enum_a, unsigned long, enum_long_D,  2)
    )
)
#elif defined(ACTIVATE_PROBES_E)
/*
 * Here we declare tracepoints really similar to one another but are different.
 * This is meant to test tracepoint comparaison code.
 */
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer(unsigned long, arg_long, arg)
    )
)
#elif defined(ACTIVATE_PROBES_F)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer(long, arg_long, arg)
    )
)
#elif defined(ACTIVATE_PROBES_G)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer_hex(long, arg_long, arg)
    )
)
#elif defined(ACTIVATE_PROBES_H)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer_hex(short, arg_long, arg)
    )
)
#elif defined(ACTIVATE_PROBES_I)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_integer_hex(int, arg_long, arg)
    )
)
#elif defined(ACTIVATE_PROBES_J)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_float(float, arg_float, (float) arg)
    )
)
#elif defined(ACTIVATE_PROBES_K)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_float(double, arg_float, (double) arg)
    )
)
#elif defined(ACTIVATE_PROBES_L)
TRACEPOINT_ENUM(multi, enum_a,
    TP_ENUM_VALUES(
        ctf_enum_value("FIELD_A", 0)
        ctf_enum_value("FIELD_B", 1)
        ctf_enum_range("RANGE_C", 2, 10)
    )
)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_enum(multi, enum_a, int, enum_int,  1)
    )
)
#elif defined(ACTIVATE_PROBES_M)
TRACEPOINT_ENUM(multi, enum_a,
    TP_ENUM_VALUES(
        ctf_enum_value("FIELD_A", 0)
        ctf_enum_value("FIELD_B", 1)
        ctf_enum_range("RANGE_C", 2, 10)
    )
)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_enum(multi, enum_a, long, enum_int,  1)
    )
)
#elif defined(ACTIVATE_PROBES_N)
TRACEPOINT_ENUM(multi, enum_a,
    TP_ENUM_VALUES(
        ctf_enum_value("FIELD_A", 0)
        ctf_enum_value("FIELD_B", 1)
        ctf_enum_range("RANGE_C", 2, 10)
    )
)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_enum(multi, enum_a, short, enum_int,  1)
    )
)
#elif defined(ACTIVATE_PROBES_O)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_string(arg_string, "string")
    )
)
#elif defined(ACTIVATE_PROBES_P)
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
        ctf_string(my_arg_string, "string")
    )
)
#else
TRACEPOINT_EVENT(multi, tp,
    TP_ARGS(unsigned long, arg),
    TP_FIELDS(
    )
)
#endif

#endif /* PROBES_H */

#include <lttng/tracepoint-event.h>
