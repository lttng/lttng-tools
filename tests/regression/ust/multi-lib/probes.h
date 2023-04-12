/*
 * Copyright (C) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER multi

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./probes.h"

#if !defined(PROBES_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define PROBES_H

#include <lttng/tracepoint.h>

#include <stdint.h>

#if defined(ACTIVATE_PROBES_A)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_integer(uint64_t, arg_long_A, arg)))
#elif defined(ACTIVATE_PROBES_B)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_integer(uint64_t, arg_long_B, arg)
				   ctf_float(float, arg_float_B, (float) arg)))
#elif defined(ACTIVATE_PROBES_C)
TRACEPOINT_ENUM(multi,
		enum_a,
		TP_ENUM_VALUES(ctf_enum_value("FIELD_A", 0) ctf_enum_value("FIELD_B", 1)
				       ctf_enum_range("RANGE_C", 2, 10)))
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_enum(multi, enum_a, int16_t, enum_short_C, 0)
				   ctf_enum(multi, enum_a, int32_t, enum_int_C, 1)
					   ctf_enum(multi, enum_a, uint64_t, enum_long_C, 2)))
#elif defined(ACTIVATE_PROBES_D)
TRACEPOINT_ENUM(multi,
		enum_a,
		TP_ENUM_VALUES(ctf_enum_value("FIELD_A", 0) ctf_enum_value("FIELD_B", 1)
				       ctf_enum_range("RANGE_C_PRIME", 2, 10)))
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_enum(multi, enum_a, int32_t, enum_int_D, 1)
				   ctf_enum(multi, enum_a, int16_t, enum_short_D, 0)
					   ctf_enum(multi, enum_a, uint64_t, enum_long_D, 2)))
#elif defined(ACTIVATE_PROBES_E)
/*
 * Here we declare tracepoints really similar to one another but are different.
 * This is meant to test tracepoint comparaison code.
 */
TRACEPOINT_EVENT(multi, tp, TP_ARGS(uint64_t, arg), TP_FIELDS(ctf_integer(uint64_t, arg_long, arg)))
#elif defined(ACTIVATE_PROBES_F)
TRACEPOINT_EVENT(multi, tp, TP_ARGS(uint64_t, arg), TP_FIELDS(ctf_integer(int64_t, arg_long, arg)))
#elif defined(ACTIVATE_PROBES_G)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_integer_hex(int64_t, arg_long, arg)))
#elif defined(ACTIVATE_PROBES_H)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_integer_hex(int16_t, arg_long, arg)))
#elif defined(ACTIVATE_PROBES_I)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_integer_hex(int32_t, arg_long, arg)))
#elif defined(ACTIVATE_PROBES_J)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_float(float, arg_float, (float) arg)))
#elif defined(ACTIVATE_PROBES_K)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_float(double, arg_float, (double) arg)))
#elif defined(ACTIVATE_PROBES_L)
TRACEPOINT_ENUM(multi,
		enum_a,
		TP_ENUM_VALUES(ctf_enum_value("FIELD_A", 0) ctf_enum_value("FIELD_B", 1)
				       ctf_enum_range("RANGE_C", 2, 10)))
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_enum(multi, enum_a, int32_t, enum_int, 1)))
#elif defined(ACTIVATE_PROBES_M)
TRACEPOINT_ENUM(multi,
		enum_a,
		TP_ENUM_VALUES(ctf_enum_value("FIELD_A", 0) ctf_enum_value("FIELD_B", 1)
				       ctf_enum_range("RANGE_C", 2, 10)))
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_enum(multi, enum_a, int64_t, enum_int, 1)))
#elif defined(ACTIVATE_PROBES_N)
TRACEPOINT_ENUM(multi,
		enum_a,
		TP_ENUM_VALUES(ctf_enum_value("FIELD_A", 0) ctf_enum_value("FIELD_B", 1)
				       ctf_enum_range("RANGE_C", 2, 10)))
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_enum(multi, enum_a, int16_t, enum_int, 1)))
#elif defined(ACTIVATE_PROBES_O)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_string(arg_string, "string")))
#elif defined(ACTIVATE_PROBES_P)
TRACEPOINT_EVENT(multi,
		 tp,
		 TP_ARGS(uint64_t, arg),
		 TP_FIELDS(ctf_unused(arg) ctf_string(my_arg_string, "string")))
#else
TRACEPOINT_EVENT(multi, tp, TP_ARGS(uint64_t, arg), TP_FIELDS(ctf_unused(arg)))
#endif

#endif /* PROBES_H */

#include <lttng/tracepoint-event.h>
