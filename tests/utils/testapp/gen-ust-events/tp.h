/*
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp

#if !defined(_TRACEPOINT_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_H

#include <lttng/tracepoint.h>

#include <stdint.h>

/* clang-format off */
TRACEPOINT_ENUM(tp,
	tptest_enum,
	TP_ENUM_VALUES(
		ctf_enum_auto("AUTO: EXPECT 0")
		ctf_enum_value("VALUE: 23", 23)
		ctf_enum_value("VALUE: 27", 27)
		ctf_enum_auto("AUTO: EXPECT 28")
		ctf_enum_range("RANGE: 101 TO 303", 101, 303)
		ctf_enum_auto("AUTO: EXPECT 304")
		ctf_enum_value("VALUE: -1", -1)
	)
)

TRACEPOINT_ENUM(tp,
	tptest_multi_range_enum,
	TP_ENUM_VALUES(
		ctf_enum_range("multiple ranges", 0, 99)
		ctf_enum_value("entry a", 100)
		ctf_enum_range("multiple ranges", 101, 199)
		ctf_enum_value("entry b", 200)
		ctf_enum_range("multiple ranges", 201, 299)
		ctf_enum_value("entry c", 300)
		ctf_enum_range("multiple ranges", 301, 1023)
	)
)

TRACEPOINT_EVENT(tp, tptest,
	TP_ARGS(
		int, anint,
		int, netint,
		long *, values,
		char *, text,
		size_t, textlen,
		char *, etext,
		uint32_t *, net_values,
		double, doublearg,
		float, floatarg
	),
	TP_FIELDS(
		ctf_integer(int, intfield, anint)
		ctf_integer_hex(int, intfield2, anint)
		ctf_integer(long, longfield, anint)
		ctf_integer(int, signedfield, -1)
		ctf_integer_network(int, netintfield, netint)
		ctf_integer_network_hex(int, netintfieldhex, netint)
		ctf_array(long, arrfield1, values, 3)
		ctf_array_text(char, arrfield2, text, 10)
		ctf_array_network(uint32_t, arrfield3, net_values, 3)
		ctf_sequence(char, seqfield1, text, size_t, textlen)
		ctf_sequence_text(char, seqfield2, text, size_t, textlen)
		ctf_sequence_network(uint32_t, seqfield3, net_values, size_t, 3)
		ctf_sequence(long, seqfield4, values, size_t, 3)
		ctf_string(stringfield, text)
		ctf_string(stringfield2, etext)
		ctf_float(float, floatfield, floatarg)
		ctf_float(double, doublefield, doublearg)
		ctf_enum(tp, tptest_enum, int, enum0, 0)
		ctf_enum(tp, tptest_enum, int, enum23, 23)
		ctf_enum(tp, tptest_enum, int, enum27, 27)
		ctf_enum(tp, tptest_enum, int, enum28, 28)
		ctf_enum(tp, tptest_enum, int, enum202, 202)
		ctf_enum(tp, tptest_enum, int, enum304, 304)
		ctf_enum(tp, tptest_enum, int, enumnegative, -1)
		/* Match 'multiple ranges'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum50, 50)
		/* Match 'entry a'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum100, 100)
		/* Match 'multiple ranges'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum150, 150)
		/* Match 'entry b'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum200, 200)
		/* Match 'multiple ranges'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum250, 250)
		/* Match 'entry c'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum300, 300)
		/* Match 'multiple ranges'. */
		ctf_enum(tp, tptest_multi_range_enum, int, enum500, 500)
	)
)
/* clang-format on */

TRACEPOINT_EVENT(tp, end, TP_ARGS(), TP_FIELDS())

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
