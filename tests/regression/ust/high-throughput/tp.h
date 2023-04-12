/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp

#if !defined(_TRACEPOINT_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	tp,
	tptest,
	TP_ARGS(int,
		anint,
		int,
		netint,
		long *,
		values,
		char *,
		text,
		size_t,
		textlen,
		double,
		doublearg,
		float,
		floatarg),
	TP_FIELDS(ctf_integer(int, intfield, anint) ctf_integer_hex(
		int, intfield2, anint) ctf_integer(long, longfield, anint)
			  ctf_integer_network(int, netintfield, netint) ctf_integer_network_hex(
				  int, netintfieldhex, netint) ctf_array(long, arrfield1, values, 3)
				  ctf_array_text(char, arrfield2, text, 10) ctf_sequence(
					  char, seqfield1, text, size_t, textlen)
					  ctf_sequence_text(char, seqfield2, text, size_t, textlen)
						  ctf_string(stringfield, text)
							  ctf_float(float, floatfield, floatarg)
								  ctf_float(double,
									    doublefield,
									    doublearg)))

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
