#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER my_provider

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

#if !defined(_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
		my_provider,
		my_first_tracepoint,
		TP_ARGS(
		int, my_integer_arg,
		char*, my_string_arg
	),
	TP_FIELDS(
		ctf_string(my_string_field, my_string_arg)
		ctf_integer(int, my_integer_field, my_integer_arg)
	)
)

#endif /* _TP_H */

#include <lttng/tracepoint-event.h>
