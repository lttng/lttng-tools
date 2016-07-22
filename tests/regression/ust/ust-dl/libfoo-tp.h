#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER libfoo

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./libfoo-tp.h"

#if !defined(_LIBFOO_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _LIBFOO_TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    libfoo,
    foo,
    TP_ARGS(void),
    TP_FIELDS()
)

#endif /* _LIBFOO_TP_H */

#include <lttng/tracepoint-event.h>
