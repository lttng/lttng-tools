#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER libbar

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./libbar-tp.h"

#if !defined(_LIBBAR_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _LIBBAR_TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    libbar,
    bar,
    TP_ARGS(void),
    TP_FIELDS()
)

#endif /* _LIBBAR_TP_H */

#include <lttng/tracepoint-event.h>
