#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER libzzz

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./libzzz-tp.h"

#if !defined(_LIBZZZ_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _LIBZZZ_TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    libzzz,
    zzz,
    TP_ARGS(void),
    TP_FIELDS()
)

#endif /* _LIBZZZ_TP_H */

#include <lttng/tracepoint-event.h>
