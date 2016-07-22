#include "libzzz.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "libzzz-tp.h"

int zzz(void)
{
	tracepoint(libzzz, zzz);
	return 1;
}
