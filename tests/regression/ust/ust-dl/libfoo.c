#include "libfoo.h"
#include "libbar.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "libfoo-tp.h"

int foo(void)
{
	tracepoint(libfoo, foo);
	bar();
	return 1;
}
