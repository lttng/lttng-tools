#include "libfoo.h"
#include "libbar.h"

int foo(void)
{
	bar();
	return 1;
}
