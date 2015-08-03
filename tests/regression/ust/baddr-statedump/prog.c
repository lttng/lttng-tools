#include <unistd.h>

#define TRACEPOINT_DEFINE
#include "tp.h"

int main()
{
	sleep(1);
	return 0;
}
