AC_INIT([lttng-tools], [0.0.1], [david.goulet@polymtl.ca], [http://lttng.org])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AC_CHECK_HEADERS([ \
	sys/types.h unistd.h fcntl.h string.h pthread.h limits.h \
	signal.h stdlib.h sys/un.h sys/socket.h stdlib.h stdio.h \
	getopt.h sys/ipc.h sys/shm.h popt.h grp.h \
])

# Check for pthread
AC_CHECK_LIB([pthread], [pthread_create], [],
	[AC_MSG_ERROR([Cannot find libpthread. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Check libpopt
AC_CHECK_LIB([popt], [poptGetContext], [],
	[AC_MSG_ERROR([Cannot find libpopt. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Check libuuid
AC_CHECK_LIB([uuid], [uuid_generate], [],
	[AC_MSG_ERROR([Cannot find libuuid. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Check liburcu
AC_CHECK_DECL([cds_list_add], [],
	[AC_MSG_ERROR([liburcu 0.5.4 or newer is needed])], [[#include <urcu/list.h>]]
)

CFLAGS="-Wall $CFLAGS -g -fno-strict-aliasing"

AC_PROG_CC
AC_PROG_LIBTOOL

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	libkernelctl/Makefile
	liblttkconsumerd/Makefile
	liblttngctl/Makefile
	liblttsessiondcomm/Makefile
	libustctl/Makefile
	libustcomm/Makefile
	ltt-sessiond/Makefile
	lttng/Makefile
	kconsumerd/Makefile
	tests/Makefile
	tests/ltt-sessiond/Makefile
])

AC_OUTPUT
