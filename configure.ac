AC_INIT([lttng-tools], [2.0-pre11], [david.goulet@polymtl.ca], ,[http://lttng.org])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
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

# Check liburcu
AC_CHECK_DECL([cds_list_add], [],
	[AC_MSG_ERROR([liburcu 0.5.4 or newer is needed])], [[#include <urcu/list.h>]]
)

AC_PROG_CC
AC_PROG_LIBTOOL

CFLAGS="-Wall $CFLAGS -g -fno-strict-aliasing"

DEFAULT_INCLUDES="-I\$(top_srcdir) -I\$(top_builddir)"

lttngincludedir="${includedir}/lttng"

AC_SUBST(lttngincludedir)
AC_SUBST(DEFAULT_INCLUDES)

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	benchmark/Makefile
	libkernelctl/Makefile
	liblttngkconsumerd/Makefile
	liblttngctl/Makefile
	liblttng-sessiond-comm/Makefile
	libustctl/Makefile
	libustcomm/Makefile
	ltt-kconsumerd/Makefile
	ltt-sessiond/Makefile
	lttng/Makefile
	tests/Makefile
	doc/Makefile
])

AC_OUTPUT
