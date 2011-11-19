AC_INIT([lttng-tools], [2.0-pre14], [david.goulet@polymtl.ca], ,[http://lttng.org])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADERS([include/config.h])

AC_CHECK_HEADERS([ \
	sys/types.h unistd.h fcntl.h string.h pthread.h limits.h \
	signal.h stdlib.h sys/un.h sys/socket.h stdlib.h stdio.h \
	getopt.h sys/ipc.h sys/shm.h popt.h grp.h \
])

AC_ARG_VAR([LTTNG_TOOLS_COMPAT_BIN_DIR], [Search for LTTng Tools 32-bit compatibility binaries in this location.])
AC_DEFINE_UNQUOTED([CONFIG_COMPAT_BIN_DIR], $LTTNG_TOOLS_COMPAT_BIN_PREFIX, [Search for LTTng Tools 32-bit compatibility binaries in this location.])

# Check for pthread
AC_CHECK_LIB([pthread], [pthread_create], [],
	[AC_MSG_ERROR([Cannot find libpthread. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Check libpopt
AC_CHECK_LIB([popt], [poptGetContext], [],
	[AC_MSG_ERROR([Cannot find libpopt. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# URCU library version needed or newer
liburcu_version=">= 0.6.6"

# Check liburcu needed function calls
AC_CHECK_DECL([cds_list_add], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/list.h>]]
)
AC_CHECK_DECL([cds_wfq_init], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/wfqueue.h>]]
)
AC_CHECK_DECL([cds_wfq_dequeue_blocking], [],
    [AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/wfqueue.h>]]
)
AC_CHECK_DECL([futex_async], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/futex.h>]]
)
AC_CHECK_DECL([rcu_thread_offline], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu.h>]]
)
AC_CHECK_DECL([rcu_thread_online], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu.h>]]
)
AC_CHECK_DECL([caa_likely], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu.h>]]
)

# Check liblttng-ust-ctl library
AC_ARG_ENABLE(lttng-ust,
	[  --disable-lttng-ust     build without LTTng-UST (Userspace Tracing) support.],
	lttng_ust_support=no, lttng_ust_support=yes)

[
if test "x$lttng_ust_support" = "xno"; then
	echo "LTTng-UST support disabled."
else
]
	AC_CHECK_LIB([lttng-ust-ctl], [ustctl_create_session], [],
		[AC_MSG_ERROR([Cannot find LTTng-UST. Use [LDFLAGS]=-Ldir to specify its location, or specify --disable-lttng-ust to build lttng-tools without LTTng-UST support.])]
	)
[
	echo "LTTng-UST support enabled."
fi
]

AM_CONDITIONAL([HAVE_LIBLTTNG_UST_CTL], [ test "x$ac_cv_lib_lttng_ust_ctl_ustctl_create_session" = "xyes" ])

AC_CHECK_FUNCS([sched_getcpu sysconf])

# Epoll check. If not present, the build will fallback on poll() API
AX_HAVE_EPOLL(
	[AX_CONFIG_FEATURE_ENABLE(epoll)],
	[AX_CONFIG_FEATURE_DISABLE(epoll)]
)
AX_CONFIG_FEATURE(
	[epoll], [This platform supports epoll(7)],
	[HAVE_EPOLL], [This platform supports epoll(7).],
	[enable_epoll="yes"], [enable_epoll="no"]
)
AM_CONDITIONAL([COMPAT_EPOLL], [ test "$enable_epoll" = "yes" ])

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
	libkernelctl/Makefile
	liblttng-consumer/Makefile
	liblttng-kconsumer/Makefile
	liblttng-ustconsumer/Makefile
	liblttngctl/Makefile
	liblttng-sessiond-comm/Makefile
	lttng-consumerd/Makefile
	lttng-sessiond/Makefile
	lttng/Makefile
	tests/Makefile
	doc/Makefile
])

AC_OUTPUT
