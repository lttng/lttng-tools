AC_INIT([lttng-tools],[2.0.0],[dgoulet@efficios.com],[],[http://lttng.org])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

version_name="Annedd'ale"
version_description="New type of beer, 100% from Quebec, flavored with sapin beaumier needles, with a touch of hops."

AC_DEFINE_UNQUOTED([VERSION_NAME], ["$version_name"], "")
AC_DEFINE_UNQUOTED([VERSION_DESCRIPTION], ["$version_description"], "")

AC_CONFIG_HEADERS([include/config.h])

AC_CHECK_HEADERS([ \
	sys/types.h unistd.h fcntl.h string.h pthread.h limits.h \
	signal.h stdlib.h sys/un.h sys/socket.h stdlib.h stdio.h \
	getopt.h sys/ipc.h sys/shm.h popt.h grp.h \
])

# Babeltrace viewer check
AC_ARG_WITH([babeltrace-bin],
	AS_HELP_STRING([--with-babeltrace-bin],
	[Location of the babeltrace viewer executable (including the filename)]),
	[BABELTRACE_BIN="$withval"],
	[BABELTRACE_BIN=''])
AC_SUBST([BABELTRACE_BIN])

# lttv-gui
AC_ARG_WITH([lttv-gui-bin],
	AS_HELP_STRING([--with-lttv-gui-bin],
   [Location of the lttv GUI viewer executable (including the filename)]),
   [LTTV_GUI_BIN="$withval"],
   [LTTV_GUI_BIN=''])
AC_SUBST([LTTV_GUI_BIN])

AC_ARG_WITH([consumerd32-bin],
	AS_HELP_STRING([--with-consumerd32-bin],
	[Location of the 32-bit consumerd executable (including the filename)]),
	[CONSUMERD32_BIN="$withval"],
	[CONSUMERD32_BIN=''])
AC_SUBST([CONSUMERD32_BIN])

AC_ARG_WITH([consumerd64-bin],
	AS_HELP_STRING([--with-consumerd64-bin],
	[Location of the 64-bit consumerd executable (including the filename)]),
	[CONSUMERD64_BIN="$withval"],
	[CONSUMERD64_BIN=''])
AC_SUBST([CONSUMERD64_BIN])

AC_ARG_WITH([consumerd32-libdir],
	AS_HELP_STRING([--with-consumerd32-libdir],
	[Directory containing the 32-bit consumerd libraries]),
	[CONSUMERD32_LIBDIR="$withval"],
	[CONSUMERD32_LIBDIR=''])
AC_SUBST([CONSUMERD32_LIBDIR])

AC_ARG_WITH([consumerd64-libdir],
	AS_HELP_STRING([--with-consumerd64-libdir],
	[Directory containing the 64-bit consumerd libraries]),
	[CONSUMERD64_LIBDIR="$withval"],
	[CONSUMERD64_LIBDIR=''])
AC_SUBST([CONSUMERD64_LIBDIR])

AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD32_BIN], "$CONSUMERD32_BIN", [Location of the 32-bit consumerd executable.])
AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD64_BIN], "$CONSUMERD64_BIN", [Location of the 64-bit consumerd executable])
AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD32_LIBDIR], "$CONSUMERD32_LIBDIR", [Search for consumerd 32-bit libraries in this location.])
AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD64_LIBDIR], "$CONSUMERD64_LIBDIR", [Search for consumerd 64-bit libraries in this location.])
AC_DEFINE_UNQUOTED([CONFIG_BABELTRACE_BIN], "$BABELTRACE_BIN", [Location of the babeltrace viewer executable.])
AC_DEFINE_UNQUOTED([CONFIG_LTTV_GUI_BIN], "$LTTV_GUI_BIN", [Location of the lttv GUI viewer executable.])

# Check for pthread
AC_CHECK_LIB([pthread], [pthread_create], [],
	[AC_MSG_ERROR([Cannot find libpthread. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Check libpopt
AC_CHECK_LIB([popt], [poptGetContext], [],
	[AC_MSG_ERROR([Cannot find libpopt. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Needed for benchmark time
AC_CHECK_DECL([caa_get_cycles], [],
	[AC_MSG_ERROR([liburcu liburcu_version or newer is needed])], [[#include <urcu/arch.h>]]
)

# URCU library version needed or newer
liburcu_version=">= 0.6.7"

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
	AS_HELP_STRING([--disable-lttng-ust],[build without LTTng-UST (Userspace Tracing) support]),
	lttng_ust_support=$enableval, lttng_ust_support=yes)

AS_IF([test "x$lttng_ust_support" = "xyes"], [
	AC_CHECK_LIB([lttng-ust-ctl], [ustctl_create_session], [],
		[AC_MSG_ERROR([Cannot find LTTng-UST. Use [LDFLAGS]=-Ldir to specify its location, or specify --disable-lttng-ust to build lttng-tools without LTTng-UST support.])]
	)
])

AM_CONDITIONAL([HAVE_LIBLTTNG_UST_CTL], [ test "x$ac_cv_lib_lttng_ust_ctl_ustctl_create_session" = "xyes" ])

AC_CHECK_FUNCS([sched_getcpu sysconf])

# check for dlopen
AC_CHECK_LIB([dl], [dlopen],
[
	have_libdl=yes
],
[
	#libdl not found, check for dlopen in libc.
	AC_CHECK_LIB([c], [dlopen],
	[
		have_libc_dl=yes
	],
	[
		AC_MSG_ERROR([Cannot find dlopen in libdl nor libc. Use [LDFLAGS]=-Ldir to specify their location.])
	])
])
AM_CONDITIONAL([LTTNG_TOOLS_BUILD_WITH_LIBDL], [test "x$have_libdl" = "xyes"])
AM_CONDITIONAL([LTTNG_TOOLS_BUILD_WITH_LIBC_DL], [test "x$have_libc_dl" = "xyes"])

# Option to only build the consumer daemon and its libraries
AC_ARG_WITH([consumerd-only],
	AS_HELP_STRING([--with-consumerd-only],[Only build the consumer daemon [default=no]]),
	[consumerd_only=$withval],
	[consumerd_only=no])
AM_CONDITIONAL([BUILD_CONSUMERD_ONLY], [test "x$consumerd_only" = "xyes"])

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
LT_INIT

CFLAGS="-Wall $CFLAGS -g -fno-strict-aliasing"

DEFAULT_INCLUDES="-I\$(top_srcdir) -I\$(top_builddir) -I\$(top_builddir)/src -I\$(top_builddir)/include"

lttngincludedir="${includedir}/lttng"

AC_SUBST(lttngincludedir)
AC_SUBST(DEFAULT_INCLUDES)

lttnglibexecdir="${libdir}/lttng/libexec"
AC_SUBST(lttnglibexecdir)

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/man/Makefile
	include/Makefile
	benchmark/Makefile
	src/Makefile
	src/common/Makefile
	src/common/kernel-ctl/Makefile
	src/common/kernel-consumer/Makefile
	src/common/ust-consumer/Makefile
	src/common/hashtable/Makefile
	src/common/sessiond-comm/Makefile
	src/common/compat/Makefile
	src/lib/Makefile
	src/lib/lttng-ctl/Makefile
	src/bin/Makefile
	src/bin/lttng-consumerd/Makefile
	src/bin/lttng-sessiond/Makefile
	src/bin/lttng/Makefile
	tests/Makefile
	tests/kernel/Makefile
	tests/tools/Makefile
	tests/ust/Makefile
	tests/ust/nprocesses/Makefile
	tests/ust/high-throughput/Makefile
	tests/ust/low-throughput/Makefile
	tests/ust/before-after/Makefile
])

AC_OUTPUT

#
# Mini-report on what will be built
#
AS_ECHO()

AS_ECHO("Version name: $version_name")
AS_ECHO("$version_description")

AS_ECHO()

# Target architecture we're building for
target_arch=$host_cpu
[
for f in $CFLAGS; do
        if test $f = "-m32"; then
			target_arch="32-bit"
        elif test $f = "-m64"; then
			target_arch="64-bit"
        fi
done
]
AS_ECHO_N("Target architecture: ")
AS_ECHO($target_arch)

# LTTng-UST enabled/disabled
AS_ECHO_N("Lttng-UST support: ")
AS_IF([test "x$lttng_ust_support" = "xyes"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

# Do we build only the consumerd, or everything
AS_IF([test "x$consumerd_only" = "xyes"],[
	AS_ECHO("Only the consumerd daemon will be built.")
],[
	AS_ECHO("All binaries will be built.")
])

# Print the bindir and libdir this `make install' will install into.
AS_ECHO()
AS_ECHO_N("Binaries will be installed in:  ")
AS_ECHO("`eval eval echo $bindir`")
AS_ECHO_N("Libraries will be installed in: ")
AS_ECHO("`eval eval echo $libdir`")

# If we build the sessiond, print the paths it will use
AS_IF([test "x$consumerd_only" = "xno"],[
	AS_ECHO()
	AS_ECHO("The sessiond daemon will look in the following directories: ")
	AS_ECHO_N("32-bit consumerd executable at: ")
	AS_IF([test "$CONSUMERD32_BIN" = ""],[
		AS_ECHO_N("`eval eval echo $lttnglibexecdir`")
		AS_ECHO("/lttng-consumerd")
	],[
		AS_ECHO("$CONSUMERD32_BIN")
	])

	AS_ECHO_N("32-bit consumer libraries in:   ")
	AS_IF([test "$CONSUMERD32_LIBDIR" = ""],[
		AS_ECHO("`eval eval echo $libdir`")
	],[
		AS_ECHO("$CONSUMERD32_LIBDIR")
	])

	AS_ECHO_N("64-bit consumerd executable at: ")
	AS_IF([test "$CONSUMERD64_BIN" = ""],[
		AS_ECHO_N("`eval eval echo $lttnglibexecdir`")
		AS_ECHO("/lttng-consumerd")
	],[
		AS_ECHO("$CONSUMERD64_BIN")
	])

	AS_ECHO_N("64-bit consumer libraries in:   ")
	AS_IF([test "$CONSUMERD64_LIBDIR" = ""],[
		AS_ECHO("`eval eval echo $libdir`")
	],[
		AS_ECHO("$CONSUMERD64_LIBDIR")
	])
])

AS_ECHO()

