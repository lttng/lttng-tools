AC_PREREQ([2.64])
AC_INIT([lttng-tools],[2.11.0-pre],[jeremie.galarneau@efficios.com],[],[https://lttng.org])

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-pax nostdinc])
AM_MAINTAINER_MODE([enable])

# Enable silent rules if available (Introduced in AM 1.11)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_REQUIRE_AUX_FILE([tap-driver.sh])

# Checks for C compiler
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_CC
AC_PROG_CC_STDC

# Checks for programs.
AC_PROG_GREP
AC_PROG_MAKE_SET
AC_PROG_SED
AC_PATH_PROG([report_fold], [fold])
LT_INIT

# Check for objcopy, required by the base address statedump and dynamic linker tests
AC_CHECK_TOOL([OBJCOPY], [objcopy], [no])
AS_IF([test "x$OBJCOPY" = "xno"],
	[AC_MSG_WARN([Cannot find objcopy. The base address statedump and dynamic linker tests will be disabled. Install the binutils package to remediate this.])]
)
AM_CONDITIONAL([HAVE_OBJCOPY], [test "x$OBJCOPY" != xno])

# check for pgrep
AC_PATH_PROG([PGREP], [pgrep], [no])
AM_CONDITIONAL([HAVE_PGREP], [test "x$PGREP" != "xno"])

# check for bison
AC_PROG_YACC
BISON=$YACC
AX_PROG_BISON_VERSION([2.4], [have_bison=yes])

AS_IF([test "x$have_bison" != "xyes"], [
  AS_IF([test "x$in_git_repo" = "xyes"], [
    AC_MSG_FAILURE([
Bison >= 2.4 is required when building from the Git repository. You can
set the YACC variable to override automatic detection.
    ])
  ], [
    AC_MSG_WARN([
Missing Bison >= 2.4. Note that the parser files are already built in
this distribution tarball, so Bison is only needed if you intend to
modify their sources. You can set the YACC variable to override automatic
detection.
    ])
  ])
])
AM_CONDITIONAL([HAVE_BISON], [test "x$have_bison" = "xyes"])

# check for flex
AC_PROG_LEX
FLEX=$LEX
AX_PROG_FLEX_VERSION([2.5.35], [have_flex=yes])

AS_IF([test "x$have_flex" != "xyes"], [
  AS_IF([test "x$in_git_repo" = "xyes"], [
    AC_MSG_FAILURE([
Flex >= 2.5.35 is required when building from the Git repository. You can
set the LEX variable to override automatic detection.
    ])
  ], [
    AC_MSG_WARN([
Missing Flex >= 2.5.35. Note that the lexer files are already built in
this distribution tarball, so Flex is only needed if you intend to
modify their sources. You can set the LEX variable to override automatic
detection.
    ])
  ])
])
AM_CONDITIONAL([HAVE_FLEX], [test "x$have_flex" = "xyes"])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AX_C___ATTRIBUTE__
AS_IF([test "x$ax_cv___attribute__" = "xyes"],
        [:],
        [AC_MSG_ERROR([The compiler does not support __attribute__ extensions])])

AX_PTHREAD(,[AC_MSG_ERROR([Could not configure pthreads support])])

AX_LIB_SOCKET_NSL

LT_NO_UNDEFINED=""
AS_CASE([$host_os],
  [cygwin*],
    [
      LT_NO_UNDEFINED="-no-undefined"
    ],
  [cygwin*|darwin*|mingw*|solaris*],
    [
      # On platforms where we only support the relayd, disable the other binaries by default
      AS_IF([test "x$enable_bin_lttng" = "x" ], [enable_bin_lttng=no])
      AS_IF([test "x$enable_bin_lttng_consumerd" = "x" ], [enable_bin_lttng_consumerd=no])
      AS_IF([test "x$enable_bin_lttng_crash" = "x" ], [enable_bin_lttng_crash=no])
      AS_IF([test "x$enable_bin_lttng_sessiond" = "x" ], [enable_bin_lttng_sessiond=no])
      AS_IF([test "x$enable_extras" = "x" ], [enable_extras=no])
      AS_IF([test "x$with_lttng_ust" = "x" ], [with_lttng_ust=no])
    ]
)

AC_SUBST(LT_NO_UNDEFINED)

# Compute minor/major/patchlevel version numbers
major_version=$(echo AC_PACKAGE_VERSION | $SED 's/^\([[0-9]]\)*\.[[0-9]]*\.[[0-9]]*.*$/\1/')
minor_version=$(echo AC_PACKAGE_VERSION | $SED 's/^[[0-9]]*\.\([[0-9]]*\)\.[[0-9]]*.*$/\1/')
patchlevel_version=$(echo AC_PACKAGE_VERSION | $SED 's/^[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\).*$/\1/')

AC_SUBST([MAJOR_VERSION], [$major_version])
AC_SUBST([MINOR_VERSION], [$minor_version])
AC_SUBST([PATCHLEVEL_VERSION], [$patchlevel_version])
AC_DEFINE_UNQUOTED([VERSION_MAJOR], $major_version, [LTTng-Tools major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], $minor_version, [LTTng-Tools minor version number])
AC_DEFINE_UNQUOTED([VERSION_PATCHLEVEL], $patchlevel_version, [LTTng-Tools patchlevel version number])

version_name="Codename TBD"
version_description='Description TBD'
version_description_c=$(echo $version_description | $SED 's/"/\\"/g')

AC_DEFINE_UNQUOTED([VERSION_NAME], ["$version_name"], "")
AC_DEFINE_UNQUOTED([VERSION_DESCRIPTION], ["$version_description_c"], "")

# libtool link_all_deplibs fixup. See http://bugs.lttng.org/issues/321.
AC_ARG_ENABLE(libtool-linkdep-fixup,
	AS_HELP_STRING([--disable-libtool-linkdep-fixup],
			[disable the libtool fixup for linking all dependent libraries (link_all_deplibs)]),
	libtool_fixup=$enableval,
	libtool_fixup=yes)

AS_IF([test "x$libtool_fixup" = "xyes"],
	    [
	    libtool_m4="$srcdir/m4/libtool.m4"
	    libtool_flag_pattern=".*link_all_deplibs\s*,\s*\$1\s*)"
	    AC_MSG_CHECKING([for occurence(s) of link_all_deplibs = no in $libtool_m4])
	    libtool_flag_pattern_count=$($GREP -c "$libtool_flag_pattern\s*=\s*no" $libtool_m4)
	    AS_IF([test $libtool_flag_pattern_count -ne 0],
	    [
		  AC_MSG_RESULT([$libtool_flag_pattern_count])
		  AC_MSG_WARN([the detected libtool will not link all dependencies, forcing link_all_deplibs = unknown])
		  $SED -i "s/\($libtool_flag_pattern\)\s*=\s*no/\1=unknown/g" $libtool_m4
		  ],
		  [
		  AC_MSG_RESULT([none])
		  ])
	    ])

AM_CONDITIONAL([NO_SHARED], [test x$enable_shared = xno])

AC_CHECK_HEADERS([ \
	sys/types.h unistd.h fcntl.h string.h pthread.h limits.h \
	signal.h stdlib.h sys/un.h sys/socket.h stdlib.h stdio.h \
	getopt.h sys/ipc.h sys/shm.h popt.h grp.h arpa/inet.h \
	netdb.h netinet/in.h paths.h stddef.h sys/file.h sys/ioctl.h \
	sys/mount.h sys/param.h sys/time.h
])

# Basic functions check
AC_CHECK_FUNCS([ \
	atexit bzero clock_gettime dup2 fdatasync fls ftruncate \
	gethostbyname gethostname getpagesize localtime_r memchr memset \
	mkdir munmap putenv realpath rmdir socket strchr strcspn strdup \
	strncasecmp strndup strnlen strpbrk strrchr strstr strtol strtoul \
	strtoull dirfd gethostbyname2 getipnodebyname epoll_create1 \
	sched_getcpu sysconf sync_file_range
])

# Check if clock_gettime, timer_create, timer_settime, and timer_delete are available in lib rt, and if so,
# add -lrt to LIBS
AC_CHECK_LIB([rt], [clock_gettime, timer_create, timer_settime, timer_delete])

# Checks for dl.
AC_CHECK_LIB([dl], [dlopen], [
	have_libdl=yes
	libdl_name=dl
], [
	# libdl not found, check for dlopen in libc.
	AC_CHECK_LIB([c], [dlopen], [
		have_libc_dl=yes
		libdl_name=c
	], [
		AC_MSG_ERROR([Cannot find dlopen in libdl nor libc. Use [LDFLAGS]=-Ldir to specify their location.])
	])
])

# Check if libdl has dlmopen support.
AH_TEMPLATE([HAVE_DLMOPEN], ["Define to 1 if dlmopen is available."])
AC_CHECK_LIB([$libdl_name], [dlmopen], [
	AC_DEFINE([HAVE_DLMOPEN], [1])
	HAVE_DLMOPEN=1
], [
	HAVE_DLMOPEN=0
])
AC_SUBST(HAVE_DLMOPEN)

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

AC_ARG_WITH([sessiond-bin],
	AS_HELP_STRING([--with-sessiond-bin],
	[Location of the sessiond executable (including the filename)]),
	[SESSIOND_BIN="$withval"],
	[SESSIOND_BIN=''])
AC_SUBST([SESSIOND_BIN])

AC_ARG_WITH([lttng-system-rundir],
	AS_HELP_STRING([--with-lttng-system-rundir],
	[Location of the system directory where the system-wide lttng-sessiond runtime files are kept. The default is "/var/run/lttng".]),
	[LTTNG_SYSTEM_RUNDIR="$withval"],
	[LTTNG_SYSTEM_RUNDIR="/var/run/lttng"])
AC_SUBST([LTTNG_SYSTEM_RUNDIR])

AC_ARG_ENABLE([test-java-agent-jul],
	[AS_HELP_STRING([--enable-test-java-agent-jul],[enable the LTTng UST Java agent JUL tests [default=no]])],
	[test_java_agent_jul=$enableval],
	[test_java_agent_jul=no]
)

AC_ARG_ENABLE([test-java-agent-log4j],
        [AS_HELP_STRING([--enable-test-java-agent-log4j],[enable the LTTng UST Java agent Log4j tests [default=no]])],
        [test_java_agent_log4j=$enableval],
        [test_java_agent_log4j=no]
)

AC_ARG_ENABLE([test-java-agent-all],
        [AS_HELP_STRING([--enable-test-java-agent-all],[enable all the LTTng UST Java agent tests [default=no]])],
        [test_java_agent_jul=$enableval
         test_java_agent_log4j=$enableval],
        [:]
)

AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD32_BIN], "$CONSUMERD32_BIN", [Location of the 32-bit consumerd executable.])
AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD64_BIN], "$CONSUMERD64_BIN", [Location of the 64-bit consumerd executable])
AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD32_LIBDIR], "$CONSUMERD32_LIBDIR", [Search for consumerd 32-bit libraries in this location.])
AC_DEFINE_UNQUOTED([CONFIG_CONSUMERD64_LIBDIR], "$CONSUMERD64_LIBDIR", [Search for consumerd 64-bit libraries in this location.])
AC_DEFINE_UNQUOTED([CONFIG_BABELTRACE_BIN], "$BABELTRACE_BIN", [Location of the babeltrace viewer executable.])
AC_DEFINE_UNQUOTED([CONFIG_LTTV_GUI_BIN], "$LTTV_GUI_BIN", [Location of the lttv GUI viewer executable.])
AC_DEFINE_UNQUOTED([CONFIG_SESSIOND_BIN], "$SESSIOND_BIN", [Location of the sessiond executable.])
AC_DEFINE_UNQUOTED([CONFIG_LTTNG_SYSTEM_RUNDIR], ["$LTTNG_SYSTEM_RUNDIR"], [LTTng system runtime directory])

AC_DEFUN([_AC_DEFINE_AND_SUBST], [
	AC_DEFINE_UNQUOTED([CONFIG_$1], [$2], [$1])
	$1="$2"
	AC_SUBST([$1])
])

AC_DEFUN([_AC_DEFINE_QUOTED_AND_SUBST], [
	AC_DEFINE_UNQUOTED([CONFIG_$1], ["$2"], [$1])
	$1="$2"
	AC_SUBST([$1])
])

# Default values
m4_define([_DEFAULT_CHANNEL_SUBBUF_SIZE], [16384])
m4_define([_DEFAULT_CHANNEL_SUBBUF_NUM], [4])
m4_define([_DEFAULT_CHANNEL_SWITCH_TIMER], [0])
m4_define([_DEFAULT_CHANNEL_LIVE_TIMER], [0])
m4_define([_DEFAULT_CHANNEL_READ_TIMER], [200000])
m4_define([_DEFAULT_CHANNEL_MONITOR_TIMER], [1000000])
m4_define([_DEFAULT_CHANNEL_BLOCKING_TIMEOUT], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_AGENT_TCP_PORT], [5345])
_AC_DEFINE_AND_SUBST([DEFAULT_APP_SOCKET_RW_TIMEOUT], [5])
_AC_DEFINE_AND_SUBST([DEFAULT_CHANNEL_SUBBUF_SIZE], [_DEFAULT_CHANNEL_SUBBUF_SIZE])
_AC_DEFINE_AND_SUBST([DEFAULT_CHANNEL_TRACEFILE_COUNT], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_CHANNEL_TRACEFILE_SIZE], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_LIVE_TIMER], [_DEFAULT_CHANNEL_LIVE_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_READ_TIMER], [_DEFAULT_CHANNEL_READ_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM], [_DEFAULT_CHANNEL_SUBBUF_NUM])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE], [1048576])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER], [_DEFAULT_CHANNEL_SWITCH_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER], [_DEFAULT_CHANNEL_MONITOR_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT], [_DEFAULT_CHANNEL_BLOCKING_TIMEOUT])
_AC_DEFINE_AND_SUBST([DEFAULT_LTTNG_LIVE_TIMER], [1000000])
_AC_DEFINE_AND_SUBST([DEFAULT_METADATA_CACHE_SIZE], [4096])
_AC_DEFINE_AND_SUBST([DEFAULT_METADATA_READ_TIMER], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_METADATA_SUBBUF_NUM], [2])
_AC_DEFINE_AND_SUBST([DEFAULT_METADATA_SUBBUF_SIZE], [4096])
_AC_DEFINE_AND_SUBST([DEFAULT_METADATA_SWITCH_TIMER], [_DEFAULT_CHANNEL_SWITCH_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_NETWORK_CONTROL_PORT], [5342])
_AC_DEFINE_AND_SUBST([DEFAULT_NETWORK_DATA_PORT], [5343])
_AC_DEFINE_AND_SUBST([DEFAULT_NETWORK_VIEWER_PORT], [5344])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_LIVE_TIMER], [_DEFAULT_CHANNEL_LIVE_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_READ_TIMER], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM], [_DEFAULT_CHANNEL_SUBBUF_NUM])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE], [_DEFAULT_CHANNEL_SUBBUF_SIZE])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER], [_DEFAULT_CHANNEL_SWITCH_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER], [_DEFAULT_CHANNEL_MONITOR_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_LIVE_TIMER], [_DEFAULT_CHANNEL_LIVE_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_READ_TIMER], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT], [0])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM], [_DEFAULT_CHANNEL_SUBBUF_NUM])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE], [524288])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER], [_DEFAULT_CHANNEL_SWITCH_TIMER])
_AC_DEFINE_AND_SUBST([DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER], [_DEFAULT_CHANNEL_MONITOR_TIMER])
_AC_DEFINE_QUOTED_AND_SUBST([DEFAULT_AGENT_BIND_ADDRESS], [localhost])
_AC_DEFINE_QUOTED_AND_SUBST([DEFAULT_NETWORK_CONTROL_BIND_ADDRESS], [0.0.0.0])
_AC_DEFINE_QUOTED_AND_SUBST([DEFAULT_NETWORK_DATA_BIND_ADDRESS], [0.0.0.0])
_AC_DEFINE_QUOTED_AND_SUBST([DEFAULT_NETWORK_VIEWER_BIND_ADDRESS], [localhost])

# Command short descriptions
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_ADD_CONTEXT], [Add context fields to a channel])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_CREATE], [Create a tracing session])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_DESTROY], [Tear down tracing sessions])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_DISABLE_CHANNEL], [Disable tracing channels])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_DISABLE_EVENT], [Disable event rules])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_ENABLE_CHANNEL], [Create or enable tracing channels])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_ENABLE_EVENT], [Create or enable event rules])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_HELP], [Display help information about a command])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_LIST], [List tracing sessions, domains, channels, and events])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_LOAD], [Load tracing session configurations])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_REGENERATE], [Manage an LTTng tracing session's data regeneration])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_SAVE], [Save tracing session configurations])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_SET_SESSION], [Set current tracing session])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_SNAPSHOT], [Snapshot buffers of current tracing session])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_START], [Start tracing])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_STATUS], [Get the status of the current tracing session])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_STOP], [Stop tracing])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_TRACK], [Track specific system resources])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_UNTRACK], [Untrack specific system resources])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_VERSION], [Show version information])
_AC_DEFINE_QUOTED_AND_SUBST([CMD_DESCR_VIEW], [Start trace viewer])

if test "x$prefix" = "xNONE"; then
	prefix=$ac_default_prefix
fi
CONFDIR=`eval echo $sysconfdir`
AC_SUBST(CONFDIR)
AC_DEFINE_UNQUOTED([CONFIG_LTTNG_SYSTEM_CONFIGDIR],"$CONFDIR", [LTTng system configuration directory.])

AC_DEFINE_DIR([CONFIG_LTTNG_SYSTEM_DATADIR],[datadir], [LTTng system data directory.])

# Check libpopt
PKG_CHECK_MODULES([POPT], [popt],
  [
    dnl PKG_CHECK_MODULES defines POPT_LIBS
  ],
  [
    AC_MSG_WARN([pkg-config was unable to find a valid .pc for libpopt. Set PKG_CONFIG_PATH to specify the pkgconfig configuration file location])
    AC_MSG_WARN([Finding libpopt without pkg-config.])
    AC_CHECK_LIB([popt],
      [poptGetContext],
      [POPT_LIBS="-lpopt"],
      [
        AC_MSG_FAILURE([Cannot find libpopt. Either set PKG_CONFIG_PATH to the configuration file location or use LDFLAGS=-Ldir to specify the library location])
      ]
    )
  ]
)
AC_SUBST(POPT_LIBS)

PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.7.6])

# First, check for uuid in system libs
AH_TEMPLATE([LTTNG_HAVE_LIBUUID], [Define if you have libuuid support])
AC_CHECK_FUNCS([uuid_generate],
  [
    AC_DEFINE([LTTNG_HAVE_LIBUUID], [1])
    UUID_LIBS=""
  ],
  [
    # Then, check if the pkg-config module is available, otherwise explicitly check
    # for libuuid, or uuid support in the C-library.
    PKG_CHECK_MODULES([UUID], [uuid],
      [
        AC_DEFINE([LTTNG_HAVE_LIBUUID], [1])
        dnl PKG_CHECK_MODULES defines UUID_LIBS
      ],
      [
        AC_MSG_WARN([pkg-config was unable to find a valid .pc for libuuid. Set PKG_CONFIG_PATH to specify the pkgconfig configuration file location])
        AC_MSG_WARN([Finding libuuid without pkg-config.])
        AC_CHECK_LIB([uuid], [uuid_generate],
          [
            AC_DEFINE([LTTNG_HAVE_LIBUUID], [1])
            UUID_LIBS="-luuid"
          ],
          [
            # libuuid not found, check for uuid_create in libc.
            AC_CHECK_LIB([c], [uuid_create],
              [
                AC_DEFINE([LTTNG_HAVE_LIBUUID], [1])
                UUID_LIBS="-lc"
              ],
              [
                AC_MSG_FAILURE([Cannot find libuuid uuid_generate nor libc uuid_create. Either set PKG_CONFIG_PATH to the configuration file location or use LDFLAGS=-Ldir to specify the library location])
              ]
            )
          ]
        )
      ]
    )
  ]
)
AC_SUBST(UUID_LIBS)

AC_CHECK_FUNC([clock_gettime], [AC_DEFINE_UNQUOTED([LTTNG_HAVE_CLOCK_GETTIME], 1, [Has clock_gettime() support.])])

# URCU library version needed or newer
m4_define([WRONG_LIBURCU_MSG], [Userspace RCU (liburcu) >= 0.9.0 is needed])

# Check liburcu needed function calls
AC_CHECK_DECL([cds_list_add], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu/list.h>]])
AC_CHECK_DECL([cds_wfcq_init], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu/wfcqueue.h>]])
AC_CHECK_DECL([cds_wfcq_dequeue_blocking], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu/wfcqueue.h>]])
AC_CHECK_DECL([futex_async], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu/futex.h>]])
AC_CHECK_DECL([rcu_thread_offline], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu.h>]])
AC_CHECK_DECL([rcu_thread_online], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu.h>]])
AC_CHECK_DECL([caa_likely], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu.h>]])
AC_CHECK_LIB([urcu-cds], [_cds_lfht_new], [],
	[AC_MSG_ERROR([WRONG_LIBURCU_MSG])])

#Function added in urcu 0.7.0
AC_CHECK_DECL([cmm_smp_mb__before_uatomic_or], [],
        [AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu.h>]]
)

#Function added in urcu 0.9.0
AC_CHECK_DECL([urcu_ref_get_unless_zero], [],
        [AC_MSG_ERROR([WRONG_LIBURCU_MSG])], [[#include <urcu/ref.h>]]
)

# Check for libkmod, it will be auto-neabled if found but won't fail if it's not,
# it can be explicitly disabled with --without-kmod
AH_TEMPLATE([HAVE_KMOD], [Define if you have kmod support])
AC_ARG_WITH([kmod],
  [AS_HELP_STRING([--with-kmod], [build with lkmod support @<:@default=check@:>@])],
  [],
  [with_kmod=check]
)

AS_IF([test "x$with_kmod" != "xno"],
  [
    AC_CHECK_LIB([kmod], [kmod_module_probe_insert_module],
      [
        AC_DEFINE([HAVE_KMOD], [1])
        KMOD_LIBS="-lkmod"
      ],
      [
        if test "x$with_kmod" != xcheck; then
          AC_MSG_FAILURE([Cannot find libkmod. Use [LDFLAGS]=-Ldir and [CPPFLAGS]=-Idir to specify its location.])
        else
          with_kmod=no
        fi
      ]
    )
  ]
)
AC_SUBST(KMOD_LIBS)

# Check for liblttng-ust-ctl, fail if it's not found,
# it can be explicitly disabled with --without-lttng-ust
AH_TEMPLATE([HAVE_LIBLTTNG_UST_CTL], [Define if you have LTTng-UST control support])
AC_ARG_WITH([lttng-ust],
  [AS_HELP_STRING([--without-lttng-ust], [build without LTTng-UST (Userspace Tracing) support])],
  [],
  [with_lttng_ust=yes]
)

AS_IF([test "x$with_lttng_ust" = "xyes"],
  [
    AC_CHECK_LIB([lttng-ust-ctl], [ustctl_recv_channel_from_consumer],
      [
        AC_DEFINE([HAVE_LIBLTTNG_UST_CTL], [1])
      ],
      [
        AC_MSG_FAILURE([Cannot find LTTng-UST >= 2.2.x. Use [LDFLAGS]=-Ldir and [CPPFLAGS]=-Idir to specify its location, or specify --without-lttng-ust to build lttng-tools without LTTng-UST support.])
      ],
      [-lurcu-common -lurcu-bp -lurcu-cds -lrt -ldl]
    )
  ]
)
AM_CONDITIONAL([HAVE_LIBLTTNG_UST_CTL], [test "x$with_lttng_ust" = "xyes"])



# check for dlopen
AC_CHECK_LIB([dl], [dlopen],
  [DL_LIBS="-ldl"],
  [
    #libdl not found, check for dlopen in libc.
    AC_CHECK_LIB([c], [dlopen],
      [DL_LIBS="-lc"],
      [AC_MSG_FAILURE([Cannot find dlopen in libdl nor libc. Use [LDFLAGS]=-Ldir to specify their location.])]
    )
  ]
)
AC_SUBST(DL_LIBS)

# Check for fmemopen
AC_CHECK_LIB([c], [fmemopen],
[
	AC_DEFINE_UNQUOTED([LTTNG_HAVE_FMEMOPEN], 1, [Has fmemopen support.])
]
)

# Check for open_memstream
AC_CHECK_LIB([c], [open_memstream],
[
	AC_DEFINE_UNQUOTED([LTTNG_HAVE_OPEN_MEMSTREAM], 1, [Has open_memstream support.])
]
)

# check for libpfm
AC_CHECK_LIB([pfm], [pfm_initialize],
	     [
	      have_libpfm=yes
	      ])
AM_CONDITIONAL([LTTNG_TOOLS_BUILD_WITH_LIBPFM], [test "x$have_libpfm" = "xyes"])

AC_ARG_ENABLE([git-version],
              [AC_HELP_STRING([--disable-git-version],
                              [Do not use the git version for the build])],
              [have_git_version=$enableval], [have_git_version=yes]
)

AM_CONDITIONAL([LTTNG_TOOLS_BUILD_GIT_SOURCE],
	[test "x${have_git_version}" = "xyes"])

# For Python
# SWIG version needed or newer:
swig_version=2.0.0

AC_ARG_ENABLE([python-bindings],
              [AC_HELP_STRING([--enable-python-bindings],
                              [compile Python bindings])],
              [enable_python_binding=$enableval], [enable_python_binding=no])

AM_CONDITIONAL([PYTHON_BINDING], [test "x$enable_python_binding" = xyes])

if test "x$enable_python_binding" = xyes; then
  AX_PKG_SWIG($swig_version, [], [ AC_MSG_ERROR([SWIG $swig_version or newer is needed]) ])
  AS_IF([test x$enable_shared = xno], [ AC_MSG_ERROR([Python bindings require shared libraries.]) ])
  AM_PATH_PYTHON([3.0])

  AC_ARG_VAR([PYTHON_INCLUDE], [Include flags for python, bypassing python-config])
  AC_ARG_VAR([PYTHON_CONFIG], [Path to python-config])
  AS_IF([test -z "$PYTHON_INCLUDE"], [
    AS_IF([test -z "$PYTHON_CONFIG"], [
      AC_PATH_PROGS([PYTHON_CONFIG],
                    [python$PYTHON_VERSION-config python-config],
                    [no],
                    [`dirname $PYTHON`])
      AS_IF([test "$PYTHON_CONFIG" = no], [AC_MSG_ERROR([cannot find python-config for $PYTHON. Do you have python-dev installed?])])
    ])
    AC_MSG_CHECKING([python include flags])
    PYTHON_INCLUDE=`$PYTHON_CONFIG --includes`
    AC_MSG_RESULT([$PYTHON_INCLUDE])
  ])

else
    AC_MSG_NOTICE([You may configure with --enable-python-bindings ]dnl
[if you want Python bindings.])

fi

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

AM_CONDITIONAL([TEST_JAVA_JUL_AGENT], [test "x$test_java_agent_jul" = "xyes"])
AM_CONDITIONAL([TEST_JAVA_LOG4J_AGENT], [test "x$test_java_agent_log4j" = "xyes"])

if test "x$test_java_agent_jul" = "xyes" || test "x$test_java_agent_log4j" = "xyes"; then
	AX_JAVA_OPTIONS
	AX_PROG_JAVAC
	AX_PROG_JAVA
	AX_PROG_JAR

	AX_CHECK_CLASSPATH

	# Check for Java UST agent common class first
	AX_CHECK_CLASS(org.lttng.ust.agent.AbstractLttngAgent)
	if test "x$ac_cv_class_org_lttng_ust_agent_AbstractLttngAgent" = "xno"; then
		AC_MSG_ERROR([The UST Java agent common class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/lttng-ust-agent-common.jar"])
	fi

	if test "x$test_java_agent_jul" = "xyes"; then
		# Check for JUL agent class
		AX_CHECK_CLASS(org.lttng.ust.agent.jul.LttngLogHandler)
		if test "x$ac_cv_class_org_lttng_ust_agent_jul_LttngLogHandler" = "xno"; then
			AC_MSG_ERROR([The UST Java agent JUL class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/lttng-ust-agent-jul.jar"])
		fi
	fi

	if test "x$test_java_agent_log4j" = "xyes"; then
		# Check for Log4j agent class
		AX_CHECK_CLASS(org.lttng.ust.agent.log4j.LttngLogAppender)
		if test "x$ac_cv_class_org_lttng_ust_agent_log4j_LttngLogAppender" = "xno"; then
			AC_MSG_ERROR([The UST Java agent Log4j class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/lttng-ust-agent-log4j.jar"])
		fi

		# Check for Log4j class
		AX_CHECK_CLASS(org.apache.log4j.Logger)
		if test "x$ac_cv_class_org_apache_log4j_Logger" = "xno"; then
			AC_MSG_ERROR([The Log4j class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/log4j.jar"])
		fi
	fi
fi

# set $IN_GIT_REPO if we're in the Git repository; the `bootstrap` file
# is not distributed in tarballs
AS_IF([test -f "$srcdir/bootstrap"], [in_git_repo=yes], [in_git_repo=no])
AM_CONDITIONAL([IN_GIT_REPO], [test "x$in_git_repo" = "xyes"])

# enable building man pages (user's intention)
AC_ARG_ENABLE(
	man-pages,
	AS_HELP_STRING(
		[--disable-man-pages],
		[Do not build and install man pages (already built in a distributed tarball)]
	),
	[man_pages_opt=$enableval],
	[man_pages_opt=yes]
)

# check for asciidoc and xmlto if we enabled building the man pages
have_asciidoc_xmlto=no
warn_prebuilt_man_pages=no

AS_IF([test "x$man_pages_opt" = "xyes"], [
	AC_PATH_PROG([ASCIIDOC], [asciidoc], [no])
	AC_PATH_PROG([XMLTO], [xmlto], [no])

	AS_IF([test "x$ASCIIDOC" = "xno" || test "x$XMLTO" = "xno"], [
		AS_IF([test "x$in_git_repo" = "xyes"], [
			# this is an error because we're in the Git repo, which
			# means the man pages are not already generated for us,
			# thus asciidoc/xmlto are required because we were asked
			# to build the man pages
			AC_MSG_ERROR([
You need asciidoc and xmlto to build the LTTng-tools man pages. Use
--disable-man-pages to disable building the man pages, in which case
they will not be installed.
			])
		], [
			# only warn here: since we're in the tarball, the man
			# pages should already be generated at this point, thus
			# asciidoc/xmlto are not strictly required
			warn_prebuilt_man_pages=yes
		])
	], [
		have_asciidoc_xmlto=yes
	])
])

# export man page build condition: build the man pages if the user
# asked for it, and if the tools are available
AM_CONDITIONAL([MAN_PAGES_OPT], [test "x$man_pages_opt" != "xno"])
AM_CONDITIONAL([HAVE_ASCIIDOC_XMLTO], [test "x$have_asciidoc_xmlto" = "xyes"])

AC_DEFINE_UNQUOTED([MANPATH], ["`eval eval echo $mandir`"], [Path to man pages.])

# embedded --help message
AC_ARG_ENABLE(
	[embedded-help],
	AS_HELP_STRING(
		[--enable-embedded-help],
		[Embed the --help messages in the executable files]
	),
	[embedded_help=$enableval],
	[embedded_help=no]
)
AS_IF([test "x$embedded_help" = "xyes"], [
	AS_IF([test "x$man_pages_opt" = "xno"], [
		AC_MSG_ERROR([You need the --enable-man-pages option with the --enable-embedded-help option.])
	])
	AC_PATH_PROG([man_prog_path], [man], [no])
	AS_IF([test "x$man_prog_path" = "xno"], [
		AC_MSG_ERROR([You need man with the --enable-embedded-help option.])
	])
	AC_DEFINE_UNQUOTED([LTTNG_EMBED_HELP], 1, [Embed --help messages.])
	AC_SUBST([MANPROG], [$man_prog_path])
])
AM_CONDITIONAL([EMBED_HELP], [test "x$embedded_help" != "xno"])

# Python agent test
UST_PYTHON_AGENT="lttngust"

AC_ARG_ENABLE(test-python2-agent,
	AS_HELP_STRING([--enable-test-python2-agent],
		[enable tests for python2 agent. Python2 interpreter path can be overridden by setting the PYTHON2 environment variable. Default: Autodetect]
	),[:],[test_python2_agent_autodetect=yes]
)

AC_ARG_ENABLE(test-python3-agent,
	AS_HELP_STRING([--enable-test-python3-agent],
		[enable tests for python3 agent. Python3 interpreter path can be overridden by setting the PYTHON3 environment variable. Default: Autodetect]
	),[:],[test_python3_agent_autodetect=yes]
)

AC_ARG_ENABLE(test-python-agent-all,
	AS_HELP_STRING([--enable-test-python-agent-all],
		[enable test for all python{2/3} agent.]
	),
)

AS_IF([test ! -z "$enable_test_python_agent_all"], [
       unset test_python2_agent_autodetect
       unset test_python3_agent_autodetect
])

AS_IF([test "x$enable_test_python_agent_all" = "xyes"], [
       enable_test_python2_agent=yes
       enable_test_python3_agent=yes
])

AS_IF([test "x$enable_test_python_agent_all" = "xno"], [
       enable_test_python2_agent=no
       enable_test_python3_agent=no
])


AS_IF([test "x$enable_test_python2_agent" = "xyes" -o "x$test_python2_agent_autodetect" = "xyes" ], [
	AS_IF([test -z "$PYTHON2"], [
			PYTHON2=python2
		], [
			AC_MSG_WARN([Using user-defined PYTHON2 ($PYTHON2) for lttng-ust python2 agent check])
	])

	AC_PATH_PROG([PYTHON2_BIN],[$PYTHON2])
	AS_IF([test -z "$PYTHON2_BIN"], [
		AS_IF([test -z "$test_python2_agent_autodetect"],[
			AC_MSG_ERROR([No python2 interpreter found. PYTHON2 can be set to override default interpreter path])
		])
	], [
		AC_MSG_CHECKING([for python2 lttng-ust agent])
		AS_IF([$PYTHON2_BIN -c "import $UST_PYTHON_AGENT" 2>/dev/null], [
			PYTHON2_AGENT=$PYTHON2_BIN
			AC_MSG_RESULT([yes])
			RUN_PYTHON_AGENT_TEST=yes
		], [
			AC_MSG_RESULT([no])
			AS_IF([test -z "$test_python2_agent_autodetect"],[
				AC_MSG_ERROR([No python2 agent found. The path to the agent can be specified by setting the PYTHONPATH environment variable.])
			])
		])

	])

])

AS_IF([test "x$enable_test_python3_agent" = "xyes" -o "x$test_python3_agent_autodetect" = "xyes" ], [
	AS_IF([test -z "$PYTHON3"], [
		PYTHON3=python3
	], [
		AC_MSG_WARN([Using user-defined PYTHON3 ($PYTHON3) for lttng-ust python3 agent check])
	])

	AC_PATH_PROG([PYTHON3_BIN],[$PYTHON3])
	AS_IF([test -z "$PYTHON3_BIN"], [
		AS_IF([test -z "$test_python3_agent_autodetect"],[
			AC_MSG_ERROR([No python3 interpreter found. PYTHON3 can be set to override default interpreter path])
		])
	], [
		AC_MSG_CHECKING([for python3 lttng-ust agent])
		AS_IF([$PYTHON3_BIN -c "import $UST_PYTHON_AGENT" 2>/dev/null], [
			PYTHON3_AGENT=$PYTHON3_BIN
			AC_MSG_RESULT([yes])
			RUN_PYTHON_AGENT_TEST=yes
		], [
			AC_MSG_RESULT([no])
			AS_IF([test -z "$test_python3_agent_autodetect"],[
				AC_MSG_ERROR([No python3 agent found. The path to the agent can be specified by setting the PYTHONPATH environment variable.])
			])
		])

	])
])
AC_SUBST([RUN_PYTHON_AGENT_TEST])
AC_SUBST([PYTHON2_AGENT])
AC_SUBST([PYTHON3_AGENT])

# Arguments for binaries build exclusion
AC_ARG_ENABLE([bin-lttng], AS_HELP_STRING([--disable-bin-lttng],[Disable the build of lttng binaries]))
AC_ARG_ENABLE([bin-lttng-consumerd], AS_HELP_STRING([--disable-bin-lttng-consumerd],
	      [Disable the build of lttng-consumerd binaries]))
AC_ARG_ENABLE([bin-lttng-crash], AS_HELP_STRING([--disable-bin-lttng-crash],[Disable the build of lttng-crash binaries]))
AC_ARG_ENABLE([bin-lttng-relayd], AS_HELP_STRING([--disable-bin-lttng-relayd],
	      [Disable the build of lttng-relayd binaries]))
AC_ARG_ENABLE([bin-lttng-sessiond], AS_HELP_STRING([--disable-bin-lttng-sessiond],
	      [Disable the build of lttng-sessiond binaries]))
AC_ARG_ENABLE([extras], AS_HELP_STRING([--disable-extras],
	      [Disable the build of the extra components]))


# Always build libconfig since it a dependency of libcommon
build_lib_config=yes

build_lib_compat=no
build_lib_consumer=no
build_lib_hashtable=no
build_lib_health=no
build_lib_index=no
build_lib_kernel_consumer=no
build_lib_kernel_ctl=no
build_lib_lttng_ctl=no
build_lib_relayd=no
build_lib_sessiond_comm=no
build_lib_testpoint=no
build_lib_ust_consumer=no

# There is an overlap for enabled dependencies, but this makes everything
# simpler. libcommon and libconfig are always compiled so they are not repeated
# here.

# Enable binary dependencies.
AS_IF([test x$enable_bin_lttng != xno],
      [
       build_lib_lttng_ctl=yes
      ]
)

AS_IF([test x$enable_bin_lttng_consumerd != xno],
      [
       build_lib_consumer=yes
       build_lib_sessiond_comm=yes
       build_lib_index=yes
       build_lib_health=yes
       build_lib_testpoint=yes
      ]
)

AS_IF([test x$enable_bin_lttng_crash != xno],
      # Do nothing since libconfig and libcommon are built by default.
      []
)

AS_IF([test x$enable_bin_lttng_relayd != xno],
      [
       build_lib_lttng_ctl=yes
       build_lib_sessiond_comm=yes
       build_lib_hashtable=yes
       build_lib_compat=yes
       build_lib_index=yes
       build_lib_health=yes
       build_lib_testpoint=yes
      ]
)
AS_IF([test x$enable_bin_lttng_sessiond != xno],
      [
       build_lib_lttng_ctl=yes
       build_lib_sessiond_comm=yes
       build_lib_kernel_ctl=yes
       build_lib_hashtable=yes
       build_lib_compat=yes
       build_lib_relayd=yes
       build_lib_testpoint=yes
       build_lib_health=yes
       build_lib_health=yes
      ]
)

# Libraries dependencies enabling
AS_IF([test x$build_lib_lttng_ctl = xyes],
      [
       build_lib_sessiond_comm=yes
       build_lib_hashtable=yes
      ]
)

AS_IF([test x$build_lib_consumer = xyes],
      [
       build_lib_sessiond_comm=yes
       build_lib_kernel_consumer=yes
       build_lib_hashtable=yes
       build_lib_compat=yes
       build_lib_relayd=yes
       AS_IF([test "x$with_lttng_ust" = "xyes"], [build_lib_ust_consumer=yes])
      ]
)

AS_IF([test x$build_lib_kernel_consumer = xyes],
      [
       build_lib_kernel_ctl=yes
       build_lib_relayd=yes
      ]
)

AS_IF([test x$build_lib_relayd = xyes],
      [
       build_lib_sessiond_comm=yes
      ]
)


# Export binaries build conditions.
AM_CONDITIONAL([BUILD_BIN_LTTNG], [test x$enable_bin_lttng != xno])
AM_CONDITIONAL([BUILD_BIN_LTTNG_CONSUMERD], [test x$enable_bin_lttng_consumerd != xno])
AM_CONDITIONAL([BUILD_BIN_LTTNG_CRASH], [test x$enable_bin_lttng_crash != xno])
AM_CONDITIONAL([BUILD_BIN_LTTNG_RELAYD], [test x$enable_bin_lttng_relayd != xno])
AM_CONDITIONAL([BUILD_BIN_LTTNG_SESSIOND], [test x$enable_bin_lttng_sessiond != xno])

# Export the tests and extras build conditions.
AS_IF([\
test "x$enable_bin_lttng" != "xno" && \
test "x$enable_bin_lttng_consumerd" != "xno" && \
test "x$enable_bin_lttng_crash" != "xno" && \
test "x$enable_bin_lttng_relayd" != "xno" && \
test "x$enable_bin_lttng_sessiond" != "xno"],
[build_tests=yes],
[build_tests=no]
)

AM_CONDITIONAL([BUILD_TESTS], [test x$build_tests = xyes])
AM_CONDITIONAL([BUILD_EXTRAS], [test x$enable_extras != xno])

# Export libraries build conditions.
AM_CONDITIONAL([BUILD_LIB_COMPAT], [test x$build_lib_compat = xyes])
AM_CONDITIONAL([BUILD_LIB_CONFIG], [test x$build_lib_config = xyes])
AM_CONDITIONAL([BUILD_LIB_CONSUMER], [test x$build_lib_consumer = xyes])
AM_CONDITIONAL([BUILD_LIB_HASHTABLE], [test x$build_lib_hashtable = xyes])
AM_CONDITIONAL([BUILD_LIB_HEALTH], [test x$build_lib_health = xyes])
AM_CONDITIONAL([BUILD_LIB_INDEX], [test x$build_lib_index = xyes])
AM_CONDITIONAL([BUILD_LIB_KERNEL_CONSUMER], [test x$build_lib_kernel_consumer = xyes])
AM_CONDITIONAL([BUILD_LIB_KERNEL_CTL], [test x$build_lib_kernel_ctl = xyes])
AM_CONDITIONAL([BUILD_LIB_LTTNG_CTL], [test x$build_lib_lttng_ctl = xyes])
AM_CONDITIONAL([BUILD_LIB_RELAYD], [test x$build_lib_relayd = xyes])
AM_CONDITIONAL([BUILD_LIB_SESSIOND_COMM], [test x$build_lib_sessiond_comm = xyes])
AM_CONDITIONAL([BUILD_LIB_TESTPOINT], [test x$build_lib_testpoint = xyes])
AM_CONDITIONAL([BUILD_LIB_UST_CONSUMER], [test x$build_lib_ust_consumer = xyes])

AM_CFLAGS="-Wall -fno-strict-aliasing $PTHREAD_CFLAGS"
AC_SUBST(AM_CFLAGS)

AM_CPPFLAGS="-I\$(top_srcdir)/include -I\$(top_builddir)/include -I\$(top_srcdir)/src -include config.h $AM_CPPFLAGS"
AC_SUBST(AM_CPPFLAGS)

lttngincludedir="${includedir}/lttng"
AC_SUBST(lttngincludedir)

lttngactionincludedir="${includedir}/lttng/action"
AC_SUBST(lttngactionincludedir)

lttngconditionincludedir="${includedir}/lttng/condition"
AC_SUBST(lttngconditionincludedir)

lttngnotificationincludedir="${includedir}/lttng/notification"
AC_SUBST(lttngnotificationincludedir)

lttngtriggerincludedir="${includedir}/lttng/trigger"
AC_SUBST(lttngtriggerincludedir)

lttnglibexecdir="${libdir}/lttng/libexec"
AC_SUBST(lttnglibexecdir)

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/man/Makefile
	doc/man/asciidoc-attrs.conf
	include/Makefile
	extras/Makefile
	extras/bindings/Makefile
	extras/bindings/swig/Makefile
	extras/bindings/swig/python/Makefile
	extras/core-handler/Makefile
	src/Makefile
	src/common/Makefile
	src/common/kernel-ctl/Makefile
	src/common/kernel-consumer/Makefile
	src/common/consumer/Makefile
	src/common/ust-consumer/Makefile
	src/common/hashtable/Makefile
	src/common/sessiond-comm/Makefile
	src/common/compat/Makefile
	src/common/relayd/Makefile
	src/common/testpoint/Makefile
	src/common/index/Makefile
	src/common/health/Makefile
	src/common/config/Makefile
	src/common/string-utils/Makefile
	src/lib/Makefile
	src/lib/lttng-ctl/Makefile
	src/lib/lttng-ctl/filter/Makefile
	src/lib/lttng-ctl/lttng-ctl.pc
	src/bin/Makefile
	src/bin/lttng-consumerd/Makefile
	src/bin/lttng-sessiond/Makefile
	src/bin/lttng-relayd/Makefile
	src/bin/lttng/Makefile
	src/bin/lttng-crash/Makefile
	tests/Makefile
	tests/destructive/Makefile
	tests/regression/Makefile
	tests/regression/kernel/Makefile
	tests/regression/tools/Makefile
	tests/regression/tools/streaming/Makefile
	tests/regression/tools/filtering/Makefile
	tests/regression/tools/health/Makefile
	tests/regression/tools/tracefile-limits/Makefile
	tests/regression/tools/snapshots/Makefile
	tests/regression/tools/live/Makefile
	tests/regression/tools/exclusion/Makefile
	tests/regression/tools/save-load/Makefile
	tests/regression/tools/save-load/configuration/Makefile
	tests/regression/tools/mi/Makefile
	tests/regression/tools/wildcard/Makefile
	tests/regression/tools/crash/Makefile
	tests/regression/tools/regen-metadata/Makefile
	tests/regression/tools/regen-statedump/Makefile
	tests/regression/tools/notification/Makefile
	tests/regression/ust/Makefile
	tests/regression/ust/nprocesses/Makefile
	tests/regression/ust/high-throughput/Makefile
	tests/regression/ust/low-throughput/Makefile
	tests/regression/ust/before-after/Makefile
	tests/regression/ust/buffers-pid/Makefile
	tests/regression/ust/periodical-metadata-flush/Makefile
	tests/regression/ust/multi-session/Makefile
	tests/regression/ust/overlap/Makefile
	tests/regression/ust/overlap/demo/Makefile
	tests/regression/ust/linking/Makefile
	tests/regression/ust/daemon/Makefile
	tests/regression/ust/exit-fast/Makefile
	tests/regression/ust/fork/Makefile
	tests/regression/ust/libc-wrapper/Makefile
	tests/regression/ust/baddr-statedump/Makefile
	tests/regression/ust/ust-dl/Makefile
	tests/regression/ust/java-jul/Makefile
	tests/regression/ust/java-log4j/Makefile
	tests/regression/ust/python-logging/Makefile
	tests/regression/ust/getcpu-override/Makefile
	tests/regression/ust/clock-override/Makefile
	tests/regression/ust/type-declarations/Makefile
	tests/regression/ust/rotation-destroy-flush/Makefile
	tests/regression/ust/blocking/Makefile
	tests/stress/Makefile
	tests/unit/Makefile
	tests/unit/ini_config/Makefile
	tests/perf/Makefile
	tests/utils/Makefile
	tests/utils/tap/Makefile
	tests/utils/testapp/Makefile
	tests/utils/testapp/gen-ust-events/Makefile
	tests/utils/testapp/gen-ust-nevents/Makefile
	tests/utils/testapp/gen-ust-nevents-str/Makefile
	tests/utils/testapp/gen-ust-tracef/Makefile
])

# Inject variable into python test script.
AC_CONFIG_FILES([tests/regression/ust/python-logging/test_python_logging],[chmod +x tests/regression/ust/python-logging/test_python_logging])
# Inject LTTNG_TOOLS_BUILD_WITH_LIBPFM variable in test script.
AC_CONFIG_FILES([tests/perf/test_perf_raw],[chmod +x tests/perf/test_perf_raw])
AC_CONFIG_FILES([tests/regression/ust/ust-dl/test_ust-dl],[chmod +x tests/regression/ust/ust-dl/test_ust-dl])

AC_OUTPUT

#
# Mini-report on what will be built.
#

PPRINT_INIT
PPRINT_SET_INDENT(1)
PPRINT_SET_TS(38)

AS_ECHO
AS_ECHO("${PPRINT_COLOR_BLDBLU}LTTng-tools $PACKAGE_VERSION \"$version_name\"$PPRINT_COLOR_RST")
AS_ECHO

AS_IF([test -n "$report_fold"], [
	AS_ECHO("`AS_ECHO("$version_description") | $report_fold -s`")
], [
	AS_ECHO("$version_description")
])

AS_ECHO
PPRINT_SUBTITLE([Features])

# Target architecture we're building for.
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
PPRINT_PROP_STRING([Target architecture], $target_arch)

# kmod enabled/disabled
test "x$with_kmod" != "xno" && value=1 || value=0
PPRINT_PROP_BOOL([libkmod support], $value)

# LTTng-UST enabled/disabled
test "x$with_lttng_ust" = "xyes" && value=1 || value=0
PPRINT_PROP_BOOL([LTTng-UST support], $value)

AS_ECHO
PPRINT_SUBTITLE([Binaries])

# List binaries to be built
test x$enable_bin_lttng != xno && value=1 || value=0
PPRINT_PROP_BOOL([lttng], $value)

test x$enable_bin_lttng_consumerd != xno && value=1 || value=0
PPRINT_PROP_BOOL([lttng-consumerd], $value)

test x$enable_bin_lttng_crash != xno && value=1 || value=0
PPRINT_PROP_BOOL([lttng-crash], $value)

test x$enable_bin_lttng_relayd != xno && value=1 || value=0
PPRINT_PROP_BOOL([lttng-relayd], $value)

test x$enable_bin_lttng_sessiond != xno && value=1 || value=0
PPRINT_PROP_BOOL([lttng-sessiond], $value)

# Extras
test x$enable_extras != xno && value=1 || value=0
AS_ECHO
PPRINT_SET_INDENT(0)
PPRINT_PROP_BOOL([Extras], $value, $PPRINT_COLOR_SUBTITLE)
PPRINT_SET_INDENT(1)

AS_ECHO
PPRINT_SUBTITLE([Tests])

# Print clear message that tests won't be built
AS_IF([test "x$build_tests" = "xno"],[
	PPRINT_WARN([Tests won't be built since some binaries were disabled])
])

# LTTng UST Java agent JUL tests enabled/disabled
test "x$test_java_agent_jul" = "xyes" && value=1 || value=0
PPRINT_PROP_BOOL([LTTng-UST Java agent JUL tests], $value)

# LTTng UST Java agent Log4j tests enabled/disabled
test "x$test_java_agent_log4j" = "xyes" && value=1 || value=0
PPRINT_PROP_BOOL([LTTng-UST Java agent Log4j tests], $value)

test ! -z "$PYTHON2_AGENT" && value=1 || value=0
PPRINT_PROP_BOOL([LTTng-UST Python2 agent tests], $value)

test ! -z "$PYTHON3_AGENT" && value=1 || value=0
PPRINT_PROP_BOOL([LTTng-UST Python3 agent tests], $value)

#Python binding enabled/disabled
test "x$enable_python_binding" = xyes && value=1 || value=0
AS_ECHO
PPRINT_SET_INDENT(0)
PPRINT_PROP_BOOL([Python binding], $value, $PPRINT_COLOR_SUBTITLE)

# man pages build enabled/disabled
m4_pushdef([build_man_pages_msg], [Build and install man pages])

AS_IF([test "x$man_pages_opt" != "xno"], [
	AS_IF([test "x$in_git_repo" = "xyes"], [
		PPRINT_PROP_BOOL([build_man_pages_msg], 1, $PPRINT_COLOR_SUBTITLE)
	], [
		AS_IF([test "x$have_asciidoc_xmlto" = "xyes"], [
			PPRINT_PROP_BOOL([build_man_pages_msg], 1, $PPRINT_COLOR_SUBTITLE)
		], [
			PPRINT_PROP_STRING([build_man_pages_msg],
				[${PPRINT_COLOR_BLDGRN}yes (already built)],
				$PPRINT_COLOR_SUBTITLE)
		])
	])
], [
	PPRINT_PROP_BOOL([build_man_pages_msg], 0, $PPRINT_COLOR_SUBTITLE)
])

m4_popdef([build_man_pages_msg])

test "x$embedded_help" = xyes && value=1 || value=0
PPRINT_PROP_BOOL([Embed --help messages], $value, $PPRINT_COLOR_SUBTITLE)

PPRINT_SET_INDENT(1)

report_bindir="`eval eval echo $bindir`"
report_libdir="`eval eval echo $libdir`"

# Print the bindir and libdir this `make install' will install into.
AS_ECHO
PPRINT_SUBTITLE([Install directories])
PPRINT_PROP_STRING([Binaries], [$report_bindir])
PPRINT_PROP_STRING([Libraries], [$report_libdir])

AS_ECHO
PPRINT_SUBTITLE([Search directories])

# If we build the sessiond, print the paths it will use
AS_IF([test "$SESSIOND_BIN" = ""],[
	path="$report_bindir/lttng-sessiond"
],[
	path="$SESSIOND_BIN"
])
PPRINT_PROP_STRING([lttng-sessiond executable], [$path])

AS_IF([test "$CONSUMERD32_BIN" = ""],[
	path="`eval eval echo $lttnglibexecdir`/lttng-consumerd"
],[
	path="$CONSUMERD32_BIN"
])
PPRINT_PROP_STRING([32-bit lttng-consumerd executable], [$path])

AS_IF([test "$CONSUMERD32_LIBDIR" = ""],[
	path="`eval eval echo $libdir`"
],[
	path="$CONSUMERD32_LIBDIR"
])
PPRINT_PROP_STRING([32-bit consumer libraries], [$path])

AS_IF([test "$CONSUMERD64_BIN" = ""],[
	path="`eval eval echo $lttnglibexecdir`/lttng-consumerd"
],[
	path="$CONSUMERD64_BIN"
])
PPRINT_PROP_STRING([64-bit lttng-consumerd executable], [$path])

AS_IF([test "$CONSUMERD64_LIBDIR" = ""],[
	path="`eval eval echo $libdir`"
],[
	path="$CONSUMERD64_LIBDIR"
])
PPRINT_PROP_STRING([64-bit consumer libraries], [$path])
PPRINT_SET_INDENT(0)

AS_IF([test "x$warn_prebuilt_man_pages" = "xyes" ], [
	AS_ECHO
	PPRINT_WARN([You need asciidoc and xmlto to build the LTTng-tools man pages.

Note that the man pages are already built in this distribution tarball,
therefore asciidoc and xmlto are only needed if you intend to modify
their sources.

Also note that the installed man pages will contain the project's
default command-line option and environment variable values.

Use --disable-man-pages to completely disable building and installing
the man pages.])
])
