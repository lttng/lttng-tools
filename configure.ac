AC_PREREQ([2.64])
AC_INIT([lttng-tools],[2.7.1],[jeremie.galarneau@efficios.com],[],[https://lttng.org])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Compute minor/major/patchlevel version numbers
AC_PROG_SED
major_version=$(echo AC_PACKAGE_VERSION | sed 's/^\([[0-9]]\)*\.[[0-9]]*\.[[0-9]]*.*$/\1/')
minor_version=$(echo AC_PACKAGE_VERSION | sed 's/^[[0-9]]*\.\([[0-9]]*\)\.[[0-9]]*.*$/\1/')
patchlevel_version=$(echo AC_PACKAGE_VERSION | sed 's/^[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\).*$/\1/')
AC_SUBST([MAJOR_VERSION], [$major_version])
AC_SUBST([MINOR_VERSION], [$minor_version])
AC_SUBST([PATCHLEVEL_VERSION], [$patchlevel_version])
AC_DEFINE_UNQUOTED([VERSION_MAJOR], $major_version, [LTTng-Tools major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], $minor_version, [LTTng-Tools minor version number])
AC_DEFINE_UNQUOTED([VERSION_PATCHLEVEL], $patchlevel_version, [LTTng-Tools patchlevel version number])

version_name="Herbe à Détourne"
version_description='Brewed with unrestrained amounts of Citra hop, the Herbe à Détourne is a fantastic New World Tripel brewed by "Dieu du Ciel!". Aromas of mango, cantaloupe melon and passion fruit, combined with a controlled bitter finish, unite in making this smooth golden-orange beer stand apart.'
version_description_c=$(echo $version_description | sed 's/"/\\"/g')

AC_DEFINE_UNQUOTED([VERSION_NAME], ["$version_name"], "")
AC_DEFINE_UNQUOTED([VERSION_DESCRIPTION], ["$version_description_c"], "")

AC_CONFIG_HEADERS([include/config.h])

AC_PROG_GREP
# libtool link_all_deplibs fixup. See http://bugs.lttng.org/issues/321.
AC_ARG_ENABLE(libtool-linkdep-fixup,
	AS_HELP_STRING([--disable-libtool-linkdep-fixup],
			[disable the libtool fixup for linking all dependent libraries (link_all_deplibs)]),
	libtool_fixup=$enableval,
	libtool_fixup=yes)

AS_IF([test "x$libtool_fixup" = "xyes"],
	    [
	    libtool_m4="$srcdir/config/libtool.m4"
	    libtool_flag_pattern=".*link_all_deplibs\s*,\s*\$1\s*)"
	    AC_MSG_CHECKING([for occurence(s) of link_all_deplibs = no in $libtool_m4])
	    libtool_flag_pattern_count=$(grep -c "$libtool_flag_pattern\s*=\s*no" $libtool_m4)
	    AS_IF([test $libtool_flag_pattern_count -ne 0],
	    [
		  AC_MSG_RESULT([$libtool_flag_pattern_count])
		  AC_MSG_WARN([the detected libtool will not link all dependencies, forcing link_all_deplibs = unknown])
		  sed -i "s/\($libtool_flag_pattern\)\s*=\s*no/\1=unknown/g" $libtool_m4
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
	atexit bzero clock_gettime dup2 fdatasync ftruncate \
	gethostbyname gethostname getpagesize localtime_r memchr memset \
	mkdir munmap putenv realpath rmdir socket strchr strcspn strdup \
	strncasecmp strndup strpbrk strrchr strstr strtol strtoul \
	strtoull \
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

if test "x$prefix" = "xNONE"; then
	prefix=$ac_default_prefix
fi
CONFDIR=`eval echo $sysconfdir`
AC_SUBST(CONFDIR)
AC_DEFINE_UNQUOTED([CONFIG_LTTNG_SYSTEM_CONFIGDIR],"$CONFDIR", [LTTng system configuration directory.])

AC_DEFINE_DIR([CONFIG_LTTNG_SYSTEM_DATADIR],[datadir], [LTTng system data directory.])

#
# Check for pthread
AC_CHECK_LIB([pthread], [pthread_create], [],
	[AC_MSG_ERROR([Cannot find libpthread. Use LDFLAGS=-Ldir to specify its location.])]
)

# Check libpopt
PKG_CHECK_MODULES([POPT], [popt],
	[LIBS="$LIBS $POPT_LIBS"],
	[
		AC_MSG_WARN([pkg-config was unable to find a valid .pc for libpopt. Set PKG_CONFIG_PATH to specify the pkgconfig configuration file location])
		AC_MSG_WARN([Finding libpopt without pkg-config.])
		AC_CHECK_LIB([popt],
			[poptGetContext],
			[],
			[
				 AC_MSG_ERROR([Cannot find libpopt. Either set PKG_CONFIG_PATH to the configuration file location or use LDFLAGS=-Ldir to specify the library location])
			]
		)
	]
)

AM_PATH_XML2(2.7.6, true, AC_MSG_ERROR(No supported version of libxml2 found.))

# Check for libuuid
PKG_CHECK_MODULES([UUID], [uuid],
[
	LIBS="$LIBS $UUID_LIBS"
	AC_DEFINE_UNQUOTED([LTTNG_HAVE_LIBUUID], 1, [Has libuuid support.])
	have_libuuid=yes
],
[
	AC_MSG_WARN([pkg-config was unable to find a valid .pc for libuuid. Set PKG_CONFIG_PATH to specify the pkgconfig configuration file location])
	AC_MSG_WARN([Finding libuuid without pkg-config.])
	AC_CHECK_LIB([uuid],
		[uuid_generate],
		[
			AC_DEFINE_UNQUOTED([LTTNG_HAVE_LIBUUID], 1, [Has libuuid support.])
			have_libuuid=yes
		],
		[
			# libuuid not found, check for uuid_create in libc.
			AC_CHECK_LIB([c],
				[uuid_create],
				[
					AC_DEFINE_UNQUOTED([LTTNG_HAVE_LIBC_UUID], 1, [Has libc uuid support.])
					have_libc_uuid=yes
				],
				[
					AC_MSG_ERROR([Cannot find libuuid uuid_generate nor libc uuid_create. Either set PKG_CONFIG_PATH to the configuration file location or use LDFLAGS=-Ldir to specify the library location])
				]
			)
		]
	)
])
AM_CONDITIONAL([LTTNG_BUILD_WITH_LIBUUID], [test "x$have_libuuid" = "xyes"])
AM_CONDITIONAL([LTTNG_BUILD_WITH_LIBC_UUID], [test "x$have_libc_uuid" = "xyes"])

# URCU library version needed or newer
liburcu_version=">= 0.8.0"

# Check liburcu needed function calls
AC_CHECK_DECL([cds_list_add], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/list.h>]]
)
AC_CHECK_DECL([cds_wfcq_init], [],
	[AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/wfcqueue.h>]]
)
AC_CHECK_DECL([cds_wfcq_dequeue_blocking], [],
    [AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu/wfcqueue.h>]]
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
#Function added in urcu 0.7.0
AC_CHECK_DECL([cmm_smp_mb__before_uatomic_or], [],
        [AC_MSG_ERROR([liburcu $liburcu_version or newer is needed])], [[#include <urcu.h>]]
)

# Check kmod library
AC_ARG_WITH(kmod-prefix,
  AS_HELP_STRING([--with-kmod-prefix=PATH],
		[Specify the installation prefix of the kmod library.
		Headers must be in PATH/include; libraries in PATH/lib.]),
		[
			CPPFLAGS="$CPPFLAGS -I${withval}/include"
			LDFLAGS="$LDFLAGS -L${withval}/lib64 -L${withval}/lib"
		])

AC_ARG_ENABLE(kmod,
	AS_HELP_STRING([--disable-kmod],[build without kmod support]),
	kmod_support=zz$enableval, kmod_support=yes)

AS_IF([test "x$kmod_support" = "xyes"], [
	AC_CHECK_LIB([kmod], [kmod_module_probe_insert_module],
		[
			AC_DEFINE([HAVE_KMOD], [1], [has kmod support])
			LIBS="$LIBS -lkmod"
			kmod_found=yes
		],
		kmod_found=no
	)
])
AM_CONDITIONAL([HAVE_KMOD], [test "x$kmod_found" = xyes])

AC_ARG_WITH(lttng-ust-prefix,
  AS_HELP_STRING([--with-lttng-ust-prefix=PATH],
                 [Specify the installation prefix of the lttng-ust library.
	          Headers must be in PATH/include; libraries in PATH/lib.]),
		  [
		    CPPFLAGS="$CPPFLAGS -I${withval}/include"
		    LDFLAGS="$LDFLAGS -L${withval}/lib64 -L${withval}/lib"
		  ])

# Check liblttng-ust-ctl library
AC_ARG_ENABLE(lttng-ust,
	AS_HELP_STRING([--disable-lttng-ust],[build without LTTng-UST (Userspace Tracing) support]),
	lttng_ust_support=$enableval, lttng_ust_support=yes)

AS_IF([test "x$lttng_ust_support" = "xyes"], [
	AC_CHECK_LIB([lttng-ust-ctl], [ustctl_recv_channel_from_consumer],
		[
			AC_DEFINE([HAVE_LIBLTTNG_UST_CTL], [1], [has LTTng-UST control support])
			lttng_ust_ctl_found=yes
		],
		[AC_MSG_ERROR([Cannot find LTTng-UST >= 2.2.x. Use --with-lttng-ust-prefix=PREFIX to specify its location, or specify --disable-lttng-ust to build lttng-tools without LTTng-UST support.])],
		[-lurcu-common -lurcu-bp -lurcu-cds -lrt -ldl]
	)
])
AM_CONDITIONAL([HAVE_LIBLTTNG_UST_CTL], [test "x$lttng_ust_ctl_found" = xyes])
AC_CHECK_FUNCS([sched_getcpu sysconf sync_file_range])

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
              [enable_python_binding=yes], [enable_python_binding=no])

AM_CONDITIONAL([PYTHON_BINDING], [test "x${enable_python_binding:-yes}" = xyes])

if test "x${enable_python_binding:-yes}" = xyes; then
  AX_PKG_SWIG($swig_version, [], [ AC_MSG_ERROR([SWIG $swig_version or newer is needed]) ])
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
	AX_CHECK_CLASS(org.lttng.ust.agent.LTTngAgent)
	if test "x$ac_cv_class_org_lttng_ust_agent_LTTngAgent" = "xno"; then
		AC_MSG_ERROR([The UST Java agent common class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/liblttng-ust-agent.jar"])
	fi

	if test "x$test_java_agent_jul" = "xyes"; then
		# Check for JUL agent class
		AX_CHECK_CLASS(org.lttng.ust.agent.jul.LTTngJUL)
		if test "x$ac_cv_class_org_lttng_ust_agent_jul_LTTngJUL" = "xno"; then
			AC_MSG_ERROR([The UST Java agent JUL class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/liblttng-ust-jul.jar"])
		fi
	fi

	if test "x$test_java_agent_log4j" = "xyes"; then
		# Check for Log4j agent class
		AX_CHECK_CLASS(org.lttng.ust.agent.log4j.LTTngLog4j)
		if test "x$ac_cv_class_org_lttng_ust_agent_log4j_LTTngLog4j" = "xno"; then
			AC_MSG_ERROR([The UST Java agent Log4j class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/liblttng-ust-agent.jar"])
		fi

		# Check for Log4j class
		AX_CHECK_CLASS(org.apache.log4j.Logger)
		if test "x$ac_cv_class_org_apache_log4j_Logger" = "xno"; then
			AC_MSG_ERROR([The Log4j class was not found. Please specify the location of the jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/log4j.jar"])
		fi
	fi
fi

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

AC_SYS_LARGEFILE

# C compiler tests
AC_PROG_CC
AC_C_INLINE

# Type availability checking
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

LT_INIT
AC_PROG_YACC
AC_PROG_LEX

if test ! -f "$srcdir/src/lib/lttng-ctl/filter/filter-parser.h"; then
	if test x"$YACC" != "xbison -y"; then
		AC_MSG_ERROR([[bison not found and is required when building from git.
		Please install bison]])
	fi
	AC_PATH_PROG([BISON],[bison])
	AX_PROG_BISON_VERSION([2.4], [],[
		AC_MSG_ERROR([[Bison >= 2.4 is required when building from git]])
	])
fi

if test ! -f "$srcdir/src/lib/lttng-ctl/filter/filter-lexer.c"; then
	if test x"$LEX" != "xflex"; then
		AC_MSG_ERROR([[flex not found and is required when building from git.
		Please install flex]])
	fi
	AC_PATH_PROG([FLEX],[flex])
	AX_PROG_FLEX_VERSION([2.5.35], [],[
		AC_MSG_ERROR([[Flex >= 2.5.35 is required when building from git]])
	])
fi

CFLAGS="-Wall $CFLAGS -g -fno-strict-aliasing"

DEFAULT_INCLUDES="-I\$(top_srcdir) -I\$(top_builddir) -I\$(top_builddir)/src -I\$(top_builddir)/include -include config.h"

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
	extras/Makefile
	extras/bindings/Makefile
	extras/bindings/swig/Makefile
	extras/bindings/swig/python/Makefile
	extras/core-handler/Makefile
	src/Makefile
	src/common/Makefile
	src/common/kernel-ctl/Makefile
	src/common/kernel-consumer/Makefile
	src/common/ust-consumer/Makefile
	src/common/hashtable/Makefile
	src/common/sessiond-comm/Makefile
	src/common/compat/Makefile
	src/common/relayd/Makefile
	src/common/testpoint/Makefile
	src/common/index/Makefile
	src/common/health/Makefile
	src/common/config/Makefile
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
	tests/regression/tools/mi/Makefile
	tests/regression/tools/wildcard/Makefile
	tests/regression/tools/crash/Makefile
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
	tests/regression/ust/java-jul/Makefile
	tests/regression/ust/java-log4j/Makefile
	tests/regression/ust/python-logging/Makefile
	tests/regression/ust/getcpu-override/Makefile
	tests/regression/ust/clock-override/Makefile
	tests/stress/Makefile
	tests/unit/Makefile
	tests/unit/ini_config/Makefile
	tests/utils/Makefile
	tests/utils/tap/Makefile
	tests/utils/testapp/Makefile
	tests/utils/testapp/gen-ust-events/Makefile
	tests/utils/testapp/gen-ust-nevents/Makefile
	tests/utils/testapp/gen-ust-tracef/Makefile
])

# Inject variable into python test script
AC_CONFIG_FILES([tests/regression/ust/python-logging/test_python_logging],[chmod +x tests/regression/ust/python-logging/test_python_logging])

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

# kmod enabled/disabled
AS_ECHO_N("libkmod support: ")
AS_IF([test "x$kmod_found" = "xyes"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

# LTTng-UST enabled/disabled
AS_ECHO_N("Lttng-UST support: ")
AS_IF([test "x$lttng_ust_support" = "xyes"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

# LTTng UST Java agent JUL tests enabled/disabled
AS_ECHO_N("LTTng-UST Java agent JUL tests: ")
AS_IF([test "x$test_java_agent_jul" = "xyes"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

# LTTng UST Java agent Log4j tests enabled/disabled
AS_ECHO_N("LTTng-UST Java agent Log4j tests: ")
AS_IF([test "x$test_java_agent_log4j" = "xyes"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

AS_ECHO_N("LTTng-UST Python2 agent tests: ")
AS_IF([test ! -z "$PYTHON2_AGENT"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

AS_ECHO_N("LTTng-UST Python3 agent tests: ")
AS_IF([test ! -z "$PYTHON3_AGENT"],[
	AS_ECHO("Enabled")
],[
	AS_ECHO("Disabled")
])

#Python binding enabled/disabled
AS_ECHO_N("Python binding: ")
AS_IF([test "x${enable_python_binding:-yes}" = xyes], [
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
	AS_ECHO_N("The lttng command will look for the lttng-sessiond executable at: ")
	AS_IF([test "$SESSIOND_BIN" = ""],[
		AS_ECHO_N("`eval eval echo $bindir`")
		AS_ECHO("/lttng-sessiond")
	],[
		AS_ECHO("$SESSIOND_BIN")
	])

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

