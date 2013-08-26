AM_CFLAGS = -I. -O2 -g -I$(top_srcdir)/include
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

if NO_SHARED
# Do not build this test if shared libraries support was
# explicitly disabled.
else
# In order to test the health check feature, the libhealth* libs
# must be built as .so to be able to LD_PRELOAD them.
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)

# Health thread exit ld_preloaded test lib
libhealthexit_la_SOURCES=health_exit.c
libhealthexit_la_LDFLAGS= $(FORCE_SHARED_LIB_OPTIONS)

# Health thread stall ld_preloaded test lib
libhealthstall_la_SOURCES=health_stall.c
libhealthstall_la_LDFLAGS= $(FORCE_SHARED_LIB_OPTIONS)

# Health thread fail ld_preloaded test lib
libhealthtpfail_la_SOURCES=health_fail.c
libhealthtpfail_la_LDFLAGS= $(FORCE_SHARED_LIB_OPTIONS)

noinst_PROGRAMS = health_check
noinst_LTLIBRARIES = libhealthexit.la libhealthstall.la libhealthtpfail.la

health_check_SOURCES = health_check.c $(UTILS)
health_check_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		     $(top_builddir)/src/common/libcommon.la
endif

dist_noinst_SCRIPTS = test_thread_exit test_thread_stall test_tp_fail
EXTRA_DIST = test_thread_exit test_thread_stall test_tp_fail

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
