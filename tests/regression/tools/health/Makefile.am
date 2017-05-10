AM_CPPFLAGS += -I. -I$(top_srcdir)/include

COPYSCRIPTS = test_thread_exit test_thread_stall test_tp_fail \
	test_health.sh test_thread_ok
dist_noinst_SCRIPTS = $(COPYSCRIPTS)

if NO_SHARED
# Do not build this test if shared libraries support was
# explicitly disabled.

EXTRA_DIST = health_exit.c health_stall.c health_fail.c \
	health_check.c $(COPYSCRIPTS)

else
# In order to test the health check feature, the libhealth* libs
# must be built as .so to be able to LD_PRELOAD them.
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)

# Health thread exit ld_preloaded test lib
libhealthexit_la_SOURCES=health_exit.c
libhealthexit_la_LDFLAGS= $(FORCE_SHARED_LIB_OPTIONS)
libhealthexit_la_LIBADD = $(DL_LIBS)

# Health thread stall ld_preloaded test lib
libhealthstall_la_SOURCES=health_stall.c
libhealthstall_la_LDFLAGS= $(FORCE_SHARED_LIB_OPTIONS)
libhealthstall_la_LIBADD = $(DL_LIBS)

# Health thread fail ld_preloaded test lib
libhealthtpfail_la_SOURCES=health_fail.c
libhealthtpfail_la_LDFLAGS= $(FORCE_SHARED_LIB_OPTIONS)
libhealthtpfail_la_LIBADD = $(DL_LIBS)

noinst_PROGRAMS = health_check
noinst_LTLIBRARIES = libhealthexit.la libhealthstall.la libhealthtpfail.la

health_check_SOURCES = health_check.c $(UTILS)
health_check_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		     $(top_builddir)/src/common/libcommon.la \
		     $(DL_LIBS)

EXTRA_DIST = $(COPYSCRIPTS)

endif

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(COPYSCRIPTS); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(COPYSCRIPTS); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
