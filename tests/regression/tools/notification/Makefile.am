AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests -I$(top_srcdir)/tests/utils/ -I$(srcdir)
AM_LDFLAGS =


LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
LIB_LTTNG_CTL = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

noinst_PROGRAMS = base_client notification

if NO_SHARED

CLEANFILES = libpause_consumer.so libpause_consumer.so.debug
EXTRA_DIST = test_notification_ust test_notification_kernel test_notification_multi_app base_client.c notification.c consumer_testpoints.c

else

# In order to test the health check feature, the helper library
# must be built as .so to be able to LD_PRELOAD it.
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)

libpause_consumer_la_SOURCES = consumer_testpoints.c
libpause_consumer_la_LIBADD = $(top_builddir)/src/common/libcommon.la $(DL_LIBS)
libpause_consumer_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)
noinst_LTLIBRARIES = libpause_consumer.la

base_client_SOURCES = base_client.c
base_client_LDADD = $(LIB_LTTNG_CTL)

notification_SOURCES = notification.c
notification_LDADD = $(LIB_LTTNG_CTL) $(LIBTAP) -lm

noinst_SCRIPTS = test_notification_ust test_notification_ust test_notification_multi_app
EXTRA_DIST = test_notification_ust test_notification_kernel test_notification_multi_app


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
endif
