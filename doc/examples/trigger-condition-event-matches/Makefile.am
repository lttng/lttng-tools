# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir)

LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la
dist_noinst_SCRIPTS = demo.sh
EXTRA_DIST = README.md

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = instrumented-app notification-client
noinst_LIBRARIES = libtracepoint-trigger-example.a

libtracepoint_trigger_example_a_SOURCES = tracepoint-trigger-example.c tracepoint-trigger-example.h

instrumented_app_SOURCES = instrumented-app.c
instrumented_app_LDADD = libtracepoint-trigger-example.a $(UST_LIBS) $(DL_LIBS)

notification_client_SOURCES = notification-client.c
notification_client_LDADD = $(LIBLTTNG_CTL)

endif
