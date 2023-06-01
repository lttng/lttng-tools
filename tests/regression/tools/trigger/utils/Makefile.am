# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/tests/utils
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la
LIBCOMMON_LGPL=$(top_builddir)/src/common/libcommon-lgpl.la

noinst_PROGRAMS = \
	notification-client \
	register-some-triggers

notification_client_SOURCES = notification-client.cpp
notification_client_LDADD = $(LIBLTTNG_CTL) $(LIBCOMMON_LGPL) \
	$(top_builddir)/tests/utils/libtestutils.la

register_some_triggers_SOURCES = register-some-triggers.cpp
register_some_triggers_LDADD = $(LIBLTTNG_CTL) \
	$(top_builddir)/src/common/libfilter.la \
	$(top_builddir)/src/common/libbytecode.la
