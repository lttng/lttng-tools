# SPDX-License-Identifier: GPL-2.0-only

include $(top_srcdir)/aminclude_static.am

lib_LTLIBRARIES = liblttng-ctl.la

liblttng_ctl_la_SOURCES = \
		channel.cpp \
		clear.cpp \
		deprecated-symbols.cpp \
		destruction-handle.cpp \
		event.cpp \
		event-rule-convert.cpp \
		event-rule-convert.hpp \
		load.cpp \
		lttng-ctl.cpp \
		lttng-ctl-health.cpp \
		lttng-ctl-helper.hpp \
		rotate.cpp \
		save.cpp \
		snapshot.cpp \
		tracker.cpp

liblttng_ctl_la_LDFLAGS = \
		$(LT_NO_UNDEFINED) \
		-export-symbols $(srcdir)/liblttng-ctl.sym \
		-Wl,--version-script=$(srcdir)/liblttng-ctl.map

EXTRA_liblttng_ctl_la_DEPENDENCIES = liblttng-ctl.sym

EXTRA_DIST = liblttng-ctl.map \
		liblttng-ctl.sym

liblttng_ctl_la_LIBADD = \
		$(top_builddir)/src/common/libsessiond-comm.la \
		$(top_builddir)/src/common/libcommon-lgpl.la \
		$(top_builddir)/src/vendor/fmt/libfmt.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ctl.pc
