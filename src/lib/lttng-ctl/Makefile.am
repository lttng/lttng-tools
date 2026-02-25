# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
#
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
		reclaim.cpp \
		rotate.cpp \
		save.cpp \
		snapshot.cpp \
		tracker.cpp

liblttng_ctl_la_LDFLAGS = \
		$(LT_NO_UNDEFINED) \
		-export-symbols $(srcdir)/liblttng-ctl.sym \
		-Wl,--version-script=$(srcdir)/liblttng-ctl.map

EXTRA_liblttng_ctl_la_DEPENDENCIES = liblttng-ctl.sym

EXTRA_DIST = \
	abi_ref/0.0.0/x86_64-64bit-linux/abi.xml \
	abi_ref/README.md \
	liblttng-ctl.map \
	liblttng-ctl.sym \
	REUSE.toml

liblttng_ctl_la_LIBADD = \
		$(top_builddir)/src/common/libsessiond-comm.la \
		$(top_builddir)/src/common/libcommon-lgpl.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ctl.pc
