# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -DINSTALL_BIN_PATH=\""$(bindir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

bin_PROGRAMS = lttng-crash

lttng_crash_SOURCES = lttng-crash.cpp

lttng_crash_LDADD = $(top_builddir)/src/common/libcommon-gpl.la \
			$(top_builddir)/src/common/libconfig.la \
			$(top_builddir)/src/vendor/fmt/libfmt.la
