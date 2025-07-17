# SPDX-License-Identifier: GPL-2.0-only

include $(top_srcdir)/aminclude_static.am

AM_CPPFLAGS += -DINSTALL_BIN_PATH=\""$(bindir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = lttng

lttng_SOURCES = command.hpp conf.cpp conf.hpp commands/start.cpp \
				commands/list.cpp commands/create.cpp commands/destroy.cpp \
				commands/stop.cpp commands/enable_events.cpp \
				commands/disable_events.cpp commands/enable_channels.cpp \
				commands/disable_channels.cpp commands/add_context.cpp \
				commands/set_session.cpp commands/version.cpp \
				commands/view.cpp \
				commands/snapshot.cpp \
				commands/save.cpp \
				commands/load.cpp \
				commands/track-untrack.cpp \
				commands/status.cpp \
				commands/metadata.cpp \
				commands/regenerate.cpp \
				commands/help.cpp \
				commands/rotate.cpp \
				commands/enable_rotation.cpp \
				commands/disable_rotation.cpp \
				commands/clear.cpp \
				loglevel.cpp loglevel.hpp \
				commands/add_trigger.cpp \
				commands/list_triggers.cpp \
				commands/remove_trigger.cpp \
				utils.cpp utils.hpp lttng.cpp \
				uprobe.cpp uprobe.hpp \
				exception.hpp exception.cpp

lttng_CXXFLAGS = $(AM_CXXFLAGS) $(POPT_CFLAGS)

lttng_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
			$(top_builddir)/src/common/libcommon-lgpl.la \
			$(top_builddir)/src/common/libpath.la \
			$(top_builddir)/src/common/libconfig.la \
			$(top_builddir)/src/common/libstring-utils.la \
			$(top_builddir)/src/common/libfilter.la \
			$(top_builddir)/src/common/libargpar-utils.la \
			$(top_builddir)/src/vendor/argpar/libargpar.la \
			$(top_builddir)/src/vendor/fmt/libfmt.la \
			$(POPT_LIBS)
