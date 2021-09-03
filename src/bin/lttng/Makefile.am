# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -DINSTALL_BIN_PATH=\""$(bindir)"\"

if EMBED_HELP
AM_CPPFLAGS += -I$(top_builddir)/doc/man
endif

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = lttng

lttng_SOURCES = command.h conf.cpp conf.h commands/start.cpp \
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
				loglevel.cpp loglevel.h \
				commands/add_trigger.cpp \
				commands/list_triggers.cpp \
				commands/remove_trigger.cpp \
				utils.cpp utils.h lttng.cpp \
				uprobe.cpp uprobe.h

lttng_CXXFLAGS = $(AM_CXXFLAGS) $(POPT_CFLAGS)

lttng_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
			$(top_builddir)/src/common/libcommon.la \
			$(top_builddir)/src/common/config/libconfig.la \
			$(top_builddir)/src/common/string-utils/libstring-utils.la \
			$(top_builddir)/src/common/filter/libfilter.la \
			$(top_builddir)/src/common/argpar/libargpar.la \
			$(POPT_LIBS)
