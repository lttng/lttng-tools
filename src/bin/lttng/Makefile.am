AM_CPPFLAGS = -DINSTALL_BIN_PATH=\""$(bindir)"\"

bin_PROGRAMS = lttng

lttng_SOURCES = command.h conf.c conf.h commands/start.c \
				commands/list.c commands/create.c commands/destroy.c \
				commands/stop.c commands/enable_events.c \
				commands/disable_events.c commands/enable_channels.c \
				commands/disable_channels.c commands/add_context.c \
				commands/set_session.c commands/version.c \
				commands/calibrate.c commands/view.c \
				utils.c utils.h lttng.c

lttng_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		$(top_builddir)/src/common/libcommon.la
