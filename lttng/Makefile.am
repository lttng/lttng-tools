AM_CPPFLAGS = -I$(top_srcdir)/include \
			  -DINSTALL_BIN_PATH=\""$(bindir)"\"

bin_PROGRAMS = lttng

lttng_SOURCES = cmd.h conf.c conf.h commands/start.c \
				commands/list.c commands/create.c commands/destroy.c \
				commands/stop.c commands/enable_events.c \
				commands/disable_events.c commands/enable_channels.c \
				commands/disable_channels.c commands/add_context.c \
				commands/set_session.c commands/version.c \
				commands/calibrate.c utils.c utils.h lttng.c

lttng_LDADD = \
		$(top_builddir)/liblttngctl/liblttngctl.la
