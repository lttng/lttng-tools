AM_CPPFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = lttng

lttng_SOURCES = conf.c commands/start.c commands/add_channel.c \
				commands/list.c commands/create.c commands/destroy.c \
				commands/stop.c commands/enable_events.c \
				commands/disable_events.c commands/enable_channels.c \
				commands/disable_channels.c commands/add_context.c \
				utils.c lttng.c

lttng_LDADD = \
		$(top_builddir)/liblttngctl/liblttngctl.la
