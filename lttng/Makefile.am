AM_CPPFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = lttng

lttng_SOURCES = config.c commands/start.c commands/add_channel.c \
				commands/list.c commands/create.c commands/destroy.c \
				commands/stop.c commands/enable_events.c \
				utils.c lttng.c

lttng_LDADD = \
		$(top_builddir)/liblttngctl/liblttngctl.la
