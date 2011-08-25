AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/benchmark \
			  -DINSTALL_BIN_PATH=\"$(bindir)\"

AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ltt-sessiond

ltt_sessiond_SOURCES = utils.c trace.c session.c traceable-app.c ust-ctl.c \
                       kernel-ctl.c context.c main.c \
                       utils.h trace.h session.h traceable-app.h ust-ctl.h \
                       context.h kernel-ctl.h ltt-sessiond.h

# link on liblttngctl for check if sessiond is already alive.
ltt_sessiond_LDADD = \
		 $(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
		 $(top_builddir)/libkernelctl/libkernelctl.la \
		 $(top_builddir)/libustctl/libustctl.la	\
		 $(top_builddir)/liblttngctl/liblttngctl.la \
		 $(top_builddir)/benchmark/liblttng-benchmark.la
