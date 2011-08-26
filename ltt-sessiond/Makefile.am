AM_CPPFLAGS = -I$(top_srcdir)/include \
			  -DINSTALL_BIN_PATH=\""$(bindir)"\"

AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ltt-sessiond

ltt_sessiond_SOURCES = utils.c utils.h \
                       trace-kernel.c trace-kernel.h \
                       trace-ust.c trace-ust.h \
                       session.c session.h \
                       traceable-app.c traceable-app.h \
                       ust-ctl.c ust-ctl.h \
                       kernel-ctl.c kernel-ctl.h \
                       context.c context.h \
                       futex.c futex.h \
                       ust-comm.c ust-comm.h \
                       ltt-sessiond.h main.c

# link on liblttngctl for check if sessiond is already alive.
ltt_sessiond_LDADD = \
		 $(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
		 $(top_builddir)/libkernelctl/libkernelctl.la \
		 $(top_builddir)/libustctl/libustctl.la	\
		 $(top_builddir)/liblttngctl/liblttngctl.la
