AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttsessiondcomm \
			  -I$(top_srcdir)/libkernelctl -I$(top_srcdir)/libustctl

AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ltt-sessiond

ltt_sessiond_SOURCES = utils.c trace.c session.c traceable-app.c ust-ctl.c kernel-ctl.c main.c

ltt_sessiond_LDADD = \
		 $(top_builddir)/liblttsessiondcomm/liblttsessiondcomm.la \
		 $(top_builddir)/libkernelctl/libkernelctl.la \
		 $(top_builddir)/libustctl/libustctl.la
