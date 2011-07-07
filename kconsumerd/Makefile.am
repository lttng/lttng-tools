AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttkconsumerd -I$(top_srcdir)/liblttsessiondcomm -I$(top_srcdir)/libkernelctl

bin_PROGRAMS = kconsumerd

kconsumerd_SOURCES = kconsumerd.c

kconsumerd_LDADD = \
		 $(top_builddir)/liblttsessiondcomm/liblttsessiondcomm.la \
		 $(top_builddir)/libkernelctl/libkernelctl.la \
		 $(top_builddir)/liblttkconsumerd/liblttkconsumerd.la
