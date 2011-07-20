AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttkconsumerd -I$(top_srcdir)/liblttsessiondcomm -I$(top_srcdir)/libkernelctl

lib_LTLIBRARIES = liblttkconsumerd.la

liblttkconsumerd_la_SOURCES = liblttkconsumerd.c liblttkconsumerd.h

liblttkconsumerd_la_LIBADD = \
		$(top_builddir)/libkernelctl/libkernelctl.la \
		$(top_builddir)/liblttsessiondcomm/liblttsessiondcomm.la
