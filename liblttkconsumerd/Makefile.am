AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttkconsumerd -I$(top_srcdir)/libkernelctl

lib_LTLIBRARIES = liblttkconsumerd.la

liblttkconsumerd_la_SOURCES = lttkconsumerd.c lttkconsumerd.h

liblttkconsumerd_la_LIBADD = \
		$(top_builddir)/libkernelctl/libkernelctl.la \
		$(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la
