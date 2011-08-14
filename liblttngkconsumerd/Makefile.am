AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libkernelctl

lib_LTLIBRARIES = liblttngkconsumerd.la

liblttngkconsumerd_la_SOURCES = lttngkconsumerd.c

liblttngkconsumerd_la_LIBADD = \
		$(top_builddir)/libkernelctl/libkernelctl.la \
		$(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la
