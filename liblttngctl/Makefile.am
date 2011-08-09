AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttngctl.la

liblttngctl_la_SOURCES = lttngctl.c

liblttngctl_la_LIBADD = \
		$(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la
