AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttngctl.la

liblttngctl_la_SOURCES = liblttngctl.c

liblttngctl_la_LIBADD = \
		$(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la
