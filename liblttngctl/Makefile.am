AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttsessiondcomm

lib_LTLIBRARIES = liblttngctl.la

liblttngctl_la_SOURCES = liblttngctl.c

liblttngctl_la_LIBADD = \
		$(top_builddir)/liblttsessiondcomm/liblttsessiondcomm.la
