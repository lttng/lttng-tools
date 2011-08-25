AM_CPPFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = ltt-kconsumerd

ltt_kconsumerd_SOURCES = ltt-kconsumerd.c

ltt_kconsumerd_LDADD = \
	   $(top_builddir)/libkernelctl/libkernelctl.la \
	   $(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
	   $(top_builddir)/liblttngkconsumerd/liblttngkconsumerd.la
