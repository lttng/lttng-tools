AM_CPPFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = lttng-consumerd

lttng_consumerd_SOURCES = lttng-consumerd.c

lttng_consumerd_LDADD = \
	   $(top_builddir)/libkernelctl/libkernelctl.la \
	   $(top_builddir)/liblttng-consumer/liblttng-consumer.la \
	   $(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
	   $(top_builddir)/librunas/librunas.la

if HAVE_LIBLTTNG_UST_CTL
lttng_consumerd_LDADD += -llttng-ust-ctl
endif
