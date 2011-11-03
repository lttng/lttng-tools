AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_LTLIBRARIES = liblttng-kconsumer.la

liblttng_kconsumer_la_SOURCES = lttng-kconsumer.c

liblttng_kconsumer_la_LIBADD = \
		$(top_builddir)/libkernelctl/libkernelctl.la
