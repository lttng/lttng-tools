AM_CPPFLAGS = -I$(top_srcdir)/include
#AM_CFLAGS = $(LTTNG_LIBS) -lpopt

bin_PROGRAMS = lttng

lttng_SOURCES = options.c lttng.c

lttng_LDADD = \
		$(top_builddir)/liblttngctl/liblttngctl.la
#		$(top_builddir)/liblttsessiondcomm/liblttsessiondcomm.la
