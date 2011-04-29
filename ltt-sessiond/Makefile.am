AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttsessiondcomm
AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ltt-sessiond

ltt_sessiond_SOURCES = session.c main.c

ltt_sessiond_LDADD = \
		 $(top_builddir)/liblttsessiondcomm/liblttsessiondcomm.la
