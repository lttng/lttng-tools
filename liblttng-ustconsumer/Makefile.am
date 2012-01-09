AM_CPPFLAGS = -I$(top_srcdir)/include

if HAVE_LIBLTTNG_UST_CTL
noinst_LTLIBRARIES = liblttng-ustconsumer.la

liblttng_ustconsumer_la_SOURCES = lttng-ustconsumer.c

liblttng_ustconsumer_la_LIBADD = -llttng-ust-ctl

endif
