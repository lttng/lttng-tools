AM_CPPFLAGS = -I$(top_srcdir)/include

if LTTNG_TOOLS_HAVE_UST
noinst_LTLIBRARIES = liblttng-ustconsumer.la

liblttng_ustconsumer_la_SOURCES = lttng-ustconsumer.c

liblttng_ustconsumer_la_LIBADD = -llttng-ust-ctl
endif
