AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttng-consumer.la

liblttng_consumer_la_SOURCES = lttng-consumer.c

liblttng_consumer_la_LIBADD = \
		$(top_builddir)/liblttng-sessiond-comm/liblttng-sessiond-comm.la \
		$(top_builddir)/liblttng-kconsumer/liblttng-kconsumer.la


if LTTNG_TOOLS_HAVE_UST
liblttng_consumer_la_LIBADD += \
		$(top_builddir)/liblttng-ustconsumer/liblttng-ustconsumer.la
endif
