# Consumer library
noinst_LTLIBRARIES = libconsumer.la

noinst_HEADERS = consumer-metadata-cache.h consumer-timer.h \
		 consumer-testpoint.h

libconsumer_la_SOURCES = consumer.c consumer.h consumer-metadata-cache.c \
                         consumer-timer.c consumer-stream.c consumer-stream.h

libconsumer_la_LIBADD = \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/kernel-consumer/libkernel-consumer.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/common/compat/libcompat.la \
		$(top_builddir)/src/common/relayd/librelayd.la

if HAVE_LIBLTTNG_UST_CTL
libconsumer_la_LIBADD += \
		$(top_builddir)/src/common/ust-consumer/libust-consumer.la
endif
