AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

SUBDIRS = compat health hashtable kernel-ctl sessiond-comm relayd \
		  kernel-consumer ust-consumer testpoint index config

AM_CFLAGS = -fno-strict-aliasing

noinst_HEADERS = lttng-kernel.h defaults.h macros.h error.h futex.h \
				 uri.h utils.h lttng-kernel-old.h \
				 consumer-metadata-cache.h consumer-timer.h \
				 consumer-testpoint.h

# Common library
noinst_LTLIBRARIES = libcommon.la
EXTRA_DIST = mi_lttng.xsd

libcommon_la_SOURCES = error.h error.c utils.c utils.h runas.c runas.h \
                       common.h futex.c futex.h uri.c uri.h defaults.c \
                       pipe.c pipe.h readwrite.c readwrite.h \
                       mi-lttng.h mi-lttng.c \
                       daemonize.c daemonize.h
libcommon_la_LIBADD = \
		-luuid \
		-lrt \
		$(top_builddir)/src/common/config/libconfig.la

# Consumer library
noinst_LTLIBRARIES += libconsumer.la

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
