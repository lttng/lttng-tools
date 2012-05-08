AM_CPPFLAGS =

SUBDIRS = compat hashtable kernel-ctl sessiond-comm kernel-consumer ust-consumer

AM_CFLAGS = -fno-strict-aliasing

noinst_HEADERS = lttng-kernel.h defaults.h macros.h error.h futex.h

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = runas.c runas.h common.h futex.c futex.h

# Consumer library
noinst_LTLIBRARIES += libconsumer.la

libconsumer_la_SOURCES = consumer.c consumer.h

libconsumer_la_LIBADD = \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/kernel-consumer/libkernel-consumer.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la \
		$(top_builddir)/src/common/compat/libcompat.la

if HAVE_LIBLTTNG_UST_CTL
libconsumer_la_LIBADD += \
		$(top_builddir)/src/common/ust-consumer/libust-consumer.la
endif
