AM_CPPFLAGS =

SUBDIRS = hashtable kernel-ctl sessiond-comm kernel-consumer ust-consumer

AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = runas.c runas.h

# Consumer library
noinst_LTLIBRARIES += libconsumer.la

libconsumer_la_SOURCES = consumer.c

libconsumer_la_LIBADD = \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/kernel-consumer/libkernel-consumer.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la

if HAVE_LIBLTTNG_UST_CTL
libconsumer_la_LIBADD += \
		$(top_builddir)/src/common/ust-consumer/libust-consumer.la
endif
