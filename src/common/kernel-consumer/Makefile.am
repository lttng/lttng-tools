# Kernel consumer library
noinst_LTLIBRARIES = libkernel-consumer.la

libkernel_consumer_la_SOURCES = kernel-consumer.c kernel-consumer.h

libkernel_consumer_la_LIBADD = \
		   $(top_builddir)/src/common/kernel-ctl/libkernel-ctl.la \
		   $(top_builddir)/src/common/relayd/librelayd.la
