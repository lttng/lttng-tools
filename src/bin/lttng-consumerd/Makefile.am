# SPDX-License-Identifier: GPL-2.0-only

lttnglibexec_PROGRAMS = lttng-consumerd

lttng_consumerd_SOURCES = \
	lttng-consumerd.cpp \
	lttng-consumerd.h \
	health-consumerd.cpp \
	health-consumerd.h

lttng_consumerd_LDADD = \
	   $(top_builddir)/src/common/consumer/libconsumer.la \
	   $(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
	   $(top_builddir)/src/common/libcommon.la \
	   $(top_builddir)/src/common/index/libindex.la \
	   $(top_builddir)/src/common/health/libhealth.la \
	   $(top_builddir)/src/common/testpoint/libtestpoint.la

lttng_consumerd_LDFLAGS = -rdynamic

if HAVE_LIBLTTNG_UST_CTL
lttng_consumerd_LDADD += $(UST_CTL_LIBS)
endif
