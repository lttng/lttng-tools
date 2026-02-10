# SPDX-FileCopyrightText: 2012-2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

include $(top_srcdir)/aminclude_static.am

lttnglibexec_PROGRAMS = lttng-consumerd

lttng_consumerd_SOURCES = \
	lttng-consumerd.cpp \
	lttng-consumerd.hpp \
	health-consumerd.cpp \
	health-consumerd.hpp

lttng_consumerd_LDADD = \
	   $(top_builddir)/src/common/libconsumer.la \
	   $(top_builddir)/src/common/libcommon-gpl.la \
	   $(top_builddir)/src/common/libindex.la \
	   $(top_builddir)/src/common/libhealth.la \
	   $(top_builddir)/src/common/libtestpoint.la \
	   $(top_builddir)/src/common/libscheduling.la \
	   $(ATOMIC_LIBS)

lttng_consumerd_LDFLAGS = -rdynamic

if HAVE_LIBLTTNG_UST_CTL
lttng_consumerd_LDADD += $(UST_CTL_LIBS)
endif
