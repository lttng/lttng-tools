# SPDX-License-Identifier: GPL-2.0-only

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
	   $(top_builddir)/src/vendor/fmt/libfmt.la

lttng_consumerd_LDFLAGS = -rdynamic

if HAVE_LIBLTTNG_UST_CTL
lttng_consumerd_LDADD += $(UST_CTL_LIBS)
endif
