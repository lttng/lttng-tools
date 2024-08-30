# SPDX-FileCopyrightText: 2023 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir) \
	-I$(top_srcdir)/tests/utils/testapp
LIB_LTTNG_CTL = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-data-pending
gen_data_pending_SOURCES = main.cpp
gen_data_pending_LDADD = $(LIB_LTTNG_CTL) \
	$(top_builddir)/src/vendor/fmt/libfmt.la
endif
