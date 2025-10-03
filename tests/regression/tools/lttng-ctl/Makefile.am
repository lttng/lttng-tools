# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>

if NO_SHARED
else
if HAVE_LIBLTTNG_UST_CTL

noinst_LTLIBRARIES += liblttng-ust-ctl-fuzz.la

noinst_SCRIPTS += \
	lttng-ctl/test_liblttng-ctl_abi.py \
	lttng-ctl/test_robust_protocol.py

liblttng_ust_ctl_fuzz_la_SOURCES = \
	lttng-ctl/liblttng-ust-ctl-fuzz.cpp

liblttng_ust_ctl_fuzz_la_CPPFLAGS = \
	$(UST_CTL_CPPFLAGS) \
	$(AM_CPPFLAGS)

# The fuzzing library needs to be LD_PRELOADed by the daemons. Force it to be shared.
liblttng_ust_ctl_fuzz_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)
endif # HAVE_LIBLTTNG_UST_CTL
endif # NO_SHARED
