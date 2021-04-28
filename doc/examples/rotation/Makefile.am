# SPDX-License-Identifier: GPL-2.0-only

LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

noinst_PROGRAMS = rotate-client
dist_noinst_SCRIPTS = rotate-client-compress.sh

rotate_client_SOURCES = rotate-client-example.c
rotate_client_LDADD = $(LIBLTTNG_CTL)
