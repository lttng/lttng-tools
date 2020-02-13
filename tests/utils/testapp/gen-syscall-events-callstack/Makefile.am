# SPDX-License-Identifier: GPL-2.0-only

AM_CFLAGS += -I$(top_srcdir)/tests/utils/
AM_CFLAGS += -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
#  The feature called Position Independent Execution (PIE) may be enabled by
#  default on some systems. Supporting this feature for this testapp would
#  increase the complexity of the testcases using this testapp as it would make
#  the addresses of functions unpredictable. So we prevent the linker from
#  using it by using the -no-pie option. If the -no-pie option is not
#  available, we assume that the PIE is not enabled by default so we do not
#  need to disable it.
if LINKER_HAVE_NO_PIE_OPTION
AM_LDFLAGS += -no-pie
endif

noinst_PROGRAMS = gen-syscall-events-callstack
gen_syscall_events_callstack_SOURCES = gen-syscall-events-callstack.c
gen_syscall_events_callstack_LDADD = $(top_builddir)/tests/utils/libtestutils.la
