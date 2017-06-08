AM_CFLAGS += -I$(top_srcdir)/tests/utils/
AM_CFLAGS += -fno-omit-frame-pointer -no-pie

noinst_PROGRAMS = gen-syscall-events-callstack
gen_syscall_events_callstack_SOURCES = gen-syscall-events-callstack.c
gen_syscall_events_callstack_LDADD = $(top_builddir)/tests/utils/libtestutils.la
