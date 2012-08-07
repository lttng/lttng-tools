lib_LTLIBRARIES = liblttng-ctl.la
noinst_PROGRAMS = filter-grammar-test

BUILT_SOURCES = filter-parser.h
AM_YFLAGS = -t -d -v

noinst_HEADERS = filter-ast.h
liblttng_ctl_la_SOURCES = lttng-ctl.c \
	filter-lexer.l filter-parser.y \
	filter-visitor-set-parent.c \
	filter-visitor-xml.c \
	filter-visitor-generate-ir.c \
	filter-visitor-ir-check-binary-op-nesting.c \
	filter-visitor-generate-bytecode.c \
	align.h \
	bug.h \
	filter-ast.h \
	filter-bytecode.h \
	filter-ir.h \
	memstream.h

filter_grammar_test_SOURCES = filter-grammar-test.c
filter_grammar_test_LDADD = liblttng-ctl.la

liblttng_ctl_la_LIBADD = \
		$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
		$(top_builddir)/src/common/libcommon.la \
		$(top_builddir)/src/common/hashtable/libhashtable.la
