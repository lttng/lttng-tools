AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src \
			  -I$(srcdir) -I$(builddir)

noinst_PROGRAMS = filter-grammar-test
noinst_LTLIBRARIES = libfilter.la
noinst_HEADERS = filter-ast.h \
		filter-symbols.h

BUILT_SOURCES = filter-parser.h
AM_YFLAGS = -t -d -v

libfilter_la_SOURCES = filter-lexer.l filter-parser.y \
	filter-visitor-set-parent.c \
	filter-visitor-xml.c \
	filter-visitor-generate-ir.c \
	filter-visitor-ir-check-binary-op-nesting.c \
	filter-visitor-ir-validate-string.c \
	filter-visitor-generate-bytecode.c \
	filter-ast.h \
	filter-bytecode.h \
	filter-ir.h \
	memstream.h
libfilter_la_CFLAGS = -include filter-symbols.h

filter_grammar_test_SOURCES = filter-grammar-test.c
filter_grammar_test_LDADD = libfilter.la

CLEANFILES = filter-lexer.c filter-parser.c filter-parser.h filter-parser.output
