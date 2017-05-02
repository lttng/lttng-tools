AM_CPPFLAGS += -I$(srcdir) -I$(builddir)

noinst_PROGRAMS = filter-grammar-test
noinst_LTLIBRARIES = libfilter.la
noinst_HEADERS = filter-ast.h \
		filter-symbols.h

BUILT_SOURCES = filter-parser.h

libfilter_la_SOURCES = \
	filter-parser.y filter-lexer.l \
	filter-visitor-set-parent.c \
	filter-visitor-xml.c \
	filter-visitor-generate-ir.c \
	filter-visitor-ir-check-binary-op-nesting.c \
	filter-visitor-ir-validate-string.c \
	filter-visitor-ir-validate-globbing.c \
	filter-visitor-ir-normalize-glob-patterns.c \
	filter-visitor-generate-bytecode.c \
	filter-ast.h \
	filter-bytecode.h \
	filter-ir.h \
	memstream.h
libfilter_la_CFLAGS = -include filter-symbols.h $(AM_CFLAGS)
libfilter_la_LIBADD = $(top_builddir)/src/common/string-utils/libstring-utils.la

AM_YFLAGS = -t -d -v

# start with empty files to clean
CLEANFILES =

if HAVE_BISON
# we have bison: we can clean the generated parser files
CLEANFILES += filter-parser.c filter-parser.h filter-parser.output
else # HAVE_BISON
# create target used to stop the build if we want to build the parser,
# but we don't have the necessary tool to do so
ERR_MSG = "Error: Cannot build target because bison is missing."
ERR_MSG += "Make sure bison is installed and run the configure script again."

filter-parser.c filter-parser.h: filter-parser.y
	@echo $(ERR_MSG)
	@false

all-local: filter-parser.c filter-parser.h
endif # HAVE_BISON

if HAVE_FLEX
# we have flex: we can clean the generated lexer files
CLEANFILES += filter-lexer.c
else # HAVE_FLEX
# create target used to stop the build if we want to build the lexer,
# but we don't have the necessary tool to do so
ERR_MSG = "Error: Cannot build target because flex is missing."
ERR_MSG += "Make sure flex is installed and run the configure script again."

filter-lexer.c: filter-lexer.l
	@echo $(ERR_MSG)
	@false

all-local: filter-lexer.c
endif # HAVE_FLEX

filter_grammar_test_SOURCES = filter-grammar-test.c
filter_grammar_test_LDADD = libfilter.la
