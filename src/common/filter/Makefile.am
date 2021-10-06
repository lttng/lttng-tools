# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir) -I$(builddir)

noinst_LTLIBRARIES = libfilter.la
noinst_HEADERS = filter-ast.h \
		filter-symbols.h

BUILT_SOURCES = filter-parser.hpp

libfilter_la_SOURCES = \
	filter-lexer.lpp \
	filter-parser.ypp \
	filter-visitor-xml.cpp \
	filter-visitor-generate-ir.cpp \
	filter-visitor-ir-check-binary-op-nesting.cpp \
	filter-visitor-ir-validate-string.cpp \
	filter-visitor-ir-validate-globbing.cpp \
	filter-visitor-ir-normalize-glob-patterns.cpp \
	filter-visitor-generate-bytecode.cpp \
	filter-ast.h \
	filter-ir.h \
	memstream.h
libfilter_la_CXXFLAGS = -include filter-symbols.h $(AM_CXXFLAGS)
libfilter_la_LIBADD = $(top_builddir)/src/common/string-utils/libstring-utils.la

AM_YFLAGS = -t -d -v -Wno-yacc

# start with empty files to clean
CLEANFILES =

if HAVE_BISON
# we have bison: we can clean the generated parser files
CLEANFILES += filter-parser.cpp filter-parser.hpp filter-parser.output
else # HAVE_BISON
# create target used to stop the build if we want to build the parser,
# but we don't have the necessary tool to do so
ERR_MSG = "Error: Cannot build target because bison is missing."
ERR_MSG += "Make sure bison is installed and run the configure script again."

filter-parser.cpp filter-parser.hpp: filter-parser.ypp
	@echo $(ERR_MSG)
	@false

all-local: filter-parser.cpp filter-parser.hpp
endif # HAVE_BISON

if HAVE_FLEX
# we have flex: we can clean the generated lexer files
CLEANFILES += filter-lexer.cpp
else # HAVE_FLEX
# create target used to stop the build if we want to build the lexer,
# but we don't have the necessary tool to do so
ERR_MSG = "Error: Cannot build target because flex is missing."
ERR_MSG += "Make sure flex is installed and run the configure script again."

filter-lexer.cpp: filter-lexer.lpp
	@echo $(ERR_MSG)
	@false

all-local: filter-lexer.cpp
endif # HAVE_FLEX
