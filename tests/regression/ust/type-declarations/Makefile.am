AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = type-declarations
type_declarations_SOURCES = type-declarations.c ust_tests_td.h
type_declarations_LDADD = -llttng-ust $(DL_LIBS)

noinst_SCRIPTS = test_type_declarations test_type_declarations.py
EXTRA_DIST = test_type_declarations test_type_declarations.py

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
