objcopy_verbose = $(objcopy_verbose_@AM_V@)
objcopy_verbose_ = $(objcopy_verbose_@AM_DEFAULT_V@)
objcopy_verbose_0 = @echo OBJCOPY $@;

AM_CPPFLAGS += -I$(srcdir) -g

noinst_PROGRAMS = prog
prog_SOURCES = prog.c tp.c tp.h
prog_LDADD = -llttng-ust -ldl

noinst_SCRIPTS = test_baddr-statedump test_baddr-statedump.py
EXTRA_DIST = test_baddr-statedump test_baddr-statedump.py

# Extract debug symbols
prog.debug: prog
	$(objcopy_verbose)$(OBJCOPY) --only-keep-debug prog prog.debug

# Strip and add debuglink
prog.strip: prog.debug
	@cp -f prog prog.strip
	$(objcopy_verbose)$(OBJCOPY) --strip-debug --add-gnu-debuglink=prog.debug prog.strip

all-local: prog.strip
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

CLEANFILES = prog.debug prog.strip
