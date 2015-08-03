AM_CPPFLAGS = -I$(srcdir) -g

noinst_PROGRAMS = prog
prog_SOURCES = prog.c tp.c
prog_LDADD = -llttng-ust

noinst_SCRIPTS = test_baddr-statedump test_baddr-statedump.py
EXTRA_DIST = test_baddr-statedump test_baddr-statedump.py

all-local: prog$(EXEEXT)
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi
	objcopy --only-keep-debug prog prog.debug
	strip -g prog
	objcopy --add-gnu-debuglink prog.debug prog

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
	rm -f prog.debug
