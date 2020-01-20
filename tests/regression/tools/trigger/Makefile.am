noinst_SCRIPTS = test_add_trigger_cli \
	test_list_triggers_cli \
	test_remove_trigger_cli
EXTRA_DIST = test_add_trigger_cli \
	test_list_triggers_cli \
	test_remove_trigger_cli

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
