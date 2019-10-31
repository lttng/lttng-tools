SUBDIRS = gen-ust-events \
	  gen-ust-nevents \
	  gen-ust-nevents-str \
	  gen-ust-tracef \
	  gen-syscall-events \
	  userspace-probe-elf-binary

if CXX_WORKS
SUBDIRS += userspace-probe-elf-cxx-binary
endif # CXX_WORKS

if TEST_SDT_UPROBE
SUBDIRS += userspace-probe-sdt-binary
endif # TEST_SDT_UPROBE

if HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT
SUBDIRS += gen-syscall-events-callstack
endif # HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT

noinst_HEADERS = signal-helper.h
