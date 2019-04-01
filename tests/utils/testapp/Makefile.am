SUBDIRS = gen-ust-events \
	  gen-ust-events-ns \
	  gen-ust-nevents \
	  gen-ust-nevents-str \
	  gen-ust-tracef \
	  gen-syscall-events \
	  userspace-probe-elf-binary

if CXX_WORKS
SUBDIRS += userspace-probe-elf-cxx-binary
endif # CXX_WORKS

if SDT_WORKS
SUBDIRS += userspace-probe-sdt-binary
endif # SDT_WORKS

if HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT
SUBDIRS += gen-syscall-events-callstack
endif # HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT

noinst_HEADERS = signal-helper.h
