# SPDX-License-Identifier: GPL-2.0-only
SUBDIRS = \
	  gen-kernel-test-events \
	  gen-py-events \
	  gen-syscall-events \
	  gen-ust-events \
	  gen-ust-nevents \
	  gen-ust-nevents-str \
	  gen-ust-tracef \
	  userspace-probe-elf-binary \
	  userspace-probe-elf-cxx-binary \
	  gen-ust-events-constructor

if TEST_SDT_UPROBE
SUBDIRS += userspace-probe-sdt-binary
endif # TEST_SDT_UPROBE

if HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT
SUBDIRS += gen-syscall-events-callstack
endif # HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT

if IS_LINUX
SUBDIRS += \
	  gen-ns-events \
	  gen-ust-events-ns
endif # IS_LINUX

noinst_HEADERS = signal-helper.hpp
