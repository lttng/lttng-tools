# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
#
## SPDX-License-Identifier: GPL-2.0-only
##
## These targets generate two include files:
##
##   - "version-git.i" holds the GIT_VERSION define ("git describe
##     --tags --dirty" output) which flips every time the working tree
##     becomes dirty or clean. Only "version-git.cpp" includes this file
##     so that a single translation unit recompiles on change.
##
##   - "version.i" holds the EXTRA_VERSION_* defines which rarely
##     change. It is included by "version.hpp" and consumed wherever
##     the extra version info is needed.
##
## Both files are regenerated on every make (via .PHONY) but the final
## "mv" only happens when their content actually changes, so dependent
## TUs aren't invalidated unless the value they embed has moved.
##
## Both files are shipped in the dist tarball so that release builds
## without a ".git" directory still have valid values. The inline
## scripts fall back to parsing the shipped file when git isn't
## available.
##
version_verbose = $(version_verbose_@AM_V@)
version_verbose_ = $(version_verbose_@AM_DEFAULT_V@)
version_verbose_0 = @echo "  GEN       " $@;

version-git.i:
	$(version_verbose)rm -f version-git.i.tmp; \
	if (test ! -f version-git.i && test -f "$(top_srcdir)/include/version-git.i"); then \
		cp "$(top_srcdir)/include/version-git.i" version-git.i; \
	fi; \
	if (test -r "$(top_srcdir)/bootstrap" && test -r "$(top_srcdir)/.git") && \
			test -x "`which git 2>&1;true`"; then \
		GIT_VERSION_STR="`cd "$(top_srcdir)" && git describe --tags --dirty`"; \
		GIT_CURRENT_TAG="`cd "$(top_srcdir)" && git describe --tags --exact-match --match="v[0-9]*" HEAD 2> /dev/null`"; \
		echo "#define GIT_VERSION \"$$GIT_VERSION_STR\"" > version-git.i.tmp; \
		if ! $(GREP) -- "-dirty" version-git.i.tmp > /dev/null && \
				test "x$$GIT_CURRENT_TAG" != "x"; then \
			echo "#define GIT_VERSION \"\"" > version-git.i.tmp; \
		fi; \
	fi; \
	if test ! -f version-git.i.tmp; then \
		if test -f version-git.i; then \
			$(GREP) "^#define \bGIT_VERSION\b.*" version-git.i > version-git.i.tmp; \
		else \
			echo '#define GIT_VERSION ""' > version-git.i.tmp; \
		fi; \
	fi; \
	if test ! -f version-git.i || \
			test x"`cat version-git.i.tmp`" != x"`cat version-git.i`"; then \
		mv version-git.i.tmp version-git.i; \
	fi; \
	rm -f version-git.i.tmp; \
	true

version.i:
	$(version_verbose)rm -f version.i.tmp; \
	if (test ! -f version.i && test -f "$(top_srcdir)/include/version.i"); then \
		cp "$(top_srcdir)/include/version.i" version.i; \
	fi; \
	echo "#define EXTRA_VERSION_NAME \"`$(SED) -n '1p' "$(top_srcdir)/version/extra_version_name" 2> /dev/null`\"" > version.i.tmp; \
	echo "#define EXTRA_VERSION_DESCRIPTION \"`$(SED) -E ':a ; N ; $$!ba ; s/[^a-zA-Z0-9 \n\t\.,]/-/g ; s/\r{0,1}\n/\\\n\\\t/g' "$(top_srcdir)/version/extra_version_description" 2> /dev/null`\"" >> version.i.tmp; \
	echo "#define EXTRA_VERSION_PATCHES \"`ls -1 "$(top_srcdir)/version/extra_patches" | $(GREP) -v '^README' | $(SED) -E ':a ; N ; $$!ba ; s/[^a-zA-Z0-9 \n\t\.]/-/g ; s/\r{0,1}\n/\\\n\\\t/g' 2> /dev/null`\"" >> version.i.tmp; \
	if test ! -f version.i || \
			test x"`cat version.i.tmp`" != x"`cat version.i`"; then \
		mv version.i.tmp version.i; \
	fi; \
	rm -f version.i.tmp; \
	true

##
## version.i and version-git.i are defined as .PHONY targets even if
## they are real files: we want the targets to be re-run on every make.
##
.PHONY: version.i version-git.i

CLEANFILES = version.i.tmp version-git.i.tmp

##
## Only clean the generated files on dist-clean; we need to keep them on
## regular clean when they are part of a dist tarball.
##
DISTCLEANFILES = version.i version-git.i

lttnginclude_HEADERS = \
	lttng/channel.h \
	lttng/clear-handle.h \
	lttng/clear.h \
	lttng/constant.h \
	lttng/destruction-handle.h \
	lttng/domain.h \
	lttng/endpoint.h \
	lttng/error-query.h \
	lttng/event-expr.h \
	lttng/event-field-value.h \
	lttng/event.h \
	lttng/handle.h \
	lttng/health.h \
	lttng/kernel.h \
	lttng/kernel-probe.h \
	lttng/load.h \
	lttng/location.h \
	lttng/log-level-rule.h \
	lttng/lttng-error.h \
	lttng/lttng-export.h \
	lttng/lttng.h \
	lttng/reclaim.h \
	lttng/rotation.h \
	lttng/save.h \
	lttng/session-descriptor.h \
	lttng/session.h \
	lttng/snapshot.h \
	lttng/stream-info.h \
	lttng/tracker.h \
	lttng/userspace-probe.h

lttngactioninclude_HEADERS= \
	lttng/action/action.h \
	lttng/action/list.h \
	lttng/action/notify.h \
	lttng/action/path.h \
	lttng/action/rotate-session.h \
	lttng/action/snapshot-session.h \
	lttng/action/start-session.h \
	lttng/action/stop-session.h \
	lttng/action/rate-policy.h

lttngconditioninclude_HEADERS= \
	lttng/condition/condition.h \
	lttng/condition/buffer-usage.h \
	lttng/condition/event-rule-matches.h \
	lttng/condition/session-consumed-size.h \
	lttng/condition/session-rotation.h \
	lttng/condition/evaluation.h

lttngnotificationinclude_HEADERS= \
	lttng/notification/channel.h \
	lttng/notification/notification.h

lttngtriggerinclude_HEADERS= \
	lttng/trigger/trigger.h

lttngeventruleinclude_HEADERS= \
	lttng/event-rule/event-rule.h \
	lttng/event-rule/jul-logging.h \
	lttng/event-rule/kernel-kprobe.h \
	lttng/event-rule/kernel-syscall.h \
	lttng/event-rule/kernel-tracepoint.h \
	lttng/event-rule/kernel-uprobe.h \
	lttng/event-rule/log4j-logging.h \
	lttng/event-rule/log4j2-logging.h \
	lttng/event-rule/python-logging.h \
	lttng/event-rule/user-tracepoint.h

noinst_HEADERS = \
	lttng/action/action-internal.hpp \
	lttng/action/list-internal.hpp \
	lttng/action/notify-internal.hpp \
	lttng/action/path-internal.hpp \
	lttng/action/rotate-session-internal.hpp \
	lttng/action/snapshot-session-internal.hpp \
	lttng/action/start-session-internal.hpp \
	lttng/action/stop-session-internal.hpp \
	lttng/action/rate-policy-internal.hpp \
	lttng/channel-internal.hpp \
	lttng/condition/buffer-usage-internal.hpp \
	lttng/condition/condition-internal.hpp \
	lttng/condition/evaluation-internal.hpp \
	lttng/condition/event-rule-matches-internal.hpp \
	lttng/condition/session-consumed-size-internal.hpp \
	lttng/condition/session-rotation-internal.hpp \
	lttng/domain-internal.hpp \
	lttng/endpoint-internal.hpp \
	lttng/error-query-internal.hpp \
	lttng/event-expr-internal.hpp \
	lttng/event-field-value-internal.hpp \
	lttng/event-internal.hpp \
	lttng/event-rule/event-rule-internal.hpp \
	lttng/event-rule/jul-logging-internal.hpp \
	lttng/event-rule/kernel-kprobe-internal.hpp \
	lttng/event-rule/kernel-syscall-internal.hpp \
	lttng/event-rule/kernel-tracepoint-internal.hpp \
	lttng/event-rule/kernel-uprobe-internal.hpp \
	lttng/event-rule/log4j-logging-internal.hpp \
	lttng/event-rule/log4j2-logging-internal.hpp \
	lttng/event-rule/python-logging-internal.hpp \
	lttng/event-rule/user-tracepoint-internal.hpp \
	lttng/health-internal.hpp \
	lttng/kernel-probe-internal.hpp \
	lttng/load-internal.hpp \
	lttng/location-internal.hpp \
	lttng/log-level-rule-internal.hpp \
	lttng/notification/channel-internal.hpp \
	lttng/notification/notification-internal.hpp \
	lttng/reclaim-internal.hpp \
	lttng/ref-internal.hpp \
	lttng/rotate-internal.hpp \
	lttng/save-internal.hpp \
	lttng/session-descriptor-internal.hpp \
	lttng/session-internal.hpp \
	lttng/snapshot-internal.hpp \
	lttng/trigger/trigger-internal.hpp \
	lttng/userspace-probe-internal.hpp \
	version.hpp \
	version.i \
	version-git.hpp \
	version-git.i
