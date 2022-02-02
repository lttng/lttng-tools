## SPDX-License-Identifier: GPL-2.0-only
##
## This target generates an include file that contains the git version
## string of the current branch, it must be continuously updated when
## we build in the git repo and shipped in dist tarballs to reflect the
## status of the tree when it was generated. If the tree is clean and
## the current commit is tag a starting with "v", consider this a
## release version and set an empty git version.
##
## Here is what the inline script does:
##
## First, delete any stale "version.i.tmp" file.
##
## If "bootstrap" and ".git" exists in the top source directory and the git
## executable is available, get the current git version string in the form:
##
##  "latest_tag"(-"number_of_commits_on_top")(-g"latest_commit_hash")(-dirty)
##
## And store it in "version.i.tmp", if the current commit is tagged, the tag
## starts with "v" and the tree is clean, consider this a release version and
## overwrite the git version with an empty string in "version.i.tmp".
##
## If we don't have a "version.i.tmp" nor a "version.i", generate an empty
## string as a failover. If a "version.i" is present, for example when building
## from a distribution tarball, get the git_version using grep.
##
## Fetch the EXTRA_VERSION_NAME define from "version/extra_version_name" and output it
## to "version.i.tmp".
##
## Fetch the EXTRA_VERSION_DESCRIPTION define from "version/extra_version_description",
## sanitize and format it with a sed script to replace all non-alpha-numeric values
## with "-" and join all lines by replacing "\n" with litteral string c-style "\n\t" and
## output it to "version.i.tmp".
##
## Repeat the same logic for the "version/extra_patches" directory.
## Data fetched from "version/extra_patches" must be sanitized and
## formatted.
## The data is fetched using "ls" with an ignore pattern for the README file.
## The sanitize step uses sed with a script to replace all
## non-alpha-numeric values, except " " (space), to "-".
## The formatting step uses sed with a script to join all lines
## by replacing "\n" with litteral string c-style "\n\t".
##
## If we don't have a "version.i" or we have both files (version.i, version.i.tmp)
## and they are different, copy "version.i.tmp" over "version.i".
## This way the dependent targets are only rebuilt when the git version
## string or either one of extra version string change.
##
version_verbose = $(version_verbose_@AM_V@)
version_verbose_ = $(version_verbose_@AM_DEFAULT_V@)
version_verbose_0 = @echo "  GEN       " $@;

version.i:
	$(version_verbose)rm -f version.i.tmp; \
	if (test ! -f version.i && test -f "$(top_srcdir)/include/version.i"); then \
		cp "$(top_srcdir)/include/version.i" version.i; \
	fi; \
	if (test -r "$(top_srcdir)/bootstrap" && test -r "$(top_srcdir)/.git") && \
			test -x "`which git 2>&1;true`"; then \
		GIT_VERSION_STR="`cd "$(top_srcdir)" && git describe --tags --dirty`"; \
		GIT_CURRENT_TAG="`cd "$(top_srcdir)" && git describe --tags --exact-match --match="v[0-9]*" HEAD 2> /dev/null`"; \
		echo "#define GIT_VERSION \"$$GIT_VERSION_STR\"" > version.i.tmp; \
		if ! $(GREP) -- "-dirty" version.i.tmp > /dev/null && \
				test "x$$GIT_CURRENT_TAG" != "x"; then \
			echo "#define GIT_VERSION \"\"" > version.i.tmp; \
		fi; \
	fi; \
	if test ! -f version.i.tmp; then \
		if test -f version.i; then \
			$(GREP) "^#define \bGIT_VERSION\b.*" version.i > version.i.tmp; \
		else \
			echo '#define GIT_VERSION ""' > version.i.tmp; \
		fi; \
	fi; \
	echo "#define EXTRA_VERSION_NAME \"`$(SED) -n '1p' "$(top_srcdir)/version/extra_version_name" 2> /dev/null`\"" >> version.i.tmp; \
	echo "#define EXTRA_VERSION_DESCRIPTION \"`$(SED) -E ':a ; N ; $$!ba ; s/[^a-zA-Z0-9 \n\t\.,]/-/g ; s/\r{0,1}\n/\\\n\\\t/g' "$(top_srcdir)/version/extra_version_description" 2> /dev/null`\"" >> version.i.tmp; \
	echo "#define EXTRA_VERSION_PATCHES \"`ls -1 "$(top_srcdir)/version/extra_patches" | $(GREP) -v '^README' | $(SED) -E ':a ; N ; $$!ba ; s/[^a-zA-Z0-9 \n\t\.]/-/g ; s/\r{0,1}\n/\\\n\\\t/g' 2> /dev/null`\"" >> version.i.tmp; \
	if test ! -f version.i || \
			test x"`cat version.i.tmp`" != x"`cat version.i`"; then \
		mv version.i.tmp version.i; \
	fi; \
	rm -f version.i.tmp; \
	true

##
## version.i is defined as a .PHONY target even if it's a real file,
## we want the target to be re-run on every make.
##
.PHONY: version.i

CLEANFILES = version.i.tmp

##
## Only clean "version.i" on dist-clean, we need to keep it on regular
## clean when it's part of a dist tarball.
##
DISTCLEANFILES = version.i

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
	lttng/rotation.h \
	lttng/save.h \
	lttng/session-descriptor.h \
	lttng/session.h \
	lttng/snapshot.h \
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
	lttng/ref-internal.hpp \
	lttng/rotate-internal.hpp \
	lttng/save-internal.hpp \
	lttng/session-descriptor-internal.hpp \
	lttng/session-internal.hpp \
	lttng/snapshot-internal.hpp \
	lttng/trigger/trigger-internal.hpp \
	lttng/userspace-probe-internal.hpp \
	version.hpp \
	version.i
