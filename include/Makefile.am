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
	echo "#define EXTRA_VERSION_PATCHES \"`ls --ignore='README' -1 "$(top_srcdir)/version/extra_patches" | $(SED) -E ':a ; N ; $$!ba ; s/[^a-zA-Z0-9 \n\t\.]/-/g ; s/\r{0,1}\n/\\\n\\\t/g' 2> /dev/null`\"" >> version.i.tmp; \
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
	lttng/health.h \
	lttng/lttng.h \
	lttng/constant.h \
	lttng/channel.h \
	lttng/domain.h \
	lttng/event.h \
	lttng/handle.h \
	lttng/session.h \
	lttng/lttng-error.h \
	lttng/snapshot.h \
	lttng/save.h \
	lttng/load.h \
	lttng/endpoint.h \
	lttng/rotation.h \
	lttng/location.h \
	lttng/userspace-probe.h \
	lttng/session-descriptor.h \
	lttng/destruction-handle.h \
	lttng/clear.h \
	lttng/clear-handle.h \
	lttng/tracker.h

lttngactioninclude_HEADERS= \
	lttng/action/action.h \
	lttng/action/notify.h

lttngconditioninclude_HEADERS= \
	lttng/condition/condition.h \
	lttng/condition/buffer-usage.h \
	lttng/condition/session-consumed-size.h \
	lttng/condition/session-rotation.h \
	lttng/condition/evaluation.h

lttngnotificationinclude_HEADERS= \
	lttng/notification/channel.h \
	lttng/notification/notification.h

lttngtriggerinclude_HEADERS= \
	lttng/trigger/trigger.h

noinst_HEADERS = \
	lttng/snapshot-internal.h \
	lttng/health-internal.h \
	lttng/save-internal.h \
	lttng/load-internal.h \
	lttng/action/action-internal.h \
	lttng/action/notify-internal.h \
	lttng/condition/condition-internal.h \
	lttng/condition/buffer-usage-internal.h \
	lttng/condition/session-consumed-size-internal.h \
	lttng/condition/evaluation-internal.h \
	lttng/condition/session-rotation-internal.h \
	lttng/notification/notification-internal.h \
	lttng/trigger/trigger-internal.h \
	lttng/endpoint-internal.h \
	lttng/notification/channel-internal.h \
	lttng/channel-internal.h \
	lttng/event-internal.h \
	lttng/rotate-internal.h \
	lttng/ref-internal.h \
	lttng/location-internal.h \
	lttng/userspace-probe-internal.h \
	lttng/session-internal.h \
	lttng/session-descriptor-internal.h \
	version.h \
	version.i
