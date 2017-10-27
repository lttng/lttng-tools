if LTTNG_TOOLS_BUILD_GIT_SOURCE
GIT_DESCRIBE_CMD = (cd $(top_srcdir); git describe)
else
GIT_DESCRIBE_CMD = /bin/true
endif

##
## The version.h file must be verified and generated or updated if the
## git commit id (called git version here) changed since the last build
## of lttng-tools.
##
version.h:
	##
	## We first create variables for the current git version and
	## the locations of the version.h and version.h.tmpl files.
	##
	@echo $(ECHO_N) "Generating version.h... $(ECHO_C)"
	@(version_h_tmpl="$(top_srcdir)/include/version.h.tmpl"; \
	if [ -f "$${version_h_tmpl}" ]; then \
		version_h="$(top_builddir)/include/version.h"; \
		##
		## Check whether we are in a git repo.
		##
		git_describe="`$(GIT_DESCRIBE_CMD) 2>/dev/null`"; \
		if [ $$? -eq 0 ]; then \
			git_version="$${git_describe}"; \
		else \
			git_version=""; \
		fi; \
		##
		## If the version.h file doesn't exist or is not up to date,
		## We replace it by the version.h.tmpl file.
		##
		if [ ! -e "$${version_h}" ] || \
			[ "$${version_h_tmpl}" -nt "$${version_h}" ]; then \
			cp "$${version_h_tmpl}" "$${version_h}"; \
		fi; \
		echo $(ECHO_N) "git version: \"$${git_version}\"$(ECHO_C)"; \
		##
		## We verify that git_version isn't the same as the one
		## currently in the file (if there is one), as we don't
		## want to update the file if it is already up to date.
		##
		version_match='^#define GIT_VERSION.*'; \
		old_version=$$($(GREP) "$${version_match}" "$${version_h}"); \
		new_version="#define GIT_VERSION	\"$${git_version}\""; \
		if [ x"$${old_version}" != x"$${new_version}" ]; then \
			$(SED) -i -e "s'$${version_match}'$${new_version}'" "$${version_h}"; \
		else \
			echo $(ECHO_N) " (cached)$(ECHO_C)"; \
		fi; \
		echo $(ECHO_N) "... $(ECHO_C)"; \
	fi)
	@echo "$(ECHO_T)ok"

##
## version.h is defined as a .PHONY file even if it's a real file as
## we want our routine to be ran for each build.
##
.PHONY: version.h

CLEANFILES = version.h

nodist_noinst_HEADERS = \
	version.h

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
	version.h.tmpl

lttngactioninclude_HEADERS= \
	lttng/action/action.h \
	lttng/action/notify.h

lttngconditioninclude_HEADERS= \
	lttng/condition/condition.h \
	lttng/condition/buffer-usage.h \
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
	lttng/condition/evaluation-internal.h \
	lttng/notification/notification-internal.h \
	lttng/trigger/trigger-internal.h \
	lttng/endpoint-internal.h \
	lttng/notification/channel-internal.h \
	lttng/channel-internal.h
