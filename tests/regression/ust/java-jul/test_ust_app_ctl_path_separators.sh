#!/bin/bash
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

TEST_DESC="Verifies the behaviour of the sessiond and Java JUL agents with multiple LTTNG_UST_APP_PATHs and multiple LTTNG_UST_CTL_PATHS"
NUM_TESTS=10

CURDIR="$(dirname "${0}")"
TESTDIR="${CURDIR}/../../../"

# shellcheck source=../../../utils/utils.sh
source "${TESTDIR}/utils/utils.sh"

SESSION_NAME="ust-app-ctl-path-separator"
CHANNEL_NAME="ust-app-ctl-path-separator"

TESTAPP_JAVA_JUL="JTestLTTng"
EVENT_NAMES_JAVA_JUL="JTestLTTng"
JAVA_JUL_CP="${CURDIR}:${CLASSPATH}"

function test_app_path_with_separators_java_jul
{
	CTL_PATH="$(mktemp -d -t "tmp.${FUNCNAME[0]}.ctl.XXXXXX")"
	CTL_PATH2="$(mktemp -d -t "tmp.${FUNCNAME[0]}.ctl2.XXXXXX")"
	TRACE_PATH="$(mktemp -d -t "tmp.${FUNCNAME[0]}.trace.XXXXXX")"

	env_vars=(
		LTTNG_UST_CTL_PATH="${CTL_PATH}:${CTL_PATH2}"
	)
	# shellcheck disable=SC2119
	LTTNG_SESSIOND_ENV_VARS="${env_vars[*]}" start_lttng_sessiond

	create_lttng_session_ok "${SESSION_NAME}" "${TRACE_PATH}"
	enable_ust_lttng_channel_ok "${SESSION_NAME}" "${CHANNEL_NAME}"
	enable_jul_lttng_event "${SESSION_NAME}" "${EVENT_NAMES_JAVA_JUL}" "${CHANNEL_NAME}"
	start_lttng_tracing_ok "${SESSION_NAME}"

	# Run app
	pushd "${TESTAPP_JAVA_JUL_DIR}"
	LTTNG_UST_APP_PATH="${CTL_PATH}:${CTL_PATH2}" java -cp "${JAVA_JUL_CP}" -Djava.library.path="${LD_LIBRARY_PATH}:/usr/local/lib:/usr/lib:/usr/local/lib64/:/usr/lib64/" "${TESTAPP_JAVA_JUL}" 100 0
	popd

	stop_lttng_tracing_ok "${SESSION_NAME}"
	destroy_lttng_session_ok "${SESSION_NAME}" --no-wait

	validate_trace_count "lttng_jul:event" "${TRACE_PATH}" 100 0

	# shellcheck disable=SC2119
	stop_lttng_sessiond

	# Cleanup
	rm -rf "${CTL_PATH}" "${CTL_PATH2}" "${TRACE_PATH}"
}

plan_tests "${NUM_TESTS}"
print_test_banner "${TEST_DESC}"
bail_out_if_no_babeltrace
test_app_path_with_separators_java_jul
