Tests = \
[
    # lttng-tools unit tests
    {
    'bin': "tools/test_sessions", 'daemon': False, 'kern': False, 'name': "Test sessions",
    'desc': "Test tracing session data structures and methods.",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/test_kernel_data_trace", 'daemon': False, 'kern': False,
    'name': "Kernel data structures",
    'desc': "Test Kernel data structures and methods.",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/test_ust_data_trace", 'daemon': False, 'kern': False,
    'name': "UST data structures",
    'desc': "Test UST data structures and methods.",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/streaming/run-ust", 'daemon': True, 'kern': False,
    'name': "UST network streaming",
    'desc': "Test user space tracing network streaming support",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/streaming/run-kernel", 'daemon': True, 'kern': True,
    'name': "Kernel network streaming",
    'desc': "Test kernel tracing network streaming support",
    'success': 0, 'enabled': True
    },

    # Kernel tests
    {
    'bin': "kernel/run-kernel-tests.sh", 'daemon': True, 'kern': True,
    'name': "Kernel tracer - lttng client",
    'desc': "Test the Kernel tracer using the lttng client",
    'success': 0, 'enabled': True
    },

    # UST tests
    {
    'bin': "ust/run-ust-global-tests.sh", 'daemon': True, 'kern': False,
    'name': "UST tracer - Global domain",
    'desc': "Test the UST tracer functionnalities for domain LTTNG_DOMAIN_UST",
    'success': 0, 'enabled': True
    },
    {
    'bin': "ust/nprocesses/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Multiple processes",
    'desc': "Test multiple process registering and tracing",
    'success': 0, 'enabled': True
    },
    {
    'bin': "ust/high-throughput/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Testing high events throughput",
    'desc': "Test multiple large number of events with concurrent application",
    'success': 0, 'enabled': True
    },
    # Deactivated. This test last 20 minutes...
    #{
    #'bin': "ust/low-throughput/run", 'daemon': True, 'kern': False,
    #'name': "UST tracer - Testing high events throughput",
    #'desc': "Test low throughput of events",
    #'success': 0, 'enabled': False
    #},
    {
    'bin': "ust/before-after/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Tracing before and after app execution",
    'desc': "Test tracing before and after app execution",
    'success': 0, 'enabled': True
    },
    {
    'bin': "ust/multi-session/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Multi-session",
    'desc': "Test tracing with 4 sessions for one application",
    'success': 0, 'enabled': True
    },

    # Tools filtering tests
    {
    'bin': "tools/filtering/unsupported-ops", 'daemon': True, 'kern': False,
    'name': "Filtering - Unsupported operators",
    'desc': "Test the failure of filter with unsupported operators",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/filtering/invalid-filters", 'daemon': True, 'kern': False,
    'name': "Filtering - Invalid filters",
    'desc': "Test the failure of invalid filters",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/filtering/valid-filters", 'daemon': True, 'kern': False,
    'name': "Filtering - Valid filters",
    'desc': "Validate the expected trace output of valid filters",
    'success': 0, 'enabled': True
    },

    # Tools health check tests
    {
    'bin': "tools/health/health_thread_ok", 'daemon': "test", 'kern': True,
    'name': "Health check - Threads OK",
    'desc': "Verify that health check is OK when running lttng-sessiond, lttng-consumerd, and lttng-relayd",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/health/health_thread_exit", 'daemon': "test", 'kern': True,
    'name': "Health check - Thread exit",
    'desc': "Call exit in the various lttng-sessiond, lttng-consumerd, lttng-relayd threads and ensure that health failure is detected",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/health/health_thread_stall", 'daemon': "test", 'kern': True,
    'name': "Health check - Thread stall",
    'desc': "Stall the various lttng-sessiond, lttng-consumerd, lttng-relayd threads and ensure that health failure is detected",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/health/health_tp_fail", 'daemon': "test", 'kern': True,
    'name': "Health check - Testpoint failure",
    'desc': "Trigger a failure in the testpoint mechanism in each thread to provoke thread teardown",
    'success': 0, 'enabled': True
    },

    # Tools streaming tests
    {
    'bin': "tools/streaming/run-kernel", 'daemon': True, 'kern': True,
    'name': "Streaming - Kernel tracing",
    'desc': "Stream a kernel trace across the network",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/streaming/run-ust", 'daemon': True, 'kern': False,
    'name': "Streaming - Userspace tracing",
    'desc': "Stream a userspace trace across the network",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/streaming/uri_switch", 'daemon': True, 'kern': False,
    'name': "Streaming - URI switching",
    'desc': "Switch URI and verify that the trace result are in the proper location",
    'success': 0, 'enabled': True
    },
    {
    'bin': "tools/streaming/high_throughput_limits", 'daemon': True, 'kern': True,
    'name': "Streaming - High throughput with bandwith limits",
    'desc': "Trace streaming with bandwidth limits",
    'success': 0, 'enabled': True
    },
]
