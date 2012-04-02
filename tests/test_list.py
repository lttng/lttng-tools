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

    #### KERNEL ####
    {
    'bin': "kernel/run-kernel-tests.sh", 'daemon': True, 'kern': True,
    'name': "Kernel tracer - lttng client",
    'desc': "Test the Kernel tracer using the lttng client",
    'success': 0, 'enabled': True
    },

    #### UST ####
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
    'bin': "ust/nevents/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Generate multiple events",
    'desc': "Test multiple events during tracing",
    'success': 0, 'enabled': True
    },
    {
    'bin': "ust/high-throughput/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Testing high events throughput",
    'desc': "Test multiple large number of events with concurrent application",
    'success': 0, 'enabled': True
    },
    {
    'bin': "ust/low-throughput/run", 'daemon': True, 'kern': False,
    'name': "UST tracer - Testing high events throughput",
    'desc': "Test low throughput of events",
    'success': 0, 'enabled': False
    # Deactivated. This test last 20 minutes...
    },
]
