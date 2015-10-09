# Remote relayd test environment configuration

# When set enable the remote test suite
# Otherwise the check-remote target will be executed locally via bash
export REMOTE_RELAYD_TEST="true" # Set to any value to enable


# SSH configuration
# Hostname or IP address
export REMOTE_RELAYD_HOST="localhost"

# Remote user
export REMOTE_RELAYD_USER="$(whoami)"

# Full path of identity file (optional)
export REMOTE_RELAYD_IDENDITY_FILE="/home/$(whoami)/.ssh/id_rsa"


# Remote path configuration
# Path to the folder containing the relayd bin
export REMOTE_RELAYD_PATH=""

# Actual bin name
export REMOTE_RELAYD_BIN="lttng-relayd"

# Path to the folder containing the babeltrace bin
export REMOTE_BABELTRACE_PATH=""

# Actual bin name
export REMOTE_BABELTRACE_BIN="babeltrace"

# Network interface configuration
# Must be set when doing Kernel testing
# The interface to be throttled.
export REMOTE_NETWORK_INTERFACE="eth0"
