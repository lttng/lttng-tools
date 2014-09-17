STREAMING
----------------

[Last updated: 2012-07-17 by David Goulet]

This is a brief howto for network streaming feature of lttng 2.0 toolchain.

See the README.md file for installation procedure or use the various Linux
distribution packages.

Terminology:

	* The "target" is the traced machine (either UST or/and kernel tracer)

	* The "remote" is the machine that receives the traces over network
	streaming transport layer.

Basics:

Here are the basic concepts of the new streaming component. We use two network
ports for that called _control_ and _data_ respectively defined by default to
5342 and 5343.

The control port is where the commands AND metadata data are sent since this
stream is considered to be the reliable and priority transport channel. The
data port is the stream which transports the tracing raw data.

In order to gather traces from the network, the remote machine MUST have a
lttng-relayd running on it bound to network interfaces remotely reachable by the
target.

[remote] $ lttng-relayd -d
(to daemonize)

[remote] $ lttng-relayd -vvv
(foreground with debug output)

[remote] $ lttng-relayd -C tcp://0.0.0.0:1234 -D tcp://0.0.0.0:5678
(control port set to TCP/1234 and data port to TCP/5678 on all IP addresses)

For now, only TCP is supported on IPv4/IPv6.

Once done, the following examples shows you how to start streaming from the
target machine to the remote host where we just started a lttng relay.

Example 1:
----------------

Simple and quick network streaming.

1) Create a tracing session that will be streamed over the network for the
specified domain. This session will contain, in our example, syscall events.

  # lttng create syscall-session

2) Enable the consumer to send data over the network for the kernel domain.

  # lttng enable-consumer --kernel net://<remote_addr>

  You can also skip this step and directly use the lttng create command like so:

  # lttng create -U net://<remote_addr> syscall-session

3) Set and start the tracing. Nothing new here.

  # lttng enable-event -a --syscall -k
  # lttng start
  (wait and get coffee)
  # lttng stop

By default on the relay side, the trace will be written to the lttng-traces/
directory of the relayd user in:

  hostname/session-name/kernel/*

The -o option of lttng-relayd allows the user to override the default output
path.

Just run babeltrace or lttng view -t PATH with the previous path.

Example 2:
----------------

This example uses all possible options to fine grained control the streaming.

1) Again, create a tracing session that will be streamed over the network for
the specified domain.

  # lttng create syscall-session

2) Set relayd URIs for the tracing session and kernel domain.

ONLY set the remote relayd URIs (both control and data at the same destination
and using default ports) on the consumer but does not enable the consumer to use
network streaming yet.

  # lttng enable-consumer -k -U net://<remote_addr>

You can also set both control and data URIs using -C and -D respectively for
that like so:

  # lttng enable-consumer -k -C tcp://<remote_addr> -D tcp://<remote_addr>

3) Enable the consumer previously setup with the relayd URIs.

This enables the previous network destination. From this point on, the consumer
is ready to stream once tracing is started.

  # lttng enable-consumer -k --enable

4) Set and start the tracing. Nothing new here.

  # lttng enable-event -a --syscall -k
  # lttng start
  (wait and get coffee)
  # lttng stop

Again, run babeltrace as mentioned in the previous example on the relayd side.

For more information, please read the --help options of each command or the man
pages lttng(1) and the lttng-relayd(8)
