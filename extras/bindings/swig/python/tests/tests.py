import unittest
import os
import time
from lttng import *

class TestLttngPythonModule (unittest.TestCase):

	def test_kernel_all_events(self):
		dom = Domain()
		dom.type = DOMAIN_KERNEL

		event = Event()
		event.type = EVENT_TRACEPOINT
		event.loglevel_type = EVENT_LOGLEVEL_ALL

		han = Handle("test_kernel_all_ev", dom)

		r = create("test_kernel_all_ev","/lttng-traces/test")
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, event, None)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = start("test_kernel_all_ev")
		self.assertGreaterEqual(r, 0, strerror(r))
		time.sleep(2)

		r = stop("test_kernel_all_ev")
		self.assertGreaterEqual(r, 0, strerror(r))

		r = destroy("test_kernel_all_ev")
		self.assertGreaterEqual(r, 0, strerror(r))


	def test_kernel_event(self):

		dom = Domain()
		dom.type = DOMAIN_KERNEL

		channel = Channel()
		channel.name="mychan"
		channel.attr.overwrite = 0
		channel.attr.subbuf_size = 4096
		channel.attr.num_subbuf = 8
		channel.attr.switch_timer_interval = 0
		channel.attr.read_timer_interval = 200
		channel.attr.output = EVENT_SPLICE

		sched_switch = Event()
		sched_switch.name = "sched_switch"
		sched_switch.type = EVENT_TRACEPOINT
		sched_switch.loglevel_type = EVENT_LOGLEVEL_ALL

		sched_process_exit = Event()
		sched_process_exit.name = "sched_process_exit"
		sched_process_exit.type = EVENT_TRACEPOINT
		sched_process_exit.loglevel_type = EVENT_LOGLEVEL_ALL

		sched_process_free = Event()
		sched_process_free.name = "sched_process_free"
		sched_process_free.type = EVENT_TRACEPOINT
		sched_process_free.loglevel_type = EVENT_LOGLEVEL_ALL

		han = Handle("test_kernel_event", dom)

		#Create session test
		r = create("test_kernel_event","/lttng-traces/test")
		self.assertGreaterEqual(r, 0, strerror(r))

		#Enabling channel tests
		r = enable_channel(han, channel)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Enabling events tests
		r = enable_event(han, sched_switch, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, sched_process_exit, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, sched_process_free, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Disabling events tests
		r = disable_event(han, sched_switch.name, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = disable_event(han, sched_process_free.name, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Renabling events tests
		r = enable_event(han, sched_switch, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, sched_process_free, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Start, stop, destroy
		r = start("test_kernel_event")
		self.assertGreaterEqual(r, 0, strerror(r))
		time.sleep(2)

		r = stop("test_kernel_event")
		self.assertGreaterEqual(r, 0, strerror(r))

		r=disable_channel(han, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r=destroy("test_kernel_event")
		self.assertGreaterEqual(r, 0, strerror(r))



	def test_ust_all_events(self):
		dom = Domain()
		dom.type = DOMAIN_UST

		event = Event()
		event.type = EVENT_TRACEPOINT
		event.loglevel_type = EVENT_LOGLEVEL_ALL

		han = Handle("test_ust_all_ev", dom)

		r = create("test_ust_all_ev","/lttng-traces/test")
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, event, None)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = start("test_ust_all_ev")
		self.assertGreaterEqual(r, 0, strerror(r))
		time.sleep(2)

		r = stop("test_ust_all_ev")
		self.assertGreaterEqual(r, 0, strerror(r))

		r = destroy("test_ust_all_ev")
		self.assertGreaterEqual(r, 0, strerror(r))


	def test_ust_event(self):

		dom = Domain()
		dom.type = DOMAIN_UST

		channel = Channel()
		channel.name="mychan"
		channel.attr.overwrite = 0
		channel.attr.subbuf_size = 4096
		channel.attr.num_subbuf = 8
		channel.attr.switch_timer_interval = 0
		channel.attr.read_timer_interval = 200
		channel.attr.output = EVENT_MMAP

		ev1 = Event()
		ev1.name = "tp1"
		ev1.type = EVENT_TRACEPOINT
		ev1.loglevel_type = EVENT_LOGLEVEL_ALL

		ev2 = Event()
		ev2.name = "ev2"
		ev2.type = EVENT_TRACEPOINT
		ev2.loglevel_type = EVENT_LOGLEVEL_ALL

		ev3 = Event()
		ev3.name = "ev3"
		ev3.type = EVENT_TRACEPOINT
		ev3.loglevel_type = EVENT_LOGLEVEL_ALL

		han = Handle("test_ust_event", dom)

		#Create session test
		r = create("test_ust_event","/lttng-traces/test")
		self.assertGreaterEqual(r, 0, strerror(r))

		#Enabling channel tests
		r = enable_channel(han, channel)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Enabling events tests
		r = enable_event(han, ev1, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, ev2, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, ev3, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Disabling events tests
		r = disable_event(han, ev1.name, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = disable_event(han, ev3.name, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Renabling events tests
		r = enable_event(han, ev1, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, ev3, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Start, stop
		r = start("test_ust_event")
		self.assertGreaterEqual(r, 0, strerror(r))
		time.sleep(2)

		r = stop("test_ust_event")
		self.assertGreaterEqual(r, 0, strerror(r))

		#Restart/restop
		r = start("test_ust_event")
		self.assertGreaterEqual(r, 0, strerror(r))
		time.sleep(2)

		r = stop("test_ust_event")
		self.assertGreaterEqual(r, 0, strerror(r))

		#Disabling channel and destroy
		r=disable_channel(han, channel.name)
		self.assertGreaterEqual(r, 0, strerror(r))

		r=destroy("test_ust_event")
		self.assertGreaterEqual(r, 0, strerror(r))


	def test_other_functions(self):
		dom = Domain()
		dom.type=DOMAIN_KERNEL

		event=Event()
		event.type=EVENT_TRACEPOINT
		event.loglevel_type=EVENT_LOGLEVEL_ALL

		ctx = EventContext()
		ctx.type=EVENT_CONTEXT_PID

		chattr = ChannelAttr()
		chattr.overwrite = 0
		chattr.subbuf_size = 4096
		chattr.num_subbuf = 8
		chattr.switch_timer_interval = 0
		chattr.read_timer_interval = 200
		chattr.output = EVENT_SPLICE

		han = Handle("test_otherf" , dom)

		r = create("test_otherf","/lttng-traces/test")
		self.assertGreaterEqual(r, 0, strerror(r))

		r = enable_event(han, event, None)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Context test
		r = add_context(han, ctx, "sched_switch", "channel0")
		self.assertGreaterEqual(r, 0, strerror(r))
		#Any channel
		r = add_context(han, ctx, "sched_wakeup", None)
		self.assertGreaterEqual(r, 0, strerror(r))
		#All events
		r = add_context(han, ctx, None, None)
		self.assertGreaterEqual(r, 0, strerror(r))

		#Def. channel attr
		channel_set_default_attr(dom, chattr)
		channel_set_default_attr(None, None)

		#Ses Daemon alive
		r = session_daemon_alive()
		self.assertTrue(r == 1 or r == 0, strerror(r))

		#Setting trace group
		r = set_tracing_group("testing")
		self.assertGreaterEqual(r, 0, strerror(r))


		r = start("test_otherf")
		self.assertGreaterEqual(r, 0, strerror(r))
		time.sleep(2)

		r = stop("test_otherf")
		self.assertGreaterEqual(r, 0, strerror(r))

		del han

		r = destroy("test_otherf")
		self.assertGreaterEqual(r, 0, strerror(r))


if __name__ == "__main__":
	# CHECK IF ROOT
	if os.geteuid() == 0:
		#Make sure session names don't already exist:
		destroy("test_kernel_event")
		destroy("test_kernel_all_events")
		destroy("test_ust_all_events")
		destroy("test_ust_event")
		destroy("test_otherf")

		unittest.main()
	else:
		print('Script must be run as root')
