#This example shows basically how to use the lttng-tools python module

from lttng import *

# This error will be raised is something goes wrong
class LTTngError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

#Setting up the domain to use
dom = Domain()
dom.type = DOMAIN_KERNEL

#Setting up a channel to use
channel = Channel()
channel.name = "mychan"
channel.attr.overwrite = 0
channel.attr.subbuf_size = 4096
channel.attr.num_subbuf = 8
channel.attr.switch_timer_interval = 0
channel.attr.read_timer_interval = 200
channel.attr.output = EVENT_SPLICE

#Setting up some events that will be used
event = Event()
event.type = EVENT_TRACEPOINT
event.loglevel_type = EVENT_LOGLEVEL_ALL

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


#Creating a new session
res = create("test","/lttng-traces/test")
if res<0:
	raise LTTngError(strerror(res))

#Creating handle
han = None
han = Handle("test", dom)
if han is None:
	raise LTTngError("Handle not created")

#Enabling the kernel channel
res = enable_channel(han, channel)
if res<0:
	raise LTTngError(strerror(res))

#Enabling some events in given channel
#To enable all events in default channel, use
#enable_event(han, event, None)
res = enable_event(han, sched_switch, channel.name)
if res<0:
	raise LTTngError(strerror(res))

res = enable_event(han, sched_process_exit, channel.name)
if res<0:
	raise LTTngError(strerror(res))

res = enable_event(han, sched_process_free, channel.name)
if res<0:
	raise LTTngError(strerror(res))

#Disabling an event
res = disable_event(han, sched_switch.name, channel.name)
if res<0:
	raise LTTngError(strerror(res))

#Getting a list of the channels
l = list_channels(han)
if type(l) is int:
		raise LTTngError(strerror(l))

#Starting the trace
res = start("test")
if res<0:
	raise LTTngError(strerror(res))

#Stopping the trace
res = stop("test")
if res<0:
	raise LTTngError(strerror(res))

#Disabling a channel
res = disable_channel(han, channel.name)
if res<0:
	raise LTTngError(strerror(res))

#Destroying the handle
del han

#Destroying the session
res = destroy("test")
if res<0:
	raise LTTngError(strerror(res))
