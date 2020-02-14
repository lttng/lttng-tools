# Trigger notification example

## Description
This example is made-up of three executables.

### `notification-client`

```
Usage: notification-client TRIGGER_NAME TRIGGER_NAME2 ...
```

A simple client that subscribes to the notifications emitted by the `TRIGGER_NAME` trigger.

Multiple trigger names can be passed and subscribed to.


### `instrumented-app`

An application that emits the `trigger_example:my_event` event every 2 seconds.

### `demo.sh`

This script adds a trigger named `demo_trigger` which emits a notification when
the user-space `trigger_example:my_event` event occurs.

This script also adds a trigger named `demo_trigger_capture` which emits a
notification when the user-space `trigger_example:my_event` event occurs and
provides captured fields if present.

Once the triggers have been setup, the notification-client is launched to print
all notifications emitted by the `demo_trigger` and `demo_trigger_capture`
trigger.

## Running the example

1) Launch a session daemon using:
        ```
        $ lttng-sessiond
        ```
2) Launch the `demo.sh` script
3) Launch the `instrumented-app`

The following output should be produced:

```
$ ./demo.sh
Registering a notification trigger named "demo_trigger" for the trigger_example:my_event user-space event
Trigger registered successfully.
Trigger registered successfully.
Subscribed to notifications of trigger "demo_trigger_capture"
Subscribed to notifications of trigger "demo_trigger"
[08-24-2020] 17:20:33.598221 - Received notification of event rule matches trigger "demo_trigger"
[08-24-2020] 17:20:33.598855 - Received notification of event rule matches trigger "demo_trigger_capture"
Captured field values:
  Field: iteration Value: [Unsigned int] 0,
  Field: does_not_exist Value: Capture unavailable,
  Field: $ctx.vtid Value: [Unsigned int] 2302494,
  Field: $ctx.procname Value: [String] instrumented-ap.
[08-24-2020] 17:20:35.598556 - Received notification of event rule matches trigger "demo_trigger"
[08-24-2020] 17:20:35.599293 - Received notification of event rule matches trigger "demo_trigger_capture"
Captured field values:
  Field: iteration Value: [Unsigned int] 1,
  Field: does_not_exist Value: Capture unavailable,
  Field: $ctx.vtid Value: [Unsigned int] 2302494,
  Field: $ctx.procname Value: [String] instrumented-ap.
[08-24-2020] 17:20:37.598977 - Received notification of event rule matches trigger "demo_trigger"
[08-24-2020] 17:20:37.599676 - Received notification of event rule matches trigger "demo_trigger_capture"
Captured field values:
  Field: iteration Value: [Unsigned int] 2,
  Field: does_not_exist Value: Capture unavailable,
  Field: $ctx.vtid Value: [Unsigned int] 2302494,
  Field: $ctx.procname Value: [String] instrumented-ap.
[08-24-2020] 17:20:39.599430 - Received notification of event rule matches trigger "demo_trigger"
[08-24-2020] 17:20:39.600178 - Received notification of event rule matches trigger "demo_trigger_capture"
Captured field values:
  Field: iteration Value: [Unsigned int] 3,
  Field: does_not_exist Value: Capture unavailable,
  Field: $ctx.vtid Value: [Unsigned int] 2302494,
  Field: $ctx.procname Value: [String] instrumented-ap.
...
```

```
$ ./instrumented-app
[08-24-2020] 17:20:33.597441 - Tracing event "trigger_example:my_event"
[08-24-2020] 17:20:35.597703 - Tracing event "trigger_example:my_event"
[08-24-2020] 17:20:37.597997 - Tracing event "trigger_example:my_event"
...
```


