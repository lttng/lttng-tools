The `filter.lttngtest.event_name` plugin only has a single input and output port.
This means that it cannot be connected directly to a `source.ctf.fs` plugin, as
those have multiple output ports for the different event streams.

A `filter.utils.muxer` plugin must be placed between any multi-output port plugin
and the `filter.lttngtest.event_name` plugin. This is done automatically with in
the architecture created by `babeltrace2 convert`.

Example with `babeltrace2 convert`:

```
SOURCE_PATH=/tmp/tmp.1J5DueCziG
EVENT_NAME=tp:the_string
babeltrace2 --plugin-path=.libs/ convert "${SOURCE_PATH}" -c filter.lttngtest.event_name -p "names=[\"$EVENT_NAME\"]" -c sink.lttngtest.field_stats
```

Example with `babeltrace2 run`:

```
SOURCE_PATH=/tmp/tmp.1J5DueCziG
EVENT_NAME=tp:the_string
babeltrace2 --plugin-path=.libs/ run -c A:source.ctf.fs -p "inputs=[\"$SOURCE_PATH\"]" -c muxer:filter.utils.muxer -c B:filter.lttngtest.event_name -p "names=[\"$EVENT_NAME\"]" -c C:sink.lttngtest.field_stats -x A:muxer -x muxer:B -x B:C
```
