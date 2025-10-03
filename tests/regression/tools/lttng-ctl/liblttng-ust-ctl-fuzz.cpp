/*
 * SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <lttng/ust-ctl.h>

#include <assert.h>
#include <dlfcn.h>

/*
 * Bear with me here!
 *
 * These macros are taken from libside static checker and they are portable!
 *
 * They allow to reduce the boiler plate to generate wrappers for LTTng ust-ctl
 * functions.
 *
 * The details are not important here. You can jump straight at the end of the
 * file to define new wrappers.
 */

/*
 * Concatenate `X` with `Y` after expanding both.
 */
#define CAT_PRIMITIVE(x, y) x##y
#define CAT(x, y)	    CAT_PRIMITIVE(x, y)

/*
 * Allows for evaluation of list with up to `4^4 - 1 = 255` elements.
 */
#define EVAL0(...) __VA_ARGS__
#define EVAL1(...) EVAL0(EVAL0(EVAL0(__VA_ARGS__)))
#define EVAL2(...) EVAL1(EVAL1(EVAL1(__VA_ARGS__)))
#define EVAL3(...) EVAL2(EVAL2(EVAL2(__VA_ARGS__)))
#define EVAL4(...) EVAL3(EVAL3(EVAL3(__VA_ARGS__)))
#define EVAL	   EVAL4

#define MAP_END(...)
#define MAP_OUT
#define MAP_COMMA ,

#define MAP_GET_END2()		   0, MAP_END
#define MAP_GET_END1(...)	   MAP_GET_END2
#define MAP_GET_END(...)	   MAP_GET_END1
#define MAP_NEXT0(test, next, ...) next MAP_OUT
#define MAP_NEXT1(test, next)	   MAP_NEXT0(test, next, 0)
#define MAP_NEXT(test, next)	   MAP_NEXT1(MAP_GET_END test, next)

#define MAP0(f, x, peek, ...) f(x) MAP_NEXT(peek, MAP1)(f, peek, __VA_ARGS__)
#define MAP1(f, x, peek, ...) f(x) MAP_NEXT(peek, MAP0)(f, peek, __VA_ARGS__)

/*
 * Applied arguments to macro function `f`.
 *
 * Example:
 *
 *   #define STR_P(X) #X
 *   #define STR(X) STR_P(X)
 *
 *   MAP(STR, foo, bar) => "foo" "bar"
 */
#define MAP(f, ...) EVAL(MAP1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

/*
 * Like `MAP`, but do partial evaluation by passing a default argument that will
 * be applied to `f` along with the elements of the list.
 *
 * Example: MAP_CURRYING(CAT, prefix_, foo, bar) => prefix_foo prefix_bar
 */
#define MAP_NEXT0_CURRYING(test, next, ...) next MAP_OUT
#define MAP_NEXT1_CURRYING(test, next)	    MAP_NEXT0_CURRYING(test, next, 0)
#define MAP_NEXT_CURRYING(test, next)	    MAP_NEXT1_CURRYING(MAP_GET_END test, next)
#define MAP0_CURRYING(f, partial, x, peek, ...) \
	f(partial, x) MAP_NEXT_CURRYING(peek, MAP1_CURRYING)(f, partial, peek, __VA_ARGS__)
#define MAP1_CURRYING(f, partial, x, peek, ...) \
	f(partial, x) MAP_NEXT_CURRYING(peek, MAP0_CURRYING)(f, partial, peek, __VA_ARGS__)
#define MAP_CURRYING(f, partial, ...) \
	EVAL(MAP1_CURRYING(f, partial, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

/*
 * Lazily initialize the content of `*preal_fn` with the address matching the
 * symbol `symbol_name` found by the dynamic linker.
 */
static void *lazy_initialize(void **preal_fn, const char *symbol_name)
{
	void *real_fn;

	/*
	 * Paired with next exchange.
	 */
	real_fn = __atomic_load_n(preal_fn, __ATOMIC_SEQ_CST);

	if (real_fn) {
		return real_fn;
	}

	real_fn = dlsym(RTLD_NEXT, symbol_name);

	assert(real_fn);

	/*
	 * This assumes that concurent `dlsym(3)` calls yield the same
	 * value. Otherwise, a compare exchange operation would be necessary.
	 *
	 * Paired with previous load.
	 */
	(void) __atomic_exchange_n(preal_fn, real_fn, __ATOMIC_SEQ_CST);

	return real_fn;
}

/*
 * This is called by the wrapper function, passing a pointer to a static storage
 * `preal`. `name` is the name of original function that is being wrapped and
 * `args` are forward to the real implementation.
 */
template <typename... Args>
int call_wrapper(void **preal_fn, const char *name, int sock, Args... args)
{
	int (*real_fn)(int, Args...) =
		reinterpret_cast<typeof(real_fn)>(lazy_initialize(preal_fn, name));

	assert(real_fn);

	int ret = lttng_ust_ctl_unknown_command(sock);

	assert(ret == 0);

	return real_fn(sock, args...);
}

/*
 * Unpack an argument by emitting its type and its name. Since the first
 * argument (`int sock`) is always present, a `,` token is place as a prefix of
 * the expansion.
 *
 * This is used to generate the signature of the wrapper.
 */
#define UNPACK_ARG(type, name) , type name

/*
 * Same as `UNPACK_ARG` but omit the argument type. This is used to forward the
 * argument to the real implementation.
 */
#define NAME_ARG(type, name) , name

/*
 * These are used for function that do not have arguments except for the
 * implicit socket.
 */
#define UNPACK_NOTHING
#define NAME_NOTHING

/*
 * Define a wrapper for function `name` taken `args`.
 *
 * The `int sock` argument must not be passed in `args`.
 *
 * Arguments must be individually wrapped using `ARG(TYPE, NAME)`.
 *
 * If the function takes no arguments (except the implicit `int sock`), then
 * `NOTHING` must be passed.
 *
 * For example, let says the following functions exist:
 *
 *   int lttng_ust_ctl_my_cool_function(int sock, struct cool *cool);
 *   int lttng_ust_ctl_my_kool_function(int sock);
 *
 * Then wrappers can be made like so:
 *
 *    DEFINE_WRAPPER(lttng_ust_ctl_my_cool_function, ARG(struct cool *, cool));
 *    DEFINE_WRAPPER(lttng_ust_ctl_my_kool_function, NOTHING);
 *
 * Every wrapped function will call the `lttng_ust_ctl_unknown_command` with the
 * `sock` argument before calling the real implementation. Therefore, the
 * wrappers act as an sort of injection fuzzer for the protocol.
 *
 * This macro expect a trailing `;` token.
 */
#define DEFINE_WRAPPER(name, args...)                                                              \
	__attribute__((visibility("default"))) int name(int sock MAP_CURRYING(CAT, UNPACK_, args)) \
	{                                                                                          \
		static void *real_fn;                                                              \
		return call_wrapper(&real_fn, __FUNCTION__, sock MAP_CURRYING(CAT, NAME_, args));  \
	}                                                                                          \
	static_assert(true)

DEFINE_WRAPPER(lttng_ust_ctl_register_done, NOTHING);

DEFINE_WRAPPER(lttng_ust_ctl_create_session, NOTHING);

DEFINE_WRAPPER(lttng_ust_ctl_create_event,
	       ARG(struct lttng_ust_abi_event *, env),
	       ARG(struct lttng_ust_abi_object_data *, channel_data),
	       ARG(struct lttng_ust_abi_object_data **, event_data));

DEFINE_WRAPPER(lttng_ust_ctl_add_context,
	       ARG(struct lttng_ust_context_attr *, ctx),
	       ARG(struct lttng_ust_abi_object_data *, obj_data),
	       ARG(struct lttng_ust_abi_object_data **, context_data));

DEFINE_WRAPPER(lttng_ust_ctl_set_filter,
	       ARG(struct lttng_ust_abi_filter_bytecode *, bytecode),
	       ARG(struct lttng_ust_abi_object_data *, obj_data));

DEFINE_WRAPPER(lttng_ust_ctl_set_capture,
	       ARG(struct lttng_ust_abi_capture_bytecode *, bytecode),
	       ARG(struct lttng_ust_abi_object_data *, obj_data));

DEFINE_WRAPPER(lttng_ust_ctl_set_exclusion,
	       ARG(struct lttng_ust_abi_event_exclusion *, exclusion),
	       ARG(struct lttng_ust_abi_object_data *, obj_data));

DEFINE_WRAPPER(lttng_ust_ctl_enable, ARG(struct lttng_ust_abi_object_data *, object));

DEFINE_WRAPPER(lttng_ust_ctl_disable, ARG(struct lttng_ust_abi_object_data *, object));

DEFINE_WRAPPER(lttng_ust_ctl_start_session, ARG(int, handle));

DEFINE_WRAPPER(lttng_ust_ctl_stop_session, ARG(int, handle));

DEFINE_WRAPPER(lttng_ust_ctl_create_event_notifier_group,
	       ARG(int, pipe_fd),
	       ARG(struct lttng_ust_abi_object_data **, event_notifier_group));

DEFINE_WRAPPER(lttng_ust_ctl_create_event_notifier,
	       ARG(struct lttng_ust_abi_event_notifier *, event_notifier),
	       ARG(struct lttng_ust_abi_object_data *, event_notifier_group),
	       ARG(struct lttng_ust_abi_object_data **, event_notifier_data));

DEFINE_WRAPPER(lttng_ust_ctl_tracepoint_list, NOTHING);

DEFINE_WRAPPER(lttng_ust_ctl_tracepoint_list_get,
	       ARG(int, tp_list_handle),
	       ARG(struct lttng_ust_abi_tracepoint_iter *, iter));

DEFINE_WRAPPER(lttng_ust_ctl_tracepoint_field_list, NOTHING);

DEFINE_WRAPPER(lttng_ust_ctl_tracepoint_field_list_get,
	       ARG(int, tp_field_list_handle),
	       ARG(struct lttng_ust_abi_field_iter *, iter));

DEFINE_WRAPPER(lttng_ust_ctl_tracer_version, ARG(struct lttng_ust_abi_tracer_version *, v));

DEFINE_WRAPPER(lttng_ust_ctl_wait_quiescent, NOTHING);

DEFINE_WRAPPER(lttng_ust_ctl_sock_flush_buffer, ARG(struct lttng_ust_abi_object_data *, object));

DEFINE_WRAPPER(lttng_ust_ctl_calibrate, ARG(struct lttng_ust_abi_calibrate *, calibrate));

DEFINE_WRAPPER(lttng_ust_ctl_release_object, ARG(struct lttng_ust_abi_object_data *, data));

DEFINE_WRAPPER(lttng_ust_ctl_release_handle, ARG(int, handle));

DEFINE_WRAPPER(lttng_ust_ctl_send_channel_to_ust,
	       ARG(int, session_handle),
	       ARG(struct lttng_ust_abi_object_data *, channel_data));

DEFINE_WRAPPER(lttng_ust_ctl_send_stream_to_ust,
	       ARG(struct lttng_ust_abi_object_data *, channel_data),
	       ARG(struct lttng_ust_abi_object_data *, stream_data));
