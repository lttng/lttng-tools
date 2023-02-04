/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAKE_UNIQUE_WRAPPER_H
#define LTTNG_MAKE_UNIQUE_WRAPPER_H

#include <common/macros.hpp>

#include <memory>

namespace lttng {

/*
 * make_unique_wrapper is intended to facilitate the use of std::unique_ptr
 * to wrap C-style APIs that don't provide RAII resource management facilities.
 *
 * Usage example:
 *
 *    // API
 *    struct my_c_struct {
 *            // ...
 *    };
 *
 *    struct my_c_struct *create_my_c_struct(void);
 *    void destroy_my_c_struct(struct my_c_struct *value);
 *
 *    // Creating a unique_ptr to my_c_struct.
 *    auto safe_c_struct =
 *            lttng::make_unique_wrapper<my_c_struct, destroy_my_c_struct>(
 *                    create_my_c_struct());
 *
 * Note that this facility is intended for use in the scope of a function.
 * If you need to return this unique_ptr instance, you should consider writting
 * a proper, idiomatic, wrapper.
 */

namespace memory {
template <typename WrappedType, void (*DeleterFunction)(WrappedType *)>
struct create_deleter_class {
	struct deleter {
		void operator()(WrappedType *instance) const
		{
			DeleterFunction(instance);
		}
	};

	std::unique_ptr<WrappedType, deleter> operator()(WrappedType *instance) const
	{
		return std::unique_ptr<WrappedType, deleter>(instance);
	}
};
} /* namespace memory */

/*
 * 'free' is a utility function for use with make_unique_wrapper. It makes it easier to
 * wrap raw pointers that have to be deleted with `free`. Using libc's 'free' as
 * a make_unique_wrapper template argument will result in an error as 'WrappedType *' will
 * not match free's 'void *' argument.
 */
template <class Type>
void free(Type *ptr)
{
	std::free(ptr);
}

template <typename WrappedType, void (*DeleterFunc)(WrappedType *)>
std::unique_ptr<WrappedType,
		typename memory::create_deleter_class<WrappedType, DeleterFunc>::deleter>
make_unique_wrapper(WrappedType *instance = nullptr)
{
	const memory::create_deleter_class<WrappedType, DeleterFunc> unique_deleter;

	return unique_deleter(instance);
}

} /* namespace lttng */

#endif /* LTTNG_MAKE_UNIQUE_WRAPPER_H */
