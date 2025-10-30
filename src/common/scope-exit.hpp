/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SCOPE_EXIT_H
#define LTTNG_SCOPE_EXIT_H

#include <utility>

namespace lttng {

namespace details {
/* Is operator() of InvocableType is marked as noexcept? */
template <typename InvocableType>
struct is_invocation_noexcept
	: std::integral_constant<bool, noexcept((std::declval<InvocableType>())())> {};
} /* namespace details. */

/*
 * Generic utility to run a lambda (or any other invocable object) when leaving
 * a scope.
 *
 * Typical usage examples include:
 * • Specify an action (e.g. restore a context) that must occur at
 *   the end of a function,
 * • Specify roll-back operations in an exception-safe way.
 */
template <typename ScopeExitInvocableType>
class scope_exit {
public:
	/*
	 * Since ScopeExitInvocableType will be invoked in the destructor, it
	 * must be `noexcept` lest we anger the undefined behaviour gods by throwing
	 * an exception while an exception is active.
	 */
	static_assert(details::is_invocation_noexcept<ScopeExitInvocableType>::value,
		      "scope_exit requires a noexcept invocable type");

	explicit scope_exit(ScopeExitInvocableType&& scope_exit_callable) :
		_on_scope_exit{ std::forward<ScopeExitInvocableType>(scope_exit_callable) }
	{
	}

	scope_exit(scope_exit&& rhs) noexcept :
		_on_scope_exit{ std::move(rhs._on_scope_exit) }, _armed{ rhs._armed }
	{
		/* Don't invoke ScopeExitInvocableType for the moved-from copy. */
		rhs.disarm();
	}

	/*
	 * The copy constructor is disabled to prevent the action from being
	 * executed twice should a copy be performed accidentaly.
	 *
	 * The move-constructor is present to enable make_scope_exit() but to
	 * also propagate the scope_exit to another scope, should it be needed.
	 */
	scope_exit(const scope_exit&) = delete;
	scope_exit& operator=(const scope_exit&) = delete;
	scope_exit& operator=(scope_exit&&) = delete;
	scope_exit() = delete;

	void arm() noexcept
	{
		_armed = true;
	}

	void disarm() noexcept
	{
		_armed = false;
	}

	~scope_exit()
	{
		if (_armed) {
			_on_scope_exit();
		}
	}

private:
	ScopeExitInvocableType _on_scope_exit;
	bool _armed = true;
};

template <typename ScopeExitInvocableType>
scope_exit<ScopeExitInvocableType> make_scope_exit(ScopeExitInvocableType&& scope_exit_callable)
{
	return scope_exit<ScopeExitInvocableType>(
		std::forward<ScopeExitInvocableType>(scope_exit_callable));
}

} /* namespace lttng */

#endif /* LTTNG_SCOPE_EXIT_H */
